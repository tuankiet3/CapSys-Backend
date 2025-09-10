using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using CapSys_Backend.Data;
using CapSys_Backend.Dtos;
using CapSys_Backend.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace CapSys_Backend.Services
{
    public class AuthService : IAuthService
    {
        private readonly CapSysDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;
        private readonly IEmailService _emailService;
        private readonly HashSet<string> _blacklistedTokens = new();

        public AuthService(CapSysDbContext context, IConfiguration configuration, ILogger<AuthService> logger, IEmailService emailService)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
            _emailService = emailService;
        }
        // Implement the ForgetPasswordAsync method
        public async Task<ApiResponse> ForgetPasswordAsync(ForgetPasswordRequest request)
        {
            try
            {
                // Check if the email exists
                var account = await _context.Accounts.FirstOrDefaultAsync(a => a.Email == request.Email);

                if (account == null)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Email not found"
                    };
                }
                // Generate a password reset token and send email
                var resetToken = GeneratePasswordResetToken(account);
                var resetUrl = $"{_configuration["FrontendUrl"]}/reset-password?token={resetToken}&email={account.Email}";

                await _emailService.SendPasswordResetEmailAsync(account.Email, account.Username, resetUrl);

                return new ApiResponse
                {
                    Success = true,
                    Message = "If the email exists, a password reset link has been sent."
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset for email: {Email}", request.Email);
                return new ApiResponse
                {
                    Success = false,
                    Message = "An error occurred during password reset"
                };
            }
        }
        // Generate JWT Token
        public string GenerateJwtToken(Account account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"] ?? "your-super-secret-key-that-is-at-least-32-characters-long");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("AccountId", account.AccountId.ToString()),
                    new Claim("Username", account.Username),
                    new Claim("Email", account.Email),
                    new Claim("AccountType", account.AccountType),
                    new Claim(ClaimTypes.Name, account.Username),
                    new Claim(ClaimTypes.NameIdentifier, account.AccountId.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _configuration["JWT:Issuer"],
                Audience = _configuration["JWT:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        private string GeneratePasswordResetToken(Account account)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"] ?? "da091c4037f94df53b94876314a5487e");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("AccountID", account.AccountId.ToString()),
                    new Claim("Email", account.Email),
                    new Claim("TokenType", "PasswordReset")
                }),
                Expires = DateTime.UtcNow.AddHours(1), // Reset token expires in 1 hour
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        public async Task<ApiResponse> RegisterAsync(RegisterRequest request)
        {
            try
            {
                var existingUsername = await _context.Accounts
                    .FirstOrDefaultAsync(x => x.Username == request.Username);

                if (existingUsername != null)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Username already exists"
                    };
                }

                var existingEmail = await _context.Accounts
                    .FirstOrDefaultAsync(x => x.Email == request.Email);

                if (existingEmail != null)
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Email already exists"
                    };
                }
                var validAccountTypes = new[] { "Student", "Lecturer", "Admin" };
                if (!validAccountTypes.Contains(request.AccountType))
                {
                    return new ApiResponse
                    {
                        Success = false,
                        Message = "Invalid account type. Must be Student, Lecturer, or Admin."
                    };
                }

                var account = new Account
                {
                    Username = request.Username,
                    Email = request.Email,
                    PasswordHash = HashPassword(request.Password),
                    AccountType = request.AccountType,
                    CreatedDate = DateTime.Now
                };

                _context.Accounts.Add(account);
                await _context.SaveChangesAsync();
                _logger.LogInformation("New account created for username: {Username}", request.Username);
                return new ApiResponse
                {
                    Success = true,
                    Message = "Account created successfully",
                    Data = new AccountInfo
                    {
                        AccountID = account.AccountId,
                        Username = account.Username,
                        Email = account.Email,
                        AccountType = account.AccountType
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for username: {Username}", request.Username);

                return new ApiResponse
                {
                    Success = false,
                    Message = "An error occurred during registration"
                };
            }
        }
        public async Task<LoginResponse> LoginAsync(LoginRequest request)
        {
            try
            {
                var account = await _context.Accounts.FirstOrDefaultAsync(a => a.Username == request.Username);

                if (account == null || !ValidatePassword(request.Password, account.PasswordHash))
                {
                    return new LoginResponse
                    {
                        Success = false,
                        Message = "Invalid username or password"
                    };
                }
                else
                {
                    return new LoginResponse
                    {
                        Success = true,
                        Message = "Login successful.",
                        Token = GenerateJwtToken(account),
                        Account = new AccountInfo
                        {
                            AccountID = account.AccountId,
                            Username = account.Username,
                            Email = account.Email,
                            AccountType = account.AccountType
                        }
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for username: {Username}", request.Username);
                return new LoginResponse
                {
                    Success = false,
                    Message = "An error occurred during login"
                };
            }
        }

        public Task<bool> LogoutAsync(string token)
        {
            try
            {
                _blacklistedTokens.Add(token);
                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout for token: {Token}", token);
                return Task.FromResult(false);
            }
        }

        public bool ValidatePassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public bool IsTokenBlacklisted(string token)
        {
            return _blacklistedTokens.Contains(token);
        }
    }
}