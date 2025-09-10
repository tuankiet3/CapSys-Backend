using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"] ?? "da091c4037f94df53b94876314a5487e");

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
                Expires = DateTime.UtcNow.AddMinutes(5),
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

                var refreshToken = GenerateRefreshToken();

                var account = new Account
                {
                    Username = request.Username,
                    Email = request.Email,
                    PasswordHash = HashPassword(request.Password),
                    AccountType = request.AccountType,
                    CreatedDate = DateTime.Now,
                    RefreshToken = refreshToken,
                    RefreshTokenExpiryTime = DateTime.Now.AddDays(_configuration.GetValue<int>("JWT:RefreshTokenValidityInDays"))
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
                    var token = GenerateJwtToken(account);
                    var refreshToken = GenerateRefreshToken();

                    account.RefreshToken = refreshToken;
                    account.RefreshTokenExpiryTime = DateTime.Now.AddDays(_configuration.GetValue<int>("JWT:RefreshTokenValidityInDays"));

                    // Lưu refresh token vào database
                    await _context.SaveChangesAsync();

                    return new LoginResponse
                    {
                        Success = true,
                        Message = "Login successful.",
                        Token = token,
                        RefreshToken = refreshToken,
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

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"] ?? "da091c4037f94df53b94876314a5487e");

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateLifetime = false, // Không validate thời gian hết hạn
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["JWT:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["JWT:Audience"],
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
            return principal;
        }

        public async Task<bool> LogoutAsync(string token)
        {
            var principal = GetPrincipalFromExpiredToken(token);
            var username = principal?.Identity?.Name;

            if (string.IsNullOrEmpty(username))
                return false;

            var user = await _context.Accounts.SingleOrDefaultAsync(u => u.Username == username);
            if (user == null) return false;

            user.RefreshToken = null;
            await _context.SaveChangesAsync();

            return true;
        }

        public bool ValidatePassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public async Task<LoginResponse> RefreshTokenAsync(TokenRequest tokenRequest)
        {
            try
            {
                var principal = GetPrincipalFromExpiredToken(tokenRequest.Token);
                var username = principal?.Identity?.Name;

                _logger.LogInformation("Refresh token request for username: {Username}", username);

                if (string.IsNullOrEmpty(username))
                {
                    _logger.LogWarning("Invalid token - no username found");
                    return new LoginResponse { Success = false, Message = "Invalid token" };
                }

                var account = await _context.Accounts.SingleOrDefaultAsync(u => u.Username == username);

                if (account == null)
                {
                    _logger.LogWarning("Account not found for username: {Username}", username);
                    return new LoginResponse { Success = false, Message = "Account not found" };
                }

                if (account.RefreshToken != tokenRequest.RefreshToken)
                {
                    _logger.LogWarning("Refresh token mismatch for user: {Username}", username);
                    return new LoginResponse { Success = false, Message = "Invalid refresh token" };
                }

                if (account.RefreshTokenExpiryTime <= DateTime.Now)
                {
                    _logger.LogWarning("Refresh token expired for user: {Username}. Expiry: {ExpiryTime}, Current: {CurrentTime}",
                        username, account.RefreshTokenExpiryTime, DateTime.Now);
                    return new LoginResponse { Success = false, Message = "Refresh token expired" };
                }

                var newAccessToken = GenerateJwtToken(account);
                var newRefreshToken = GenerateRefreshToken();

                account.RefreshToken = newRefreshToken;
                account.RefreshTokenExpiryTime = DateTime.Now.AddDays(_configuration.GetValue<int>("JWT:RefreshTokenValidityInDays"));
                await _context.SaveChangesAsync();

                _logger.LogInformation("Successfully refreshed token for user: {Username}", username);

                return new LoginResponse
                {
                    Token = newAccessToken,
                    RefreshToken = newRefreshToken,
                    Success = true,
                    Message = "Token refreshed successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return new LoginResponse
                {
                    Success = false,
                    Message = "Error during token refresh"
                };
            }
        }
    }
}