using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CapSys_Backend.Dtos;
using CapSys_Backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CapSys_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse
                {
                    Success = false,
                    Message = "Invalid input data",
                    Data = ModelState
                });
            }

            var result = await _authService.RegisterAsync(request);

            if (result.Success)
            {
                _logger.LogInformation("User {Username} registered successfully", request.Username);
                return CreatedAtAction(nameof(Register), result);
            }

            _logger.LogWarning("Failed registration attempt for username: {Username}", request.Username);
            return BadRequest(result);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse
                {
                    Success = false,
                    Message = "Invalid input data",
                    Data = ModelState
                });
            }

            var result = await _authService.LoginAsync(request);

            if (result.Success)
            {
                _logger.LogInformation("User {Username} logged in successfully", request.Username);
                return Ok(result);
            }

            _logger.LogWarning("Failed login attempt for username: {Username}", request.Username);
            return BadRequest(result);
        }
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var token = GetTokenFromRequest();
                if (string.IsNullOrEmpty(token))
                {
                    return BadRequest(new ApiResponse
                    {
                        Success = false,
                        Message = "No token provided"
                    });
                }

                var result = await _authService.LogoutAsync(token);

                if (result)
                {
                    var username = User.FindFirstValue(ClaimTypes.Name);
                    _logger.LogInformation("User {Username} logged out successfully", username);

                    return Ok(new ApiResponse
                    {
                        Success = true,
                        Message = "Logout successful"
                    });
                }

                return BadRequest(new ApiResponse
                {
                    Success = false,
                    Message = "Logout failed"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new ApiResponse
                {
                    Success = false,
                    Message = "An error occurred during logout"
                });
            }
        }

        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgetPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponse
                {
                    Success = false,
                    Message = "Invalid email address",
                    Data = ModelState
                });
            }

            var result = await _authService.ForgetPasswordAsync(request);

            _logger.LogInformation("Password reset requested for email: {Email}", request.Email);
            return Ok(result);
        }

        [HttpGet("profile")]
        [Authorize]
        public IActionResult GetProfile()
        {
            try
            {
                var accountInfo = new AccountInfo
                {
                    AccountID = int.Parse(User.FindFirstValue("AccountID") ?? "0"),
                    Username = User.FindFirstValue("Username") ?? "",
                    Email = User.FindFirstValue("Email") ?? "",
                    AccountType = User.FindFirstValue("AccountType") ?? ""
                };

                return Ok(new ApiResponse
                {
                    Success = true,
                    Message = "Profile retrieved successfully",
                    Data = accountInfo
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving user profile");
                return StatusCode(500, new ApiResponse
                {
                    Success = false,
                    Message = "Error retrieving profile"
                });
            }
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenRequest tokenRequest)
        {
            if (tokenRequest is null)
            {
                return BadRequest("Invalid client request");
            }

            var result = await _authService.RefreshTokenAsync(tokenRequest);

            if (result.Success)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }
        private string GetTokenFromRequest()
        {
            var authHeader = Request.Headers.Authorization.FirstOrDefault();
            if (authHeader != null && authHeader.StartsWith("Bearer "))
            {
                return authHeader.Substring("Bearer ".Length).Trim();
            }
            return string.Empty;
        }
    }
}