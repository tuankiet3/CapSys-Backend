using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CapSys_Backend.Dtos;
using CapSys_Backend.Models;

namespace CapSys_Backend.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest request);
        Task<bool> LogoutAsync(string token);
        Task<ApiResponse> RegisterAsync(RegisterRequest request);
        Task<ApiResponse> ForgetPasswordAsync(ForgetPasswordRequest request);
        string GenerateJwtToken(Account account);
        bool ValidatePassword(string password, string hash);
        string HashPassword(string password);
    }
}