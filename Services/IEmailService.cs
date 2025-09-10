using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CapSys_Backend.Services
{
    public interface IEmailService
    {
        Task SendPasswordResetEmailAsync(string email, string username, string resetUrl);
    }
}