using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace CapSys_Backend.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }
        public async Task SendPasswordResetEmailAsync(string email, string username, string resetUrl)
        {
            try
            {
                var smtpClient = new SmtpClient(_configuration["Email:SmtpHost"])
                {
                    Port = int.Parse(_configuration["Email:SmtpPort"] ?? "587"),
                    Credentials = new NetworkCredential(
                        _configuration["Email:Username"],
                        _configuration["Email:Password"]),
                    EnableSsl = true,
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_configuration["Email:FromAddress"] ?? "noreply@yourapp.com"),
                    Subject = "Password Reset Request",
                    Body = GeneratePasswordResetEmailBody(username, resetUrl),
                    IsBodyHtml = true,
                };

                mailMessage.To.Add(email);

                await smtpClient.SendMailAsync(mailMessage);
                _logger.LogInformation("Password reset email sent to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send password reset email to {Email}", email);
                throw;
            }
        }
        private string GeneratePasswordResetEmailBody(string username, string resetUrl)
        {
            return $@"
                <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>Hello {username},</p>
                    <p>We received a request to reset your password. Click the link below to reset your password:</p>
                    <p><a href='{resetUrl}' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <p>Best regards,<br>Your App Team</p>
                </body>
                </html>";
        }
    }
}