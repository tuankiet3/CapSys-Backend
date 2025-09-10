using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CapSys_Backend.Dtos
{
    public class RegisterRequest
    {

        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;


        [Required(ErrorMessage = "Email is required")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;


        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters long")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;


        [Required(ErrorMessage = "Please confirm your password")]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;


        [Required(ErrorMessage = "Account type is required")]
        [StringLength(20, ErrorMessage = "Account type cannot exceed 20 characters")]
        [Display(Name = "Account Type")]
        public string AccountType { get; set; } = "Student";
    }
}