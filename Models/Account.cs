using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
namespace CapSys_Backend.Models;

public partial class Account
{
    public int AccountId { get; set; }

    [Required]
    [StringLength(50)]
    public string Username { get; set; } = null!;
    [Required]
    [StringLength(100)]
    [EmailAddress]
    public string Email { get; set; } = null!;
    [Required]
    [StringLength(255)]
    public string PasswordHash { get; set; } = null!;
    [Required]
    [StringLength(20)]
    public string AccountType { get; set; } = null!;

    public DateTime? CreatedDate { get; set; }
}
