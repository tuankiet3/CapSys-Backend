using System;
using System.Collections.Generic;
using CapSys_Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace CapSys_Backend.Data;

public partial class CapSysDbContext : DbContext
{
    public CapSysDbContext()
    {
    }

    public CapSysDbContext(DbContextOptions<CapSysDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Account> Accounts { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseSqlServer("Server=TUANKIET\\MSSQLSERVER01;Database=CapSysDB;Integrated Security=SSPI;TrustServerCertificate=True;Encrypt=False;");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Account>(entity =>
        {
            entity.HasKey(e => e.AccountId).HasName("PK__Accounts__349DA586BCC7C183");

            entity.HasIndex(e => e.Username, "UQ__Accounts__536C85E47DBAD6E3").IsUnique();

            entity.HasIndex(e => e.Email, "UQ__Accounts__A9D1053426EA51D6").IsUnique();

            entity.Property(e => e.AccountId).HasColumnName("AccountID");
            entity.Property(e => e.AccountType).HasMaxLength(20);
            entity.Property(e => e.CreatedDate).HasDefaultValueSql("(getdate())");
            entity.Property(e => e.Email).HasMaxLength(100);
            entity.Property(e => e.PasswordHash).HasMaxLength(255);
            entity.Property(e => e.Username).HasMaxLength(50);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
