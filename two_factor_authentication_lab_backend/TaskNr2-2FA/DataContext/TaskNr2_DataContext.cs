using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using TaskNr2_2FA.Models;

namespace TaskNr2_2FA.DataContext
{
    public class TaskNr2_DataContext : IdentityDbContext<User, IdentityRole, string>
    {
        public TaskNr2_DataContext(DbContextOptions<TaskNr2_DataContext> dbOptions) : base(dbOptions) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }

    }
}