using Microsoft.AspNetCore.Identity;

namespace TaskNr2_2FA.Models
{
    public class User : IdentityUser
    {
        public string Name { get; set; }
        public string? TwoFactorSecret { get; set; }
        public int FailedTwoFactorAttempts { get; set; }
        public DateTimeOffset? LastFailedTwoFactorAttempt { get; set; }
    }
}
