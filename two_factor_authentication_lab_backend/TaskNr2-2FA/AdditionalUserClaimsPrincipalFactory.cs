using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using TaskNr2_2FA.Models;

namespace TaskNr2_2FA
{
    public class AdditionalUserClaimsPrincipalFactory :
        UserClaimsPrincipalFactory<User>
    {
        public AdditionalUserClaimsPrincipalFactory(
            UserManager<User> userManager,
            IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, optionsAccessor)
        {
        }

        public async override Task<ClaimsPrincipal> CreateAsync(User user)
        {
            var principal = await base.CreateAsync(user);
            var identity = (ClaimsIdentity)principal.Identity;

            var claims = new List<Claim>();

            if (user.TwoFactorEnabled)
            {
                claims.Add(new Claim("amr", "mfa"));
            }
            else
            {
                claims.Add(new Claim("amr", "pwd"));
            }

            identity.AddClaims(claims);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
            return principal;
        }
    }
}
