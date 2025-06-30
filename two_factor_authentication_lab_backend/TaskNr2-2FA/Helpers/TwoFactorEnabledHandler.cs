using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;
using TaskNr2_2FA.Helpers;
using TaskNr2_2FA.Models;

public class TwoFactorEnabledHandler : AuthorizationHandler<TwoFactorEnabledRequirement>
{
    private readonly UserManager<User> _userManager;

    public TwoFactorEnabledHandler(UserManager<User> userManager)
    {
        _userManager = userManager;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        TwoFactorEnabledRequirement requirement)
    {
        var IsPasswordCorrect = context.User.HasClaim(c => c.Type == "IsPasswrodCorrect" && c.Value == "1");
        var IsLoggedinWith2FA = context.User.HasClaim(c => c.Type == "LoggedInUsing2FA" && c.Value == "1");
        if (IsPasswordCorrect && IsLoggedinWith2FA)
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null && user.TwoFactorEnabled)
                {
                    context.Succeed(requirement);
                }
            }
        }
    }
}