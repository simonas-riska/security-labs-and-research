using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using TaskNr2_2FA.Models;
using TaskNr2_2FA.Models.DTO;

namespace TaskNr2_2FA.Services.Abstract
{
    public interface IAuthService
    {
        Task<Response<LoginResponseDTO>> LoginUser(SignInUserDTO credentials);
        Task<Response<IdentityResult>> RegisterUser(RegisterUserDTO user);
        Task<Response<TwoFactorAuthSetupDTO>> Setup2FAAsync(string userId);
        Task<Response<LoginResponseDTO>> LoginWith2FACode(string userId, string twoFactorCode);
        Task<Response<TwoFactorBackupCodesDTO>> VerifySetup2FAAsync(string userId, string code);
        Task<Response<LoginResponseDTO>> LoginWith2FABackupCodeAsync(string userId, string code);
        Task<Response<bool>> Delete2FA(string userId);
        Task<Response<bool>> Logout(string userId);
        Task<Response<AuthenticationStatusDTO>> IsSignedIn(ClaimsPrincipal user);
        Task<Response<bool>> DoesUsernameExists(string username);
        //Task<Response<bool>> IsPasswordCorrect(string username, string password);

    }
}
