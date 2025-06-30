using Microsoft.AspNetCore.Mvc;
using TaskNr2_2FA.Services.Abstract;
using TaskNr2_2FA.Models.DTO;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using TaskNr2_2FA.Models;

namespace TaskNr2_2FA.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        // Constructor
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost, Route("login")]
        [AllowAnonymous]
        public async Task<IActionResult> SignIn(SignInUserDTO credentials)
        {
            var response = await _authService.LoginUser(credentials);
            if (response.Success)
            {
                // Set the JWT token as an HttpOnly cookie
                SetJwtCookie(response.Token);
            }
            return HandleResponse(response);
        }

        [HttpPost("username-exists")]
        [AllowAnonymous]
        public async Task<IActionResult> CheckUsernameExists(string username)
        {
            return Ok(await _authService.DoesUsernameExists(username));
        }

        [HttpPost, Route("register")]
        [AllowAnonymous]
        public async Task<IActionResult> SignUp(RegisterUserDTO userDetails)
        {
            var response = await _authService.RegisterUser(userDetails);
            return HandleResponse(response);
        }

        [HttpPost, Route("setup2fa")]
        [Authorize]
        public async Task<IActionResult> Setup2FA()
        {
            var loggedInUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (loggedInUserId is null)
                return Unauthorized("You are not authorized to set up 2FA for this account.");

            var response = await _authService.Setup2FAAsync(loggedInUserId);
            return HandleResponse(response);
        }

        [HttpPost, Route("login2fa")]
        [Authorize]
        public async Task<IActionResult> Login2FA(string code)
        {
            var loggedInUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (loggedInUserId is null)
                return Unauthorized("You are not authorized.");

            var response = await _authService.LoginWith2FACode(loggedInUserId, code);
            if (response.Success)
            {
                // Set the new JWT token as an HttpOnly cookie
                SetJwtCookie(response.Token);
            }
            return HandleResponse(response);
        }

        [HttpPost, Route("login2fabackupcode")]
        [AllowAnonymous]
        public async Task<IActionResult> Login2FABackupCode(string code)
        {
            var loggedInUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (loggedInUserId is null)
                return Unauthorized("You are not authorized to verify 2FA for this account.");

            var response = await _authService.LoginWith2FABackupCodeAsync(loggedInUserId, code);
            if (response.Success)
            {
                // Set the new JWT token as an HttpOnly cookie
                SetJwtCookie(response.Token);
            }
            return HandleResponse(response);
        }

        [HttpPost, Route("verify2fa")]
        [Authorize]
        public async Task<IActionResult> Verify2FA(string code)
        {
            var loggedInUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (loggedInUserId is null)
                return Unauthorized("You are not authorized to verify 2FA for this account.");

            var response = await _authService.VerifySetup2FAAsync(loggedInUserId, code);
            return HandleResponse(response);
        }

        [HttpPost, Route("delete2fa")]
        [Authorize]
        public async Task<IActionResult> Delete2FA()
        {
            var loggedInUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (loggedInUserId is null)
                return Unauthorized("You are not authorized to delete 2FA for this account.");

            var response = await _authService.Delete2FA(loggedInUserId);
            return HandleResponse(response);
        }

        [HttpPost, Route("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var response = await _authService.Logout(User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (response.Success)
            {
                // Remove the authentication cookie
                Response.Cookies.Delete("AuthToken");
            }
            return HandleResponse(response);
        }

        [HttpPost, Route("isloggedin")]
        public async Task<IActionResult> IsLoggedIn()
        {
            var user = User;
            return HandleResponse(await _authService.IsSignedIn(User));
        }

        // Helper method to set the JWT as an HttpOnly cookie
        private void SetJwtCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true, 
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(60)
            };
            Response.Cookies.Append("AuthToken", token, cookieOptions);
        }

        public static IActionResult HandleResponse<T>(Response<T> result)
        {
            if (result.Success)
                return new OkObjectResult(result);

            return new BadRequestObjectResult(result);
        }


    }
}
