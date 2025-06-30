//using Microsoft.AspNetCore.Identity;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Text;
//using TaskNr2_2FA.Models;
//using TaskNr2_2FA.Models.DTO;
//using TaskNr2_2FA.QrHelper;
//using TaskNr2_2FA.Services.Abstract;

//namespace TaskNr2_2FA.Services
//{
//    public class AuthService2 : IAuthService
//    {
//        private readonly SignInManager<User> _signInManager;
//        private readonly UserManager<User> _userManager;

//        public AuthService2(SignInManager<User> signInManager,
//            UserManager<User> userManager)
//        {
//            _signInManager = signInManager;
//            _userManager = userManager;
//        }
//        public async Task<Response<LoginResponseDTO>> LoginUser(SignInUserDTO credentials)
//        {
//            var user = await _userManager.FindByEmailAsync(credentials.UsernameOrEmail) ?? await _userManager.FindByNameAsync(credentials.UsernameOrEmail);

//            if (user == null)
//            {
//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "Login failed",
//                    error: new ErrorDetails
//                    {
//                        Code = "InvalidCredentials",
//                        Messages = new List<string> { "Email or password is incorrect." }
//                    }
//                );
//            }
//            var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, credentials.Password, false, false);
//            if (signInResult.RequiresTwoFactor)
//            {
//                return new Response<LoginResponseDTO>(

//                    success: false,
//                    message: "Login requires 2FA",
//                    error: new ErrorDetails
//                    {
//                        Code = "LoginWith2FA",
//                        Messages = new List<string> { "Login requires 2FA" }
//                    },
//                    token: GenerateJwtToken(user, new () { new Claim("IsLoggedInWith2FA", "0"), new Claim("TwoFactorEnabled", user.TwoFactorEnabled ? "1" : "0") }),
//                    data: new() 
//                    { 
//                        Id= user.Id,
//                        TwoFactorEnabled = user.TwoFactorEnabled}
//                );
//            }

//            if (!signInResult.Succeeded)
//            {

//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "Login failed",
//                    error: new ErrorDetails
//                    {
//                        Code = "InvalidCredentials",
//                        Messages = new List<string> { "Email or password is incorrect." }
//                    }
//                );
//            }

//            return new Response<LoginResponseDTO>(
//                success: true,
//                message: "Login successful!",
//                data: new LoginResponseDTO
//                {
//                    Id = user.Id,
//                    Username = user.UserName,
//                    Name = user.Name,
//                    Email = user.Email,
//                    TwoFactorEnabled = user.TwoFactorEnabled
//                },
//                token: GenerateJwtToken(user, new() { new Claim("IsLoggedInWith2FA", "0"), new Claim("TwoFactorEnabled", user.TwoFactorEnabled ? "1" : "0") })

//            );
//        }

//        public async Task<Response<IdentityResult>> RegisterUser(RegisterUserDTO user)
//        {
//            User _user = new()
//            {
//                UserName = user.Username,
//                Email = user.Email,
//                Name = user.Name,
//            };

//            var result = await _userManager.CreateAsync(_user, user.Password);

//            if (!result.Succeeded)
//            {
//                var errors = result.Errors.Select(e => e.Description).ToList();

//                return new Response<IdentityResult>(
//                    success: false,
//                    message: "User Registration Failed!",
//                    error: new ErrorDetails
//                    {
//                        Code = "RegistrationFailed",
//                        Messages = errors
//                    }
//                );
//            }
//            var token = await _userManager.GenerateTwoFactorTokenAsync(_user, TokenOptions.DefaultAuthenticatorProvider);
//            return new Response<IdentityResult>(
//                success: true,
//                message: "User Registration Successful!",
//                data: result
//            );
//        }
//        public async Task<Response<TwoFactorAuthSetupDTO>> Setup2FAAsync(string userId)
//        {
//            var user = await _userManager.FindByIdAsync(userId);
//            if (user == null)
//            {
//                return new Response<TwoFactorAuthSetupDTO>
//                (
//                    success: false,
//                    message: "User not found."
//                );
//            }
//            //var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
//            if (user.TwoFactorEnabled)
//            {
//                return new Response<TwoFactorAuthSetupDTO>
//                (
//                    success: false,
//                    message: "2FA already enabled."
//                );
//            }
//            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);

//            if (string.IsNullOrEmpty(authenticatorKey))
//            {
//                await _userManager.ResetAuthenticatorKeyAsync(user);
//                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
//            }
//            var appName = "TaskNr2_2FA";
//            var authenticatorUri = $"otpauth://totp/{Uri.EscapeDataString(appName)}:{Uri.EscapeDataString(user.Email)}?secret={authenticatorKey}&issuer={Uri.EscapeDataString(appName)}";
//            user.TwoFactorSecret = authenticatorKey;
//            await _userManager.UpdateAsync(user);
//            var payload = new TwoFactorAuthSetupDTO()
//            {
//                QrImage = QrGenerator.GenerateQrCodePayload($"otpauth://totp/{user.Email}?secret={user.TwoFactorSecret}&issuer=TaskNr2_2FA"),
//                Issuer = "TaskNr2_2FA",
//                Email = user.Email,
//                Token = user.TwoFactorSecret
//            };
//            return new Response<TwoFactorAuthSetupDTO>
//            (
//                success: true,
//                data: payload,
//                message: "2FA setup code generated."
//            );
//        }

//        public async Task<Response<LoginResponseDTO>> LoginWith2FACode(string userId, string twoFactorCode)
//        {
//            var user = await _userManager.FindByIdAsync(userId);

//            if (user == null)
//            {
//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "User not found.",
//                    error: new ErrorDetails
//                    {
//                        Code = "UserNotFound",
//                        Messages = new List<string> { "No user exists with the provided ID." }
//                    }
//                );
//            }

//            var isValid2FA = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, twoFactorCode);

//            if (!isValid2FA)
//            {
//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "Invalid 2FA code.",
//                    error: new ErrorDetails
//                    {
//                        Code = "Invalid2FACode",
//                        Messages = new List<string> { "The provided 2FA code is incorrect." }
//                    }
//                );
//            }

//            await _signInManager.SignInAsync(user, isPersistent: false);

//            return new Response<LoginResponseDTO>(
//                success: true,
//                message: "Login successful!",
//                data: new LoginResponseDTO
//                {
//                    Id = user.Id,
//                    Username = user.UserName,
//                    Name = user.Name,
//                    Email = user.Email,
//                    Phone = user.PhoneNumber,
//                    TwoFactorEnabled = user.TwoFactorEnabled
//                }
//            );
//        }

//        public async Task<Response<TwoFactorBackupCodesDTO>> VerifySetup2FAAsync(string userId, string code)
//        {
//            var user = await _userManager.FindByIdAsync(userId);

//            if (user == null)
//            {
//                return new Response<TwoFactorBackupCodesDTO>
//                (
//                    success: false,
//                    message: "User not found."
//                );
//            }

//            var loginResult = await LoginWith2FACode(userId, code);
//            if (!loginResult.Success)
//                return new Response<TwoFactorBackupCodesDTO>(
//                    success: loginResult.Success,
//                    message: loginResult.Message,
//                    data: null,
//                    error: loginResult.Error
//                    );

//            var backupCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
//            if (backupCodes == null)
//            {
//                return new Response<TwoFactorBackupCodesDTO>(
//                    success: false,
//                    message: "FailedToGenerateBackupCodes",
//                    data: null
//                   ,error: new()
//                   {
//                       Code= "FailedToGenerateBackupCodes",
//                       Messages = new() {"Failed to generate backup codes" }
//                   }
//                    );
//            }
//            return new Response<TwoFactorBackupCodesDTO>(
//                    success: true,
//                    message: "2FABackupCodes",
//                    data: new()
//                    {
//                        UserId = user.Id,
//                        BackupCodes = backupCodes

//                    }
//                    );

//        }
//        public async Task<Response<LoginResponseDTO>> LoginWith2FABackupCodeAsync(string userId, string code)
//        {
//            var user = await _userManager.FindByIdAsync(userId);

//            if (user == null)
//            {
//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "User not found.",
//                    error: new ErrorDetails
//                    {
//                        Code = "UserNotFound",
//                        Messages = new List<string> { "No user exists with the provided ID." }
//                    }
//                );
//            }

//            var isBackupCodeValid = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, code);

//            if (!isBackupCodeValid.Succeeded)
//            {
//                return new Response<LoginResponseDTO>(
//                    success: false,
//                    message: "Invalid 2FA or backup code.",
//                    error: new ErrorDetails
//                    {
//                        Code = "InvalidCode",
//                        Messages = new List<string> { "The provided code is incorrect or has been used." }
//                    }
//                );
//            }

//            await _signInManager.SignInAsync(user, isPersistent: false);

//            return new Response<LoginResponseDTO>(
//                success: true,
//                message: "Login successful!",
//                data: new LoginResponseDTO
//                {
//                    Id = user.Id,
//                    Username = user.UserName,
//                    Name = user.Name,
//                    Email = user.Email,
//                    Phone = user.PhoneNumber,
//                    TwoFactorEnabled = user.TwoFactorEnabled
//                }
//            );
//        }
//        public async Task<Response<bool>> Delete2FA(string userId)
//        {
//            var user = await _userManager.FindByIdAsync(userId);

//            if (user == null)
//            {
//                return new Response<bool>
//                (
//                    success: false,
//                    message: "User not found."
//                );
//            }

//            if (!await _userManager.GetTwoFactorEnabledAsync(user))
//            {
//                return new Response<bool>
//                (
//                    success: false,
//                    message: "2FA is not enabled for this user."
//                );
//            }

//            var disable2FAResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
//            if (!disable2FAResult.Succeeded)
//            {
//                return new Response<bool>
//                (
//                    success: false,
//                    message: "Failed to disable 2FA."
//                );
//            }

//            await _userManager.ResetAuthenticatorKeyAsync(user);
//            await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
//            await _signInManager.SignOutAsync();

//            return new Response<bool>
//            (
//                success: true,
//                data: true,
//                message: "Two-Factor Authentication has been successfully disabled."
//            );
//        }

//        public async Task<Response<bool>> Logout(string userId)
//        {
//            await _signInManager.SignOutAsync();
//            return new Response<bool>
//            (
//                success : true,
//                message : "User logged out successfully."
//            );
//        }
//        public Response<bool> IsSignedIn(ClaimsPrincipal user)
//        {
//            if (!_signInManager.IsSignedIn(user))
//                return new Response<bool>
//                (
//                    success: false,
//                    message: "User is not signed in"
//                );
//            return  new Response<bool>
//                (
//                    success: true,
//                    message: "User is signed in"
//                );
//        }

//        public async Task<Response<bool>> DoesUsernameExists(string username)
//        {
//            var user = await _userManager.FindByNameAsync(username);
//            bool userExists = user != null;

//            return new Response<bool>
//            (
//                success: userExists,
//                message: userExists ? "Username exists." : "Username does not exist.",
//                data: userExists
//            );
//        }

//        public async Task<Response<bool>> IsPasswordCorrect(string username, string password)
//        {
//            var usernameResponse = await DoesUsernameExists(username);
//            if (!usernameResponse.Success)
//            {
//                // Return the response from DoesUsernameExists directly if the user does not exist
//                return usernameResponse;
//            }
//            var user = await _userManager.FindByNameAsync(username);

//            // Check if the password is correct
//            var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);

//            return new Response<bool>
//            (
//                success: result.Succeeded,
//                message: result.Succeeded ? "Password is correct." : "Password is incorrect.",
//                data: result.Succeeded
//            );
//        }

//        private string GenerateJwtToken(User user, List<Claim>? customClaims = null)
//        {
//            var claims = new List<Claim>
//            {
//                new Claim(JwtRegisteredClaimNames.Sub, user.Id), // Subject claim
//                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique identifier
//                new Claim("TwoFactorEnabled", (user.TwoFactorEnabled ? 1 : 0).ToString()),
//            };

//            // Add any custom claims if provided
//            if (customClaims != null)
//            {
//                claims.AddRange(customClaims);
//            }

//            // Define the security key using a symmetric key
//            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ITSM_TaskNr2_2FA_MykJ_SimR_VaiV_2024"));

//            // Create signing credentials
//            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//            // Create the JWT token
//            var token = new JwtSecurityToken(
//                issuer: "TaskNr2_2FA",
//                audience: "TaskNr2_2FA",
//                claims: claims,
//                expires: DateTime.Now.AddMinutes(60), // Set token expiration
//                signingCredentials: creds // Set signing credentials
//            );

//            // Write the token as a string
//            return new JwtSecurityTokenHandler().WriteToken(token);
//        }
//    }
//}
