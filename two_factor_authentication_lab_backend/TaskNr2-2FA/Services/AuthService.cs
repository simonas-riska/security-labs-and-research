using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TaskNr2_2FA.Models.DTO;
using TaskNr2_2FA.Models;
using TaskNr2_2FA.QrHelper;
using TaskNr2_2FA.Services.Abstract;
using Microsoft.Extensions.Options;
using System.Text.Json.Serialization;
using TaskNr2_2FA.Helpers;

namespace TaskNr2_2FA.Services
{
    public class AuthService : IAuthService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly JwtSettings _jwtSettings;

        public AuthService(
            SignInManager<User> signInManager,
            UserManager<User> userManager,
            IOptions<JwtSettings> jwtSettings)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<Response<LoginResponseDTO>> LoginUser(SignInUserDTO credentials)
        {
            var user = await FindUserByUsernameOrEmail(credentials.UsernameOrEmail);
            if (user == null)
            {
                return CreateErrorResponse<LoginResponseDTO>("InvalidCredentials", "Email or password is incorrect.");
            }

            var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, credentials.Password, false, true);

            if (signInResult.IsLockedOut)
            {
                return CreateErrorResponse<LoginResponseDTO>("UserLockedOut", "Account is locked due to multiple failed login attempts.");
            }


            if (!signInResult.Succeeded && !signInResult.RequiresTwoFactor)
            {
                return CreateErrorResponse<LoginResponseDTO>("InvalidCredentials", "Email or password is incorrect.");
            }

            
            if (signInResult.RequiresTwoFactor)
            {
                // User needs to set up 2FA
                var token = GenerateTempLoginToken(user);
                //var token = GenerateJwtToken(user, new List<Claim>
                //    {
                //        new Claim("IsPasswordCorrect", "1"),
                //        new Claim(ClaimTypes.NameIdentifier, user.Id)
                //    });

                return CreateTwoFactorResponse(user, token);
            }
            else if (!user.TwoFactorEnabled)
            {
                // User needs to set up 2FA
                var token = Generate2FAToken(user, new List<Claim>
                    {
                        new Claim("IsPasswordCorrect", "1"),
                    });

                return CreateRequires2FASetupResponse(user, token);
            }
            else
            {
                // Should not reach here if 2FA is mandatory
                return CreateErrorResponse<LoginResponseDTO>("UnexpectedState", "Unexpected authentication state.");
            }
        }

        public async Task<Response<IdentityResult>> RegisterUser(RegisterUserDTO userDto)
        {
            var user = new User
            {
                UserName = userDto.Username,
                Email = userDto.Email,
                Name = userDto.Name,
            };

            var result = await _userManager.CreateAsync(user, userDto.Password);
            return result.Succeeded
                ? CreateSuccessResponse(result, "User Registration Successful!")
                : CreateErrorResponse<IdentityResult>("RegistrationFailed", "User Registration Failed!", result.Errors.Select(e => e.Description).ToList());
        }

        public async Task<Response<TwoFactorAuthSetupDTO>> Setup2FAAsync(string userId)
        {
            var user = await FindUserById(userId);
            if (user == null) return CreateErrorResponse<TwoFactorAuthSetupDTO>("UserNotFound", "User not found.");
            if (user.TwoFactorEnabled) return CreateErrorResponse<TwoFactorAuthSetupDTO>("TwoFAAlreadyEnabled", "2FA already enabled.");

            var authenticatorKey = await GetOrResetAuthenticatorKeyAsync(user);

            var payload = Generate2FAPayload(user.Email, authenticatorKey);
            user.TwoFactorSecret = authenticatorKey;

            await _userManager.UpdateAsync(user);
            return CreateSuccessResponse(payload, "2FA setup code generated.");
        }

        public async Task<Response<LoginResponseDTO>> LoginWith2FACode(string userId, string twoFactorCode)
        {
            var user = await FindUserById(userId);
            if (user == null) return CreateErrorResponse<LoginResponseDTO>("UserNotFound", "User not found.");
            if (user.FailedTwoFactorAttempts >= 5 && user.LastFailedTwoFactorAttempt != null && user.LastFailedTwoFactorAttempt > DateTimeOffset.UtcNow.AddMinutes(1))
            {
                return CreateErrorResponse<LoginResponseDTO>("UserLockedOut", "Too many failed 2FA attempts. Try again in 1 minute.");
            }
            var signInResult = await _signInManager.TwoFactorAuthenticatorSignInAsync(
                twoFactorCode,
                isPersistent: false,
                rememberClient: false
            );
            //var isCodeValid = await VerifyTwoFactorCodeAsync(user, twoFactorCode);

            if (!signInResult.Succeeded)
            {
                user.FailedTwoFactorAttempts++;
                user.LastFailedTwoFactorAttempt = DateTimeOffset.UtcNow;
                await _userManager.UpdateAsync(user);
                if (user.FailedTwoFactorAttempts >= 5)
                {
                    return CreateErrorResponse<LoginResponseDTO>("UserLockedOut", "Too many failed 2FA attempts. Try again in 1 minute.");
                }
                return CreateErrorResponse<LoginResponseDTO>("InvalidCode", "Invalid 2FA code.");
            }
            user.FailedTwoFactorAttempts = 0;
            await _userManager.UpdateAsync(user);
            await _signInManager.SignInAsync(user, isPersistent: false);
            var token = Generate2FAToken(user);
            var response = CreateSuccessResponse(new LoginResponseDTO
            {
                Id = user.Id,
                Username = user.UserName,
                Name = user.Name,
                Email = user.Email,
                TwoFactorEnabled = user.TwoFactorEnabled
            }, "Login successful!");

            // Set AuthenticationStatus to "Authenticated"
            response.AuthenticationStatus = "Authenticated";
            response.Token = token;

            return response;
        }


        public async Task<Response<LoginResponseDTO>> LoginWith2FABackupCodeAsync(string userId, string code)
        {
            var user = await FindUserById(userId);
            if (user == null) return CreateErrorResponse<LoginResponseDTO>("UserNotFound", "User not found.");

            var isBackupCodeValid = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, code);
            if (!isBackupCodeValid.Succeeded)
            {
                return CreateErrorResponse<LoginResponseDTO>("InvalidCode", "Invalid 2FA or backup code.");
            }

            await _signInManager.SignInAsync(user, isPersistent: false);

            // Generate a new full token
            var token = Generate2FAToken(user);

            var response = CreateSuccessResponse(new LoginResponseDTO
            {
                Id = user.Id,
                Username = user.UserName,
                Name = user.Name,
                Email = user.Email,
                TwoFactorEnabled = user.TwoFactorEnabled
            }, "Login successful!");

            // Set the token in the response object (not serialized)
            response.Token = token;
            return response;
        }

        public async Task<Response<bool>> DoesUsernameExists(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            bool exists = user != null;
            return CreateSuccessResponse(exists, "Username existence check completed.");
        }

        private async Task<User> FindUserByUsernameOrEmail(string usernameOrEmail)
        {
            return await _userManager.FindByEmailAsync(usernameOrEmail)
                   ?? await _userManager.FindByNameAsync(usernameOrEmail);
        }

        public async Task<Response<TwoFactorBackupCodesDTO>> VerifySetup2FAAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return CreateErrorResponse<TwoFactorBackupCodesDTO>("UserNotFound", "User not found.");
            }
            if (user.TwoFactorEnabled)
            {
                return CreateErrorResponse<TwoFactorBackupCodesDTO>("2FAIsEnabled", "2FA is already set up and enabled.");

            }
            // Verify the 2FA code
            var is2FACodeValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code
            );

            if (!is2FACodeValid)
            {
                return CreateErrorResponse<TwoFactorBackupCodesDTO>("InvalidCode", "Invalid 2FA code.");
            }

            // Enable 2FA for the user
            user.TwoFactorEnabled = true;
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            // Generate backup codes
            var backupCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            var backupCodesDto = new TwoFactorBackupCodesDTO
            {
                UserId = user.Id,
                BackupCodes = backupCodes.ToList()
            };

            // Sign in the user
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Generate full JWT token
            var token = Generate2FAToken(user);

            // Create success response
            var response = CreateSuccessResponse(
                backupCodesDto,
                "2FA has been successfully verified and enabled."
            );

            // Set AuthenticationStatus to "Authenticated"
            response.AuthenticationStatus = "Authenticated";
            response.Token = token;

            return response;
        }


        public async Task<Response<bool>> Delete2FA(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return CreateErrorResponse<bool>("UserNotFound", "User not found.");
            }

            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = null;
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return CreateErrorResponse<bool>("Disable2FAFailed", "Failed to disable 2FA.");
            }

            return CreateSuccessResponse(true, "2FA has been successfully disabled.");
        }

        public async Task<Response<bool>> Logout(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return CreateErrorResponse<bool>("UserNotFound", "User not found.");
            }

            await _signInManager.SignOutAsync();

            return CreateSuccessResponse(true, "User logged out successfully.");
        }

        public async Task<Response<AuthenticationStatusDTO>> IsSignedIn(ClaimsPrincipal userClaims)
        {
            var user = await _userManager.GetUserAsync(userClaims);
            if (user == null)
            {
                return new Response<AuthenticationStatusDTO>
                {
                    Success = false,
                    Data = null,
                    Message = "User not found.",
                    AuthenticationStatus = "UserNotFound"
                };
            }
            var authStatus = new AuthenticationStatusDTO
            {
                IsPasswordCorrect = false,
                RequiresTwoFactor = false,
                RequiresTwoFactorSetup = !user.TwoFactorEnabled
            };
            //var isSignedIn = _signInManager.IsSignedIn(userClaims);

            //if (!isSignedIn)
            //{
            //    //var userId = user.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub).Value;
            //    //if (userId is null)
            //        return new Response<AuthenticationStatusDTO>
            //        {
            //            Success = true,
            //            Data = authStatus,
            //            Message = "Authentication status retrieved.",
            //            AuthenticationStatus = "Login"
            //        };
            //}

            if (userClaims.Identity != null)
            {
                // Check if the user requires two-factor authentication
                var isPasswordCorrectClaim = userClaims.Claims.FirstOrDefault(c => c.Type == "IsPasswordCorrect");
                //var twoFactorEnabledClaim = userClaims.Claims.FirstOrDefault(c => c.Type == "TwoFactorEnabled");
                var isLoggedInUsingTwoFactorClaim = userClaims.Claims.FirstOrDefault(c => c.Type == "LoggedInUsing2FA");
                authStatus.IsPasswordCorrect = (isPasswordCorrectClaim is not null && isPasswordCorrectClaim.Value.Equals("1"));
                //authStatus.RequiresTwoFactorSetup = (twoFactorEnabledClaim is null || twoFactorEnabledClaim.Value == "false");
                //authStatus.RequiresTwoFactor = isLoggedInUsingTwoFactorClaim is null && (twoFactorEnabledClaim is not null && twoFactorEnabledClaim.Value == "true");
                authStatus.RequiresTwoFactor = (isLoggedInUsingTwoFactorClaim is null || isLoggedInUsingTwoFactorClaim.Value == "0") && user.TwoFactorEnabled;

            }

            return new Response<AuthenticationStatusDTO>
            {
                Success = true,
                Data = authStatus,
                Message = "Authentication status retrieved."
            };
        }

        private Response<T> CreateErrorResponse<T>(string code, string message)
        {
            return new Response<T>
            {
                Success = false,
                Message = message,
                Error = new ErrorDetails
                {
                    Code = code,
                    Messages = new List<string> { message }
                }
            };
        }

        private async Task<bool> VerifyTwoFactorCodeAsync(User user, string code)
        {
            return await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code);
        }

        private async Task<User> FindUserById(string userId)
        {
            return await _userManager.FindByIdAsync(userId);
        }

        private Response<LoginResponseDTO> CreateTwoFactorResponse(User user, string token)
        {
            var response = new Response<LoginResponseDTO>
            {
                Success = true,
                Message = "Login requires 2FA",
                Data = new LoginResponseDTO
                {
                    Id = user.Id,
                    Username = user.UserName,
                    Name = user.Name,
                    Email = user.Email,
                    TwoFactorEnabled = user.TwoFactorEnabled
                },
                AuthenticationStatus = "RequiresTwoFactor",
                Token = token // Set the token here (not serialized)
            };
            return response;
        }

        private Response<T> CreateSuccessResponse<T>(T data, string message)
        {
            return new Response<T>
            {
                Success = true,
                Message = message,
                Data = data
            };
        }

        private async Task<string> GetOrResetAuthenticatorKeyAsync(User user)
        {
            var authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(authenticatorKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            return authenticatorKey;
        }

        private TwoFactorAuthSetupDTO Generate2FAPayload(string email, string secret)
        {
            var appName = _jwtSettings.Issuer;
            return new TwoFactorAuthSetupDTO
            {
                QrImage = QrGenerator.GenerateQrCodePayload($"otpauth://totp/{email}?secret={secret}&issuer={appName}"),
                Issuer = appName,
                Email = email,
                Token = secret
            };
        }

        private string Generate2FAToken(User user, List<Claim>? customClaims = null)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("IsPasswordCorrect", "1"),
                new Claim("LoggedInUsing2FA", "1")
            };

            if (customClaims != null)
            {
                claims.AddRange(customClaims);
            }

            // claims.Add(new Claim("Require2FA", user.TwoFactorEnabled.ToString()));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateTempLoginToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Email),
                new Claim("IsPasswordCorrect", "1"),
                new Claim("LoggedInUsing2FA", "0")
            };
            // This token can have a very short expiration time
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tempToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(3), // Short-lived
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(tempToken);
        }

        private Response<T> CreateErrorResponse<T>(string code, string message, List<string> errors)
        {
            return new Response<T>
            {
                Success = false,
                Message = message,
                Error = new ErrorDetails
                {
                    Code = code,
                    Messages = errors ?? new List<string> { message }
                }
            };
        }

        private Response<LoginResponseDTO> CreateRequires2FASetupResponse(User user, string token)
        {
            var response = new Response<LoginResponseDTO>
            {
                Success = true,
                Message = "2FA setup required.",
                Data = new LoginResponseDTO
                {
                    Id = user.Id,
                    Username = user.UserName,
                    Name = user.Name,
                    Email = user.Email,
                    TwoFactorEnabled = user.TwoFactorEnabled
                },
                AuthenticationStatus = "RequiresTwoFactorSetup",
                Token = token // Set the token here (not serialized)
            };
            return response;
        }
    }
}
