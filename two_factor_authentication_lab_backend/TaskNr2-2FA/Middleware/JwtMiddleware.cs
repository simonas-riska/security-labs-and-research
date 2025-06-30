using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TaskNr2_2FA.Services.Abstract;
using Microsoft.Extensions.Options;
using TaskNr2_2FA.Helpers; // Namespace where JwtSettings is located

namespace TaskNr2_2FA.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtSettings _jwtSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<JwtSettings> jwtSettings)
        {
            _next = next;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Extract the token from the AuthToken cookie
            var token = context.Request.Cookies["AuthToken"];

            if (!string.IsNullOrWhiteSpace(token))
            {
                try
                {
                    // Parse the token to get claims
                    var principal = GetPrincipalFromToken(token);
                    if (principal != null)
                    {
                        context.User = principal; // Set the context user
                    }
                }
                catch (Exception ex)
                {
                    // Handle token validation errors
                    Console.WriteLine($"Token validation failed: {ex.Message}");
                }
            }

            // Call the next middleware in the pipeline
            await _next(context);
        }

        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var tokenHandler = new JwtSecurityTokenHandler();

            // Set up token validation parameters
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // Validate the token and get the claims principal
            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            return principal; // Return the ClaimsPrincipal
        }
    }
}
