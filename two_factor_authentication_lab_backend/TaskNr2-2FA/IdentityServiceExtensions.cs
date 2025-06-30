using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using TaskNr2_2FA.DataContext;
using TaskNr2_2FA.Models;
using System;

namespace TaskNr2_2FA.Extensions
{
    public static class IdentityServiceExtensions
    {
        public static IServiceCollection ConfigureIdentity(this IServiceCollection services, IConfigurationManager configuration)
        {
            var issuer = configuration.GetSection("JwtSettings:Issuer").Value;
            services.AddIdentity<User, IdentityRole>(options =>
            {
                // User settings
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

                // Password settings
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 3;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                options.Password.RequiredUniqueChars = 1;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // Sign-in settings
                options.SignIn.RequireConfirmedEmail = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;

                // Tokens
                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider; // Default 2FA provider
                options.Tokens.AuthenticatorIssuer = issuer;
            })
            .AddEntityFrameworkStores<TaskNr2_DataContext>()
            .AddDefaultTokenProviders()
            ;
            //.AddDefaultTokenProviders();

            // Token lifespan configuration
            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromHours(3);
            });

            return services;
        }
    }
}
