public class AuthenticationStatusDTO
{
    public bool IsAuthenticated { get
        {
            return IsPasswordCorrect && !RequiresTwoFactorSetup && !RequiresTwoFactor;
        }
    }
    public bool IsPasswordCorrect { get; set; }
    public bool RequiresTwoFactor { get; set; }
    public bool RequiresTwoFactorSetup { get; set; }
}