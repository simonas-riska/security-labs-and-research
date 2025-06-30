namespace TaskNr2_2FA.Models.DTO
{
    public class TwoFactorAuthSetupDTO
    {
        public string QrImage { get; set; }
        public string Token { get; set; }
        public string Issuer { get; set; }
        public string Email {  get; set; }
    }
}
