namespace TaskNr2_2FA.Models.DTO
{
    public class TwoFactorBackupCodesDTO
    {
        public string UserId { get; set; }
        public IEnumerable<string> BackupCodes { get; set; }


    }
}
