namespace TaskNr2_2FA.Models.DTO
{
    public class LoginResponseDTO
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Address { get; set; }
        public bool TwoFactorEnabled { get; set; }
    }
}
