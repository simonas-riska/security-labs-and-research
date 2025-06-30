using System.ComponentModel.DataAnnotations;

namespace TaskNr2_2FA.Models.DTO
{
    public class RegisterUserDTO
    {
        [Required] public string Username { get; set; }
        [Required] public string Password { get; set; } = string.Empty;
        [Required] public string Email { get; set; }
        [Required] public string Name { get; set; }

    }
}
