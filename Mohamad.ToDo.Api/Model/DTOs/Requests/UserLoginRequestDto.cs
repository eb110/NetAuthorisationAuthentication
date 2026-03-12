using System.ComponentModel.DataAnnotations;

namespace Mohamad.ToDo.Api.Model.DTOs.Requests
{
    public class UserLoginRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
