using System.ComponentModel.DataAnnotations;

namespace Mohamad.ToDo.Api.Model.DTOs.Requests
{
    public class UserRegistrationDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
        [Required]
        public string Username { get; set; } = string.Empty;
    }
}
