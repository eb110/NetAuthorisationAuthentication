using System.ComponentModel.DataAnnotations;

namespace Mohamad.ToDo.Api.Model.DTOs.Requests
{
    public class TokenRequestDto
    {
        [Required]
        public string Token { get; set; } = string.Empty;
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
