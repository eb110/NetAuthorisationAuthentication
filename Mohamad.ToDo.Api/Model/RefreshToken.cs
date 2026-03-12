using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace Mohamad.ToDo.Api.Model
{
    //refresh token should last much longer than jwt token
    //it has to be linked with identity table (net asp core one)
    public record RefreshToken
    {
        public int Id { get; set; }
        public required string UserId { get; set; }
        public required string Token { get; set; }
        public required string JwtId { get; set; }
        public bool IsUsed { get; set; }
        public bool IsRevorked { get; set; }
        public DateTime AddedDate { get; set; }
        public DateTime ExpiryDate { get; set; }

        //link to identity user table
        //one to one relationship
        [ForeignKey(nameof(UserId))]
        public IdentityUser User { get; set; } = null!;
        
    }
}
