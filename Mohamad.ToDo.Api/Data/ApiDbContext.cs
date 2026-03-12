using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mohamad.ToDo.Api.Model;

namespace Mohamad.ToDo.Api.Data
{
    public class ApiDbContext(DbContextOptions<ApiDbContext> options) : IdentityDbContext(options)
    {
        public virtual DbSet<ItemData> Items { get; set; }
        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
