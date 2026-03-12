using Asp.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Mohamad.ToDo.Api.Data;
using System.Security.Claims;

namespace Mohamad.ToDo.Api.Controllers
{
    //2
    [ApiVersion(1)]
    [Route("api/v{v:apiVersion}/[controller]")] //api/v1/claimssetup
    [ApiController]
    public class ClaimsSetupController(
        ApiDbContext context,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ILogger<SetupController> logger
        ) : ControllerBase
    {

        [HttpGet]
        public async Task<ActionResult<IList<Claim>>> GetAllClaims(string email)
        {
            //userExist
            var userExist = await userManager.FindByEmailAsync(email);
            if (userExist == null)
            {
                logger.LogInformation($"The user {email} does not exist");
                return BadRequest(new
                {
                    result = $"The user {email} does not exist"
                });
            }

            var userClaims = await userManager.GetClaimsAsync(userExist);
            return Ok(userClaims);
        }

        [HttpPost]
        [Route("AddClaimsToUser")]
        public async Task<ActionResult> AddClaimsToUser(string email, string claimKey, string claimValue)
        {
            //check if user exist
            var userExist = await userManager.FindByEmailAsync(email);
            if (userExist == null)
            {
                logger.LogInformation($"The user {email} does not exist");
                return BadRequest(new
                {
                    result = $"The user {email} does not exist"
                });
            }

            var userClaim = new Claim(claimKey, claimValue);

            var result = await userManager.AddClaimAsync(userExist, userClaim);

            if (result.Succeeded)
            {
                logger.LogInformation($"claim has been added");
                return Ok(new
                {
                    result = $"claim has been added"
                });
            }

            logger.LogInformation($"claim has not been added");
            return BadRequest(new
            {
                result = $"claim has not been added"
            });
        }
    }
}
