using Asp.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Mohamad.ToDo.Api.Data;

namespace Mohamad.ToDo.Api.Controllers
{
    //1
    [ApiVersion(1)]
    [Route("api/v{v:apiVersion}/[controller]")] //api/v1/setup
    [ApiController]
    public class SetupController(
        ApiDbContext context,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ILogger<SetupController> logger
        ) : ControllerBase
    {

        [HttpGet]
        public async Task<ActionResult<List<IdentityRole>>> GetAllRoles()
        {
            var roles = await roleManager.Roles.ToListAsync();
            return Ok(roles);
        }

        [HttpPost]
        public async Task<ActionResult> CreateRole(string name)
        {
            //check if role exist
            var roleExist = await roleManager.RoleExistsAsync(name);
            if (!roleExist)
            {
                var roleResult = await roleManager.CreateAsync(new IdentityRole(name));
                if (roleResult.Succeeded)
                {
                    logger.LogInformation($"The role {name} has been added successfully");
                    return Ok(new
                    {
                        result = $"The role {name} has been added successfully"
                    });
                }

                logger.LogInformation($"The role {name} has NOT been added successfully");
                return BadRequest(new
                {
                    result = $"The role {name} has been added successfully"
                });
            }

            return BadRequest(new { error = "Role already exist" });
        }

        [HttpGet]
        [Route("GetAllUsers")]
        public async Task<ActionResult<List<IdentityUser>>> GetAllUsers()
        {
            var users = await userManager.Users.ToListAsync();

            return Ok(users);
        }

        [HttpPost]
        [Route("AddUserToRole")]
        public async Task<ActionResult> AddUserToRole(string email, string roleName)
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

            //check if role exist
            var roleExist = await roleManager.RoleExistsAsync(roleName);
            if (!roleExist)
            {
                logger.LogInformation($"The role {roleName} does not exist");
                return BadRequest(new
                {
                    result = $"The role {roleName} does not exist"
                });
            }

            //do the job
            var result = await userManager.AddToRoleAsync(userExist, roleName);
            if (result.Succeeded)
            {
                logger.LogInformation($"The role {roleName} has been added successfully to user");
                return Ok(new
                {
                    result = $"The role {roleName} has been added successfully to user"
                });
            }

            logger.LogInformation($"Adding new role to user failed");
            return BadRequest(new
            {
                result = $"Adding new role to user failed"
            });
        }

        [HttpGet]
        [Route("GetUserRoles")]
        public async Task<ActionResult<IList<string>>> GetUserRoles(string email)
        {
            //check the email
            var userExist = await userManager.FindByEmailAsync(email);
            if (userExist == null)
            {
                logger.LogInformation($"The user {email} does not exist");
                return BadRequest(new
                {
                    result = $"The user {email} does not exist"
                });
            }

            //return the roles
            var roles = await userManager.GetRolesAsync(userExist);

            return Ok(roles);
        }

        [HttpPost]
        [Route("RemoveUserFromRole")]
        public async Task<ActionResult> RemoveUserFromRoles(string email, string roleName)
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

            //roleExist
            var roleExist = await roleManager.RoleExistsAsync(roleName);
            if (!roleExist)
            {
                logger.LogInformation($"The role {roleName} does not exist");
                return BadRequest(new
                {
                    result = $"The role {roleName} does not exist"
                });
            }

            //removeRole
            var result = await userManager.RemoveFromRoleAsync(userExist, roleName);

            if (result.Succeeded)
            {
                logger.LogInformation($"The role {roleName} has been removed");
                return Ok(new
                {
                    result = $"The role {roleName} has been removed"
                });
            }

            logger.LogInformation($"role removal failed");
            return BadRequest(new
            {
                result = $"role removal failed"
            });
        }
    }
}
