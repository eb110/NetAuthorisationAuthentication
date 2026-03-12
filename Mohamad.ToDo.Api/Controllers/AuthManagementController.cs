using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Mohamad.ToDo.Api.Configuration;
using Mohamad.ToDo.Api.Data;
using Mohamad.ToDo.Api.Model;
using Mohamad.ToDo.Api.Model.DTOs.Requests;
using Mohamad.ToDo.Api.Model.DTOs.Responses;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Mohamad.ToDo.Api.Controllers
{
    [Route("api/[controller]")] // http://localhost:5000/api/AuthManagement
    [ApiController]
    //jwtconfig custom class with access to appsetting.json => injected by program class
    //user manager => asp identity ui dll => injected by program class(add default identity) => will give its functionalities
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly ApiDbContext _dbContext;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AuthManagementController> _logger;

        public AuthManagementController(
            UserManager<IdentityUser> userManager, 
            IOptionsMonitor<JwtConfig> optionsMonitor,
            TokenValidationParameters tokenValidationParameters,
            RoleManager<IdentityRole> roleManager,
            ILogger<AuthManagementController> logger,
            ApiDbContext apiDbContext)
        {
            _userManager = userManager;
            //appsettings
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParameters = tokenValidationParameters;
            _dbContext = apiDbContext;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult> Register([FromBody] UserRegistrationDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if (existingUser != null)
                {
                    return BadRequest(new RegistrationResponseDto
                    {
                        Errors = new List<string>()
                        {
                            "email already is use"
                        },
                        Success = false
                    });
                }

                var newUser = new IdentityUser
                {
                    Email = user.Email,
                    UserName = user.Username
                };
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                if(isCreated.Succeeded)
                {
                    //add user to the role => the role has to exist
                    var resultRoleAddition = await _userManager.AddToRoleAsync(newUser, "AppUser");

                    var jwtToken = await GenerateJwtToken(newUser);

                    return Ok(jwtToken);
                }
                else
                {
                    return BadRequest(new RegistrationResponseDto
                    {
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                        Success = false
                    });
                }
            }

            return BadRequest(new RegistrationResponseDto
            {
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult> Login([FromBody] UserLoginRequestDto user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if (existingUser == null)
                {
                    return BadRequest(new RegistrationResponseDto
                    {
                        Errors = new List<string>()
                        {
                            "Invalid login"
                        },
                        Success = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

                if(!isCorrect)
                {
                    return BadRequest(new RegistrationResponseDto
                    {
                        Errors = new List<string>()
                        {
                            "Invalid login"
                        },
                        Success = false
                    });
                }else
                {
                    var jwtToken = await GenerateJwtToken(existingUser);

                    return Ok(jwtToken);
                }
            }

            return BadRequest(new RegistrationResponseDto
            {
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<ActionResult> RefreshToken([FromBody] TokenRequestDto tokenRequest)
        {
            if(ModelState.IsValid)
            {
                var result = await VerifyAndGenerateToken(tokenRequest);

                if(result == null)
                {
                    return BadRequest(new RegistrationResponseDto
                    {
                        Errors = new List<string>() { "Invalid token"},
                        Success = false
                    });
                }

                return Ok(result);
            }

            return BadRequest(new RegistrationResponseDto
            {
                Errors = new List<string>() { "Invalid payload" },
                Success = false
            });
        }

        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto tokenRequest)
        {          
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                //validation 1
                //we have to verify if the token is not a random string but a real token
                //parameters are instantiated within program class
                //the key value comes from appseting.json
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                //validation 2
                //check if the encryption method is the one utilised during creation of the token
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase);

                    if(!result)
                    {
                        throw new("wrong type of security algorithm being used");
                    }
                }

                //validation 3
                //expiry time
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)!.Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                //this is refresh token call
                //if the token is still valid then its and error
                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult
                    {
                        Success = false,
                        Errors = new List<string>() { "Token has not expired yet" }
                    };
                }

                //validation 4
                //user have to have the refreshToken in db
                //if not than it's not a vali request
                var storedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
                if (storedToken == null)
                {
                    return new AuthResult
                    {
                        Success = false,
                        Errors = new List<string>() { "This is not a valid refresh token" }
                    };
                }

                //validation 5
                //if refresh token has expired than its status == IsUsed => true
                if (storedToken.IsUsed)
                {
                    return new AuthResult
                    {
                        Success = false,
                        Errors = new List<string>() { "refresh token being used => invalid" }
                    };
                }


                //validation 6
                if (storedToken.IsRevorked)
                {
                    return new AuthResult
                    {
                        Success = false,
                        Errors = new List<string>() { "refresh token being revorked" }
                    };
                }

                //validation 7
                //jti
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)!.Value;

                if (storedToken.JwtId != jti)
                {
                    return new AuthResult
                    {
                        Success = false,
                        Errors = new List<string>() { "refresh token jti does not correspond to db value" }
                    };
                }

                //TOKEN IS VALID
                //update current token
                storedToken.IsUsed = true;
                _dbContext.RefreshTokens.Update(storedToken);
                await _dbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser!);

            }
            catch(Exception ex)
            {
                throw new("token verification failed");
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTimeVal;
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
            var claims = await GetAllValidClaims(user);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //very important step => get all claims / rule claims / default claims
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            //refresh token
            var refreshToken = new RefreshToken
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevorked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                //refresh token value
                Token = RandomString(35) + Guid.NewGuid()
            };

            _dbContext.RefreshTokens.Add(refreshToken);
            await _dbContext.SaveChangesAsync();

            return new AuthResult
            {
                Success = true,
                Token = jwtToken,
                RefreshToken = refreshToken.Token
            };
        }

        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(x => x[random.Next(x.Length)]).ToArray());
        }

        //remember -> this is the set of claims that will end up in jwt token
        private async Task<List<Claim>> GetAllValidClaims(IdentityUser user)
        {
            var _options = new IdentityOptions();

            //default set of claims for the user
            //every user have to have it - at least in this project
            var claims = new List<Claim>()
            {
                  new Claim("Id", user.Id),
                  new Claim(JwtRegisteredClaimNames.Email, user.Email!),
                  new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
                    //required for the refresh token process
                    //it has to be unique for the current user as it will be validate 
                    //if the token expires and user have to refresh it
                  new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            //Main task - add all user claims and all user role claims to claims list
            //attach the list to jwt

            //extra set of claims from the actual user
            var userClaims = await _userManager.GetClaimsAsync(user);
            //add claims to default set
            claims.AddRange(userClaims);

            //get the user roles and add it to the claims
            var userRoles = await _userManager.GetRolesAsync(user);
            //parse roles to claims
            foreach(var userRole in userRoles)
            {             
                var role = await _roleManager.FindByNameAsync(userRole);

                //role can have claims
                if(role != null)
                {
                    claims.Add(new Claim(ClaimTypes.Role, userRole));
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    foreach(var roleClaim in roleClaims)
                    {
                        claims.Add(roleClaim);
                    }
                }
            }

            //return final list of claims
            return claims;
        }
    }
}
