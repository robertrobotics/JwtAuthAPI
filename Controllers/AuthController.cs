using JwtAuthAPI.Interfaces;
using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase, IBasicAuthController
    {
        private readonly JwtBearerTokenSettings _jwtBearerTokenSettings;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthController(IOptions<JwtBearerTokenSettings> jwtTokenOptions, UserManager<IdentityUser> userManager)
        {
            _jwtBearerTokenSettings = jwtTokenOptions.Value;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody]UserDetails userDetails)
        {
            if (!ModelState.IsValid || userDetails == null)
            {
                return new BadRequestObjectResult(new { Message = "User could not be registered" });
            }

            var identityUser = new IdentityUser() { UserName = userDetails.UserName, Email = userDetails.Email };
            var result = await _userManager.CreateAsync(identityUser, userDetails.Password);
            if (!result.Succeeded)
            {
                var dictionary = new ModelStateDictionary();
                result.Errors.ToList().ForEach(error => dictionary.AddModelError(error.Code, error.Description));

                return new BadRequestObjectResult(new { Message = "User could not be registered", Errors = dictionary });
            }

            return Ok(new { Message = "User has been registered" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody]UserCredentials userCredentials)
        {
            IdentityUser identityUser;

            if (!ModelState.IsValid || 
                userCredentials == null || 
                (identityUser = await ValidateUser(userCredentials)) == null)
            {
                return new BadRequestObjectResult(new { Message = "Login failed" });
            }
            return Ok(new { Token = GenerateSecurityToken(identityUser), Message = "Successful login" });
        }

        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            return Ok(new { Token = "", Message = "User has been logged out" });
        }

        private async Task<IdentityUser> ValidateUser(UserCredentials userCredentials)
        {
            var identityUser = string.IsNullOrEmpty(userCredentials.Username) 
                ? null 
                : await _userManager.FindByNameAsync(userCredentials.Username);

            if (identityUser != null)
            {
                var passwordVerificationResult = _userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, userCredentials.Password);
                return passwordVerificationResult == PasswordVerificationResult.Failed ? null : identityUser;
            }

            return null;
        }


        private object GenerateSecurityToken(IdentityUser identityUser)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, identityUser.UserName.ToString()),
                    new Claim(ClaimTypes.Email, identityUser.Email)
                }),

                Expires = DateTime.UtcNow.AddSeconds(_jwtBearerTokenSettings.ExpiryTime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _jwtBearerTokenSettings.Audience,
                Issuer = _jwtBearerTokenSettings.Issuer
            };

            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(securityToken);
        }
    }
}
