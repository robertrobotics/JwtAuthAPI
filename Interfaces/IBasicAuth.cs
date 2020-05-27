using JwtAuthAPI.Models;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JwtAuthAPI.Interfaces
{
    interface IBasicAuthController
    {
        /// <summary>
        /// Register new user if user's data is correct.
        /// </summary>
        /// <param name="userDetails">User's details to be registered in DB</param>
        Task<IActionResult> Register([FromBody]UserDetails userDetails);

        /// <summary>
        /// Verifies whether user is registered, then if true let the user login.
        /// </summary>
        /// <param name="userCredentials">User's credentials to be verified.</param>
        Task<IActionResult> Login([FromBody]UserCredentials userCredentials);

        /// <summary>
        /// Logouts user.
        /// </summary>
        Task<IActionResult> Logout();
    }
}
