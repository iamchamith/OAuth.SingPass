using Microsoft.AspNetCore.Authentication.OAuth;

namespace AspNet.Security.OAuth.SingPass
{
    public class SingPassAuthenticationOptions : OAuthOptions
    {
        public string RederectUrl { get; set; }
        public SingPassAuthenticationOptions()
        {
            ClaimsIssuer = SingPassAuthenticationDefaults.Issuer;
            CallbackPath = SingPassAuthenticationDefaults.CallbackPath;         
        }
    }
}
