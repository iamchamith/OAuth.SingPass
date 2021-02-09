using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;
using Newtonsoft.Json;

namespace AspNet.Security.OAuth.SingPass
{
    public class SingPassAuthenticationHandler : OAuthHandler<SingPassAuthenticationOptions>
    {
        public SingPassAuthenticationHandler(IOptionsMonitor<SingPassAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
              : base(options, logger, encoder, clock)
        { }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            if (!tokens.Response.RootElement.TryGetProperty("subject", out var subject))
                throw new SingPassAuthenticationException("Cannot find valid subject");

            var subjectString = subject.GetString();
             
            identity.AddClaim(new Claim("sub", subjectString));
            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, subject);
            context.RunClaimActions(subject);

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        }
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var state = Options.StateDataFormat.Protect(properties);
            var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            queryStrings.Add("response_type", "code");
            queryStrings.Add("state", state);
            queryStrings.Add("client_id", Options.ClientId);
            queryStrings.Add("redirect_uri", Options.RederectUrl + Options.CallbackPath);

            var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationEndpoint;
        }
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            return base.HandleChallengeAsync(properties);
        }
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["redirect_uri"] = Options.RederectUrl,
                ["code"] = context.Code,
                ["client_id"] = Options.ClientId,
                ["client_secret"] = Options.ClientSecret
            };

            request.Content = new FormUrlEncodedContent(parameters!);

            using var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }
            var httpContent = await response.Content.ReadAsStringAsync();
            var tokenInfo = JsonConvert.DeserializeObject<dynamic>(httpContent);
            tokenInfo["subject"] = context.Code;
            var payload = JsonDocument.Parse(JsonConvert.SerializeObject(tokenInfo));

            return OAuthTokenResponse.Success(payload);
        }
    }
}

