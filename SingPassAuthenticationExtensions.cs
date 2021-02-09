using System; 
using AspNet.Security.OAuth.SingPass;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{

    public static class SingPassAuthenticationExtensions
    {
        public static AuthenticationBuilder AddSingPass([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddSingPass(SingPassAuthenticationDefaults.AuthenticationScheme, options => { });
        }
        public static AuthenticationBuilder AddSingPass(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<SingPassAuthenticationOptions> configuration)
        {
            return builder.AddSingPass(SingPassAuthenticationDefaults.AuthenticationScheme, configuration);
        }
        public static AuthenticationBuilder AddSingPass(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme,
            [NotNull] Action<SingPassAuthenticationOptions> configuration)
        {
            return builder.AddSingPass(scheme, SingPassAuthenticationDefaults.DisplayName, configuration);
        }

        public static AuthenticationBuilder AddSingPass(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme,
            [CanBeNull] string caption,
            [NotNull] Action<SingPassAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<SingPassAuthenticationOptions, SingPassAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}
