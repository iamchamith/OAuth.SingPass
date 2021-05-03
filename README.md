Go startup.cs
add following code under ConfigureServices

  `services.AddSingPass("SingPass", options =>
              {
                  options.AuthorizationEndpoint = Configuration["ExternalLogins:SingPass:AuthorizationEndpoint"];
                  options.TokenEndpoint = Configuration["ExternalLogins:SingPass:TokenEndpoint"];
                  options.RederectUrl = Configuration["ExternalLogins:SingPass:RederectUrl"];
                  options.ClientId = Configuration["ExternalLogins:SingPass:ClientId"];
                  options.ClientSecret = Configuration["ExternalLogins:SingPass:ClientSecret"];
                  options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                  options.SaveTokens = true;
              });`
