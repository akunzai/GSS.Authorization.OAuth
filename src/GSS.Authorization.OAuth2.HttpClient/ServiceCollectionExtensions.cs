using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace GSS.Authorization.OAuth2
{
    public static class ServiceCollectionExtensions
    {
        public static IHttpClientBuilder AddOAuth2HttpClient(this IServiceCollection services,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizerHttpClient = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }
            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }
            services.TryAddTransient<IAuthorizer, ResourceOwnerCredentialsAuthorizer>();
            
            var authorizerHttpClientBuilder = services.AddHttpClient<AuthorizerHttpClient>();
            configureAuthorizerHttpClient?.Invoke(authorizerHttpClientBuilder);

            services.AddOptions<AuthorizerOptions>().Configure<IServiceProvider>((options, resolver) =>
            {
                configureOptions(resolver, options);
            })
            .PostConfigure(options =>
            {
                Validator.ValidateObject(options, new ValidationContext(options), validateAllProperties: true);
            });

            return services.AddHttpClient<OAuth2HttpClient>()
                .AddHttpMessageHandler(resolver => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(resolver));
        }
    }
}
