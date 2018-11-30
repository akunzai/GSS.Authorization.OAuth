using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace GSS.Authorization.OAuth2
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add typed HttpClient with <see cref="OAuth2HttpHandler"/> and related services
        /// </summary>
        /// <typeparam name="TClient">The type of the typed client.</typeparam>
        /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions"/>.</param>
        /// <param name="configureAuthorizerHttpClient">A delegate that is used to configure an <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="AuthorizerHttpClient"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuth2HttpClient<TClient, TAuthorizer>(this IServiceCollection services,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizerHttpClient = null)
            where TClient : class
            where TAuthorizer : class, IAuthorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            var builder = services.AddOAuth2Authorizer<TAuthorizer>(configureOptions);

            configureAuthorizerHttpClient?.Invoke(builder);

            return services.AddHttpClient<TClient>()
                .AddHttpMessageHandler(resolver => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(resolver));
        }

        /// <summary>
        /// Add named HttpClient with <see cref="OAuth2HttpHandler"/> and related services
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="name">The logical name of the <see cref="HttpClient"/> to configure.</param>
        /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions"/>.</param>
        /// <param name="configureAuthorizerHttpClient">A delegate that is used to configure an <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="AuthorizerHttpClient"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuth2HttpClient<TAuthorizer>(this IServiceCollection services, string name,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizerHttpClient = null)
            where TAuthorizer : class, IAuthorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            var builder = services.AddOAuth2Authorizer<TAuthorizer>(configureOptions);

            configureAuthorizerHttpClient?.Invoke(builder);

            return services.AddHttpClient(name)
                .AddHttpMessageHandler(resolver => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(resolver));
        }

        /// <summary>
        /// Add OAuth2 Authorizer and related services
        /// </summary>
        /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the <see cref="AuthorizerHttpClient"/>.</returns>
        internal static IHttpClientBuilder AddOAuth2Authorizer<TAuthorizer>(this IServiceCollection services,
            Action<IServiceProvider, AuthorizerOptions> configureOptions)
            where TAuthorizer : class, IAuthorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            services.TryAddTransient<IAuthorizer, TAuthorizer>();

            services.AddOptions<AuthorizerOptions>().Configure<IServiceProvider>((options, resolver) =>
            {
                configureOptions(resolver, options);
            })
            .PostConfigure(options =>
            {
                Validator.ValidateObject(options, new ValidationContext(options), validateAllProperties: true);
            });

            return services.AddHttpClient<AuthorizerHttpClient>();
        }
    }
}
