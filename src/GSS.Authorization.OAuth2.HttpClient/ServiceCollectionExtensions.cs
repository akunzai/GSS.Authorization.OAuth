using System;
using System.Linq;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;

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
        /// <param name="configureAuthorizer">A delegate that is used to configure an <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuth2HttpClient<TClient, TAuthorizer>(this IServiceCollection services,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizer = null)
            where TClient : class
            where TAuthorizer : Authorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            TryAddOAuth2Authorizer<TAuthorizer>(services, configureOptions, configureAuthorizer);

            return services
                .AddMemoryCache()
                .AddHttpClient<TClient>()
                .AddHttpMessageHandler(resolver => new OAuth2HttpHandler(
                    resolver.GetRequiredService<TAuthorizer>(),
                    resolver.GetRequiredService<IMemoryCache>()));
        }

        /// <summary>
        /// Add named HttpClient with <see cref="OAuth2HttpHandler"/> and related services
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="name">The logical name of the <see cref="HttpClient"/> to configure.</param>
        /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions"/>.</param>
        /// <param name="configureAuthorizer">A delegate that is used to configure an <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuth2HttpClient<TAuthorizer>(this IServiceCollection services, string name,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizer = null)
            where TAuthorizer : Authorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            TryAddOAuth2Authorizer<TAuthorizer>(services, configureOptions, configureAuthorizer);

            return services
                .AddMemoryCache()
                .AddHttpClient(name)
                .AddHttpMessageHandler(resolver => new OAuth2HttpHandler(
                    resolver.GetRequiredService<TAuthorizer>(),
                    resolver.GetRequiredService<IMemoryCache>()));
        }

        /// <summary>
        /// Try Add OAuth2 Authorizer and related services
        /// </summary>
        /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the <see cref="AuthorizerHttpClient"/>.</returns>
        internal static void TryAddOAuth2Authorizer<TAuthorizer>(this IServiceCollection services,
            Action<IServiceProvider, AuthorizerOptions> configureOptions,
            Action<IHttpClientBuilder> configureAuthorizer = null)
            where TAuthorizer : Authorizer
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            if (services.Any(x => x.ServiceType == typeof(TAuthorizer)))
            {
                return;
            }

            services.AddOptions<AuthorizerOptions>()
                .Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
                .PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), validateAllProperties: true));

            var builder = services.AddHttpClient<TAuthorizer>();

            configureAuthorizer?.Invoke(builder);
        }
    }
}
