using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add typed HttpClient with <see cref="OAuthHttpHandler"/> and related services
        /// </summary>
        /// <typeparam name="TClient">The type of the typed client.</typeparam>
        /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuthHttpClient<TClient, TRequestSigner>(this IServiceCollection services,
            Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
            where TClient : class
            where TRequestSigner : RequestSignerBase
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            services.TryAddSingleton<TRequestSigner>();

            services.AddOptions<OAuthHttpHandlerOptions>()
                .Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
                .PostConfigure(ValidateOptions);

            return services
                .AddHttpClient<TClient>()
                .AddHttpMessageHandler(resolver => new OAuthHttpHandler(
                    resolver.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>(),
                    resolver.GetRequiredService<TRequestSigner>()));
        }

        /// <summary>
        /// Add typed HttpClient with <see cref="OAuthHttpHandler"/> and default request signer (HMAC-SHA1)
        /// </summary>
        /// <typeparam name="TClient">The type of the typed client.</typeparam>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuthHttpClient<TClient>(this IServiceCollection services,
            Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
            where TClient : class
        {
            return services.AddOAuthHttpClient<TClient, HmacSha1RequestSigner>(configureOptions);
        }

        /// <summary>
        /// Add named HttpClient with <see cref="OAuthHttpHandler"/> and related services
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="name">The logical name of the <see cref="HttpClient"/> to configure.</param>
        /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuthHttpClient<TRequestSigner>(this IServiceCollection services, string name,
            Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
            where TRequestSigner : RequestSignerBase
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            services.TryAddSingleton<TRequestSigner>();

            services.AddOptions<OAuthHttpHandlerOptions>()
                .Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
                .PostConfigure(ValidateOptions);

            return services
                .AddHttpClient(name)
                .AddHttpMessageHandler(resolver => new OAuthHttpHandler(
                    resolver.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>(),
                    resolver.GetRequiredService<TRequestSigner>()));
        }

        /// <summary>
        /// Add named HttpClient with <see cref="OAuthHttpHandler"/> and default request signer (HMAC-SHA1)
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="name">The logical name of the <see cref="HttpClient"/> to configure.</param>
        /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions"/>.</param>
        /// <returns>An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure the client.</returns>
        public static IHttpClientBuilder AddOAuthHttpClient(this IServiceCollection services, string name,
            Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
        {
            return services.AddOAuthHttpClient<HmacSha1RequestSigner>(name, configureOptions);
        }

        private static void ValidateOptions(OAuthHttpHandlerOptions options)
        {
            Validator.ValidateObject(options, new ValidationContext(options), true);
            if (string.IsNullOrWhiteSpace(options.ClientCredentials.Key))
            {
                throw new ArgumentNullException($"{nameof(options.ClientCredentials)}.{nameof(options.ClientCredentials.Key)}");
            }
            if (string.IsNullOrWhiteSpace(options.ClientCredentials.Secret))
            {
                throw new ArgumentNullException($"{nameof(options.ClientCredentials)}.{nameof(options.ClientCredentials.Secret)}");
            }
        }
    }
}
