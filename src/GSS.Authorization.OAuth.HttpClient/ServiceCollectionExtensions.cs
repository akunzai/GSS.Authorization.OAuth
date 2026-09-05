using System;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth;

public static class ServiceCollectionExtensions
{
    // Probing whether a signer can take OAuthOptions is a property of the type, not of a container,
    // so the result is cached across registrations. A null entry means "no matching constructor".
    private static readonly ConcurrentDictionary<Type, ObjectFactory?> _signerFactories = new();

    /// <summary>
    /// Add typed HttpClient with <see cref="OAuthHttpHandler" /> and related services
    /// </summary>
    /// <remarks>
    /// Each HttpClient name gets its own <typeparamref name="TOptions" /> and request signer.
    /// The first registration is also bound to the unnamed <see cref="IOptions{TOptions}" /> and to the
    /// singleton <typeparamref name="TRequestSigner" />, so resolving those from the container yields the
    /// configuration of the first registered client.
    /// </remarks>
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
    /// <typeparam name="TOptions">The type of the configure options.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TClient, TRequestSigner, TOptions>(
        this IServiceCollection services,
        Action<IServiceProvider, TOptions> configureOptions)
        where TClient : class
        where TRequestSigner : class, IRequestSigner
        where TOptions : OAuthHttpHandlerOptions, new()
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configureOptions == null)
        {
            throw new ArgumentNullException(nameof(configureOptions));
        }

        return AddOAuthHttpClientCore<TRequestSigner, TOptions>(
            services, services.AddHttpClient<TClient>(), configureOptions);
    }

    /// <summary>
    /// Add typed HttpClient with <see cref="OAuthHttpHandler" /> and related services
    /// </summary>
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TClient, TRequestSigner>(
        this IServiceCollection services,
        Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
        where TClient : class
        where TRequestSigner : class, IRequestSigner
    {
        return services.AddOAuthHttpClient<TClient, TRequestSigner, OAuthHttpHandlerOptions>(configureOptions);
    }

    /// <summary>
    /// Add typed HttpClient with <see cref="OAuthHttpHandler" /> and default request signer (HMAC-SHA1)
    /// </summary>
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <typeparam name="TOptions">The type of the configure options.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TClient, TOptions>(
        this IServiceCollection services,
        Action<IServiceProvider, TOptions> configureOptions)
        where TClient : class
        where TOptions : OAuthHttpHandlerOptions, new()
    {
        return services.AddOAuthHttpClient<TClient, HmacSha1RequestSigner, TOptions>(configureOptions);
    }

    /// <summary>
    /// Add typed HttpClient with <see cref="OAuthHttpHandler" /> and default request signer (HMAC-SHA1)
    /// </summary>
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TClient>(
        this IServiceCollection services,
        Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
        where TClient : class
    {
        return services.AddOAuthHttpClient<TClient, OAuthHttpHandlerOptions>(configureOptions);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuthHttpHandler" /> and related services
    /// </summary>
    /// <remarks>
    /// Each HttpClient name gets its own <typeparamref name="TOptions" /> and request signer.
    /// The first registration is also bound to the unnamed <see cref="IOptions{TOptions}" /> and to the
    /// singleton <typeparamref name="TRequestSigner" />, so resolving those from the container yields the
    /// configuration of the first registered client.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="HttpClient" /> to configure.</param>
    /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
    /// <typeparam name="TOptions">The type of the configure options.</typeparam>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TRequestSigner, TOptions>(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, TOptions> configureOptions)
        where TRequestSigner : class, IRequestSigner
        where TOptions : OAuthHttpHandlerOptions, new()
    {
        if (services == null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (configureOptions == null)
        {
            throw new ArgumentNullException(nameof(configureOptions));
        }

        return AddOAuthHttpClientCore<TRequestSigner, TOptions>(
            services, services.AddHttpClient(name), configureOptions);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuthHttpHandler" /> and related services
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="HttpClient" /> to configure.</param>
    /// <typeparam name="TRequestSigner">The type of the request signer.</typeparam>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TRequestSigner>(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
        where TRequestSigner : class, IRequestSigner
    {
        return services.AddOAuthHttpClient<TRequestSigner, OAuthHttpHandlerOptions>(name, configureOptions);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuthHttpHandler" /> and default request signer (HMAC-SHA1)
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="HttpClient" /> to configure.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient<TOptions>(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, TOptions> configureOptions)
        where TOptions : OAuthHttpHandlerOptions, new()
    {
        return services.AddOAuthHttpClient<HmacSha1RequestSigner, TOptions>(name, configureOptions);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuthHttpHandler" /> and default request signer (HMAC-SHA1)
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="HttpClient" /> to configure.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="OAuthHttpHandlerOptions" />.</param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuthHttpClient(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, OAuthHttpHandlerOptions> configureOptions)
    {
        return services.AddOAuthHttpClient<OAuthHttpHandlerOptions>(name, configureOptions);
    }

    private static IHttpClientBuilder AddOAuthHttpClientCore<TRequestSigner, TOptions>(
        IServiceCollection services,
        IHttpClientBuilder builder,
        Action<IServiceProvider, TOptions> configureOptions)
        where TRequestSigner : class, IRequestSigner
        where TOptions : OAuthHttpHandlerOptions, new()
    {
        // The HttpClient name is the seam HttpClientFactory already keys on, so options are keyed on it too.
        // The first client keeps the unnamed options as its own instance, so resolving IOptions<TOptions>
        // from the container yields exactly what that client's handler uses, and configureOptions still
        // runs once per client.
        var isFirstClient = !services.Any(x => x.ServiceType == typeof(IConfigureOptions<TOptions>));
        var optionsName = isFirstClient ? Options.DefaultName : builder.Name;

        services.TryAddSingleton<TRequestSigner>();

        services.AddOptions<TOptions>(optionsName)
            .Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
            .PostConfigure(ValidateOptions);

        var signer = new SignerCache<TRequestSigner>();

        return builder.AddHttpMessageHandler(resolver =>
        {
            // IOptions<T> and IOptionsMonitor<T> keep separate caches and would each run configureOptions,
            // so the first client must stay on IOptions<T> to share one instance with whoever resolves it.
            var options = isFirstClient
                ? resolver.GetRequiredService<IOptions<TOptions>>().Value
                : resolver.GetRequiredService<IOptionsMonitor<TOptions>>().Get(optionsName);
            return new OAuthHttpHandler(Options.Create(options), signer.Get(resolver, options));
        });
    }

    private static void ValidateOptions(OAuthHttpHandlerOptions options)
    {
        Validator.ValidateObject(options, new ValidationContext(options), true);
        if (string.IsNullOrWhiteSpace(options.ClientCredentials.Key))
        {
            throw new ArgumentNullException(
                $"{nameof(options.ClientCredentials)}.{nameof(options.ClientCredentials.Key)}");
        }

        if (string.IsNullOrWhiteSpace(options.ClientCredentials.Secret))
        {
            throw new ArgumentNullException(
                $"{nameof(options.ClientCredentials)}.{nameof(options.ClientCredentials.Secret)}");
        }

        if (string.IsNullOrWhiteSpace(options.TokenCredentials.Key))
        {
            throw new ArgumentNullException(
                $"{nameof(options.TokenCredentials)}.{nameof(options.TokenCredentials.Key)}");
        }

        if (string.IsNullOrWhiteSpace(options.TokenCredentials.Secret))
        {
            throw new ArgumentNullException(
                $"{nameof(options.TokenCredentials)}.{nameof(options.TokenCredentials.Secret)}");
        }
    }

    /// <summary>
    /// Holds the request signer of a single HttpClient name. The signer snapshots that name's options,
    /// which matches how <see cref="OAuthHttpHandler" /> snapshots them.
    /// </summary>
    private sealed class SignerCache<TRequestSigner> where TRequestSigner : class, IRequestSigner
    {
        private readonly object _gate = new();
        private IRequestSigner? _signer;

        public IRequestSigner Get(IServiceProvider resolver, OAuthOptions options)
        {
            if (_signer != null)
            {
                return _signer;
            }

            lock (_gate)
            {
                return _signer ??= Create(resolver, options);
            }
        }

        private static IRequestSigner Create(IServiceProvider resolver, OAuthOptions options)
        {
            var factory = _signerFactories.GetOrAdd(typeof(TRequestSigner), type =>
            {
                try
                {
                    return ActivatorUtilities.CreateFactory(type, new[] { typeof(OAuthOptions) });
                }
                catch (InvalidOperationException)
                {
                    // The signer takes no OAuthOptions, so it cannot be built per client name.
                    return null;
                }
            });

            return factory == null
                ? resolver.GetRequiredService<TRequestSigner>()
                : (IRequestSigner)factory(resolver, new object[] { options });
        }
    }
}
