using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Add typed HttpClient with <see cref="OAuth2HttpHandler" /> and related services
    /// </summary>
    /// <remarks>
    /// Each HttpClient name gets its own <see cref="AuthorizerOptions" /> and <see cref="Authorizer" /> instance.
    /// The first registration is also bound to the unnamed <see cref="IOptions{TOptions}" /> and to the container
    /// registration of <typeparamref name="TAuthorizer" />, so resolving those yields the configuration of the
    /// first registered client.
    /// <para>
    /// The access token is cached per HttpClient name for the lifetime of the registration, so it survives
    /// handler rotation, and concurrent callers share a single request to the authorization server.
    /// </para>
    /// </remarks>
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions" />.</param>
    /// <param name="configureAuthorizer">
    /// A delegate that is used to configure an
    /// <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer" />.
    /// </param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuth2HttpClient<TClient, TAuthorizer>(
        this IServiceCollection services,
        Action<IServiceProvider, AuthorizerOptions> configureOptions,
        Action<IHttpClientBuilder>? configureAuthorizer = null)
        where TClient : class
        where TAuthorizer : Authorizer
    {
        return services.AddOAuth2HttpClient<TClient, TAuthorizer>(configureOptions, configureAuthorizer, null);
    }

    /// <summary>
    /// Add typed HttpClient with <see cref="OAuth2HttpHandler" /> and related services
    /// </summary>
    /// <inheritdoc cref="AddOAuth2HttpClient{TClient, TAuthorizer}(IServiceCollection, Action{IServiceProvider, AuthorizerOptions}, Action{IHttpClientBuilder})" path="/remarks" />
    /// <typeparam name="TClient">The type of the typed client.</typeparam>
    /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions" />.</param>
    /// <param name="configureAuthorizer">
    /// A delegate that is used to configure an
    /// <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer" />.
    /// </param>
    /// <param name="configureHandler">
    /// A delegate that is used to configure an <see cref="OAuth2HttpHandlerOptions" /> for this client only.
    /// When <see langword="null" />, the client uses the unnamed <see cref="OAuth2HttpHandlerOptions" />.
    /// </param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuth2HttpClient<TClient, TAuthorizer>(
        this IServiceCollection services,
        Action<IServiceProvider, AuthorizerOptions> configureOptions,
        Action<IHttpClientBuilder>? configureAuthorizer,
        Action<IServiceProvider, OAuth2HttpHandlerOptions>? configureHandler)
        where TClient : class
        where TAuthorizer : Authorizer
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        if (configureOptions == null) throw new ArgumentNullException(nameof(configureOptions));

        return AddOAuth2HttpClientCore<TAuthorizer>(
            services,
            services.AddMemoryCache().AddHttpClient<TClient>(),
            configureOptions,
            configureAuthorizer,
            configureHandler);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuth2HttpHandler" /> and related services
    /// </summary>
    /// <remarks>
    /// Each HttpClient name gets its own <see cref="AuthorizerOptions" /> and <see cref="Authorizer" /> instance.
    /// The first registration is also bound to the unnamed <see cref="IOptions{TOptions}" /> and to the container
    /// registration of <typeparamref name="TAuthorizer" />, so resolving those yields the configuration of the
    /// first registered client.
    /// <para>
    /// The access token is cached per HttpClient name for the lifetime of the registration, so it survives
    /// handler rotation, and concurrent callers share a single request to the authorization server.
    /// </para>
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="System.Net.Http.HttpClient" /> to configure.</param>
    /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions" />.</param>
    /// <param name="configureAuthorizer">
    /// A delegate that is used to configure an
    /// <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer" />.
    /// </param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuth2HttpClient<TAuthorizer>(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, AuthorizerOptions> configureOptions,
        Action<IHttpClientBuilder>? configureAuthorizer = null)
        where TAuthorizer : Authorizer
    {
        return services.AddOAuth2HttpClient<TAuthorizer>(name, configureOptions, configureAuthorizer, null);
    }

    /// <summary>
    /// Add named HttpClient with <see cref="OAuth2HttpHandler" /> and related services
    /// </summary>
    /// <inheritdoc cref="AddOAuth2HttpClient{TAuthorizer}(IServiceCollection, string, Action{IServiceProvider, AuthorizerOptions}, Action{IHttpClientBuilder})" path="/remarks" />
    /// <param name="services">The <see cref="IServiceCollection" />.</param>
    /// <param name="name">The logical name of the <see cref="System.Net.Http.HttpClient" /> to configure.</param>
    /// <typeparam name="TAuthorizer">The type of the authorizer.</typeparam>
    /// <param name="configureOptions">A delegate that is used to configure an <see cref="AuthorizerOptions" />.</param>
    /// <param name="configureAuthorizer">
    /// A delegate that is used to configure an
    /// <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> for the <see cref="Authorizer" />.
    /// </param>
    /// <param name="configureHandler">
    /// A delegate that is used to configure an <see cref="OAuth2HttpHandlerOptions" /> for this client only.
    /// When <see langword="null" />, the client uses the unnamed <see cref="OAuth2HttpHandlerOptions" />.
    /// </param>
    /// <returns>
    /// An <see cref="T:Microsoft.Extensions.DependencyInjection.IHttpClientBuilder" /> that can be used to configure
    /// the client.
    /// </returns>
    public static IHttpClientBuilder AddOAuth2HttpClient<TAuthorizer>(
        this IServiceCollection services,
        string name,
        Action<IServiceProvider, AuthorizerOptions> configureOptions,
        Action<IHttpClientBuilder>? configureAuthorizer,
        Action<IServiceProvider, OAuth2HttpHandlerOptions>? configureHandler)
        where TAuthorizer : Authorizer
    {
        if (services == null) throw new ArgumentNullException(nameof(services));

        if (configureOptions == null) throw new ArgumentNullException(nameof(configureOptions));

        return AddOAuth2HttpClientCore<TAuthorizer>(
            services,
            services.AddMemoryCache().AddHttpClient(name),
            configureOptions,
            configureAuthorizer,
            configureHandler);
    }

    private static IHttpClientBuilder AddOAuth2HttpClientCore<TAuthorizer>(
        IServiceCollection services,
        IHttpClientBuilder builder,
        Action<IServiceProvider, AuthorizerOptions> configureOptions,
        Action<IHttpClientBuilder>? configureAuthorizer,
        Action<IServiceProvider, OAuth2HttpHandlerOptions>? configureHandler)
        where TAuthorizer : Authorizer
    {
        // The HttpClient name is the seam HttpClientFactory already keys on, so options are keyed on it too.
        // The first client keeps the unnamed options and the container registration of TAuthorizer, so both
        // still describe that client, and configureOptions runs exactly once per client.
        var isFirstClient = !services.Any(x => x.ServiceType == typeof(TAuthorizer));
        var optionsName = isFirstClient ? Options.DefaultName : builder.Name;

        services.AddOptions<AuthorizerOptions>(optionsName)
            .Configure<IServiceProvider>((options, resolver) => configureOptions(resolver, options))
            .PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), true));

        // A colon never appears in the name AddHttpClient<T>() derives, so this cannot collide with a caller's name.
        var authorizerClientName = $"{builder.Name}:{typeof(TAuthorizer).Name}";
        var authorizerBuilder = isFirstClient
            ? services.AddHttpClient<TAuthorizer>()
            : services.AddHttpClient(authorizerClientName);
        configureAuthorizer?.Invoke(authorizerBuilder);

        if (configureHandler != null)
        {
            services.AddOptions<OAuth2HttpHandlerOptions>(builder.Name)
                .Configure<IServiceProvider>((options, resolver) => configureHandler(resolver, options));
        }

        // One cache per client name, so the access token and its single-flight guarantee survive the
        // handler rotation HttpClientFactory performs.
        var accessTokens = new AccessTokenCacheHolder(builder.Name);

        return builder.AddHttpMessageHandler(resolver => new OAuth2HttpHandler(
            ResolveHandlerOptions(resolver, builder.Name, configureHandler != null),
            accessTokens.Get(resolver,
                () => ResolveAuthorizer<TAuthorizer>(resolver, optionsName, authorizerClientName, isFirstClient))));
    }

    private static IOptions<OAuth2HttpHandlerOptions> ResolveHandlerOptions(
        IServiceProvider resolver,
        string name,
        bool configured)
    {
        return configured
            ? Options.Create(resolver.GetRequiredService<IOptionsMonitor<OAuth2HttpHandlerOptions>>().Get(name))
            : resolver.GetRequiredService<IOptions<OAuth2HttpHandlerOptions>>();
    }

    private static IAuthorizer ResolveAuthorizer<TAuthorizer>(
        IServiceProvider resolver,
        string optionsName,
        string authorizerClientName,
        bool isFirstClient)
        where TAuthorizer : Authorizer
    {
        if (isFirstClient)
        {
            return resolver.GetRequiredService<TAuthorizer>();
        }

        // IOptions<T> and IOptionsMonitor<T> keep separate caches and would each run configureOptions,
        // so only the named clients go through the monitor.
        var options = resolver.GetRequiredService<IOptionsMonitor<AuthorizerOptions>>().Get(optionsName);
        var client = resolver.GetRequiredService<IHttpClientFactory>().CreateClient(authorizerClientName);
        return ActivatorUtilities.CreateInstance<TAuthorizer>(resolver, client, Options.Create(options));
    }

    /// <summary>
    /// Holds the access token cache of a single HttpClient name.
    /// </summary>
    private sealed class AccessTokenCacheHolder(string name)
    {
        private readonly object _gate = new();
        private AccessTokenCache? _cache;

        public AccessTokenCache Get(IServiceProvider resolver, Func<IAuthorizer> authorizer)
        {
            if (_cache != null)
            {
                return _cache;
            }

            lock (_gate)
            {
                return _cache ??= new AccessTokenCache(
                    authorizer, resolver.GetRequiredService<IMemoryCache>(), name);
            }
        }
    }
}
