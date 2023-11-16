using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GSS.Authorization.OAuth2.HttpClient.Tests;

public class OAuth2Fixture
{
    public OAuth2Fixture()
    {
        var host = Host.CreateDefaultBuilder()
            .Build();
        Configuration = host.Services.GetRequiredService<IConfiguration>();
    }

    public IConfiguration Configuration { get; }

    public IServiceProvider BuildOAuth2HttpClient(HttpMessageHandler? handler)
    {
        handler ??= new HttpClientHandler();
        var services = new ServiceCollection();
        services.AddOptions<OAuth2HttpHandlerOptions>().Configure(options =>
        {
            options.SendAccessTokenInQuery = Configuration.GetValue("OAuth2:SendAccessTokenInQuery", false);
        });
        if (Configuration.GetValue("OAuth2:GrantFlow", "ResourceOwnerCredentials")!
            .Equals("ClientCredentials", StringComparison.OrdinalIgnoreCase))
            services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(ConfigureAuthorizerOptions,
                    authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => handler))
                .ConfigurePrimaryHttpMessageHandler(_ => handler);
        else
            services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
                    ConfigureAuthorizerOptions,
                    authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => handler))
                .ConfigurePrimaryHttpMessageHandler(_ => handler);
        return services.BuildServiceProvider();
    }

    private void ConfigureAuthorizerOptions(IServiceProvider resolver, AuthorizerOptions options)
    {
        options.AccessTokenEndpoint = Configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint")!;
        options.ClientId = Configuration["OAuth2:ClientId"]!;
        options.ClientSecret = Configuration["OAuth2:ClientSecret"]!;
        options.SendClientCredentialsInRequestBody = true;
        options.Credentials = new NetworkCredential(
            Configuration["OAuth2:Credentials:UserName"],
            Configuration["OAuth2:Credentials:Password"]);
        options.Scopes = Configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
    }
}