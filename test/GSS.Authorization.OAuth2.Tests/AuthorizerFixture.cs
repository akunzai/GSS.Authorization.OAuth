using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GSS.Authorization.OAuth2.Tests;

public class AuthorizerFixture
{
    public AuthorizerFixture()
    {
        Configuration = Host.CreateDefaultBuilder().Build()
            .Services.GetRequiredService<IConfiguration>();
    }

    public IConfiguration Configuration { get; }

    public IServiceProvider BuildAuthorizer<TAuthorizer>(HttpMessageHandler? handler,
        Action<HttpStatusCode, string>? errorHandler)
        where TAuthorizer : class
    {
        handler ??= new HttpClientHandler();
        var services = new ServiceCollection();
        services.AddOptions<AuthorizerOptions>().Configure(options =>
        {
            options.AccessTokenEndpoint = Configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint")!;
            options.ClientId = Configuration["OAuth2:ClientId"]!;
            options.ClientSecret = Configuration["OAuth2:ClientSecret"]!;
            options.Credentials = new NetworkCredential(
                Configuration["OAuth2:Credentials:UserName"],
                Configuration["OAuth2:Credentials:Password"]);
            options.Scopes = Configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            options.OnError = errorHandler;
        }).PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), true));

        services.AddHttpClient<TAuthorizer>()
            .ConfigurePrimaryHttpMessageHandler(_ => handler);
        return services.BuildServiceProvider();
    }
}