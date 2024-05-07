using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Reflection;
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

static void ConfigureAuthorizerOptions(IServiceProvider resolver, AuthorizerOptions options)
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint")!;
    options.ClientId = configuration["OAuth2:ClientId"]!;
    options.ClientSecret = configuration["OAuth2:ClientSecret"]!;
    options.SendClientCredentialsInRequestBody =
        configuration.GetValue("OAuth2:SendClientCredentialsInRequestBody", false);
    options.Credentials = new NetworkCredential(
        configuration["OAuth2:Credentials:UserName"],
        configuration["OAuth2:Credentials:Password"]);
    options.Scopes = configuration["OAuth2:Scope"]?.Split(" ");
    options.OnError = (code, message) => Console.Error.Write($"ERROR: [${code}]: {message}");
}

static void ConfigureHttpClient(HttpClient client)
{
    var assembly = Assembly.GetEntryAssembly();
    var productName = assembly?.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
    var productVersion = assembly?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ??
                         assembly?.GetName().Version?.ToString();
    if (!string.IsNullOrEmpty(productName) && !string.IsNullOrEmpty(productVersion))
    {
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(productName, productVersion));
    }

    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddOptions<OAuth2HttpHandlerOptions>().Configure(options =>
{
    options.SendAccessTokenInBody = builder.Configuration.GetValue("OAuth2:SendAccessTokenInBody", false);
    options.SendAccessTokenInQuery = builder.Configuration.GetValue("OAuth2:SendAccessTokenInQuery", false);
});
var clientBuilder =
    builder.Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials")!
        .Equals("ClientCredentials", StringComparison.OrdinalIgnoreCase)
        ? builder.Services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(
            ConfigureAuthorizerOptions, b => b.ConfigureHttpClient(ConfigureHttpClient))
        : builder.Services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
            ConfigureAuthorizerOptions, b => b.ConfigureHttpClient(ConfigureHttpClient));
clientBuilder.ConfigureHttpClient(ConfigureHttpClient);
var host = builder.Build();

var configuration = host.Services.GetRequiredService<IConfiguration>();

Console.WriteLine("Creating a client...");
var oauth2Client = host.Services.GetRequiredService<OAuth2HttpClient>();

Console.WriteLine("Sending a request...");
var response = await oauth2Client.HttpClient.GetAsync(configuration.GetValue<Uri>("OAuth2:ResourceEndpoint"))
    .ConfigureAwait(false);

Console.WriteLine("Response data:");
var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
Console.WriteLine(data);