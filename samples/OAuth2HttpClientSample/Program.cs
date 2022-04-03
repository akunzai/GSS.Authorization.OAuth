using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

static void ConfigureAuthorizerOptions(IServiceProvider resolver, AuthorizerOptions options)
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
    options.ClientId = configuration["OAuth2:ClientId"];
    options.ClientSecret = configuration["OAuth2:ClientSecret"];
    options.SendClientCredentialsInRequestBody =
        configuration.GetValue("OAuth2:SendClientCredentialsInRequestBody", false);
    options.Credentials = new NetworkCredential(
        configuration["OAuth2:Credentials:UserName"],
        configuration["OAuth2:Credentials:Password"]);
    options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
    options.OnError = (code, message) => Console.Error.Write($"ERROR: [${code}]: {message}");
}

static void ConfigureHttpClient(HttpClient client)
{
    var assembly = Assembly.GetEntryAssembly();
    var productName = assembly?.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
    var productVersion = assembly?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? assembly?.GetName().Version?.ToString();
    if (!string.IsNullOrEmpty(productName) && !string.IsNullOrEmpty(productVersion))
    {
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(productName, productVersion));
    }

    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
}

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((hostContext, services) =>
    {
        var clientBuilder =
            hostContext.Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials")
                .Equals("ClientCredentials", StringComparison.OrdinalIgnoreCase)
                ? services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(
                    ConfigureAuthorizerOptions, builder => builder.ConfigureHttpClient(ConfigureHttpClient))
                : services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
                    ConfigureAuthorizerOptions, builder => builder.ConfigureHttpClient(ConfigureHttpClient));
        clientBuilder.ConfigureHttpClient(ConfigureHttpClient);
    }).Build();
var configuration = host.Services.GetRequiredService<IConfiguration>();

Console.WriteLine("Creating a client...");
var oauth2Client = host.Services.GetRequiredService<OAuth2HttpClient>();

Console.WriteLine("Sending a request...");
var response = await oauth2Client.HttpClient.GetAsync(configuration.GetValue<Uri>("OAuth2:ResourceEndpoint"))
    .ConfigureAwait(false);

Console.WriteLine("Response data:");
var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
Console.WriteLine(data);