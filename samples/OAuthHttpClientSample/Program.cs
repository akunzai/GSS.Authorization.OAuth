using System.Net.Http.Headers;
using System.Reflection;
using GSS.Authorization.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((hostContext, services) =>
    {
        services.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
        {
            options.ClientCredentials = new OAuthCredential(
                hostContext.Configuration["OAuth:ClientId"]!,
                hostContext.Configuration["OAuth:ClientSecret"]!);
            options.TokenCredentials = new OAuthCredential(
                hostContext.Configuration["OAuth:TokenId"]!,
                hostContext.Configuration["OAuth:TokenSecret"]!);
            options.SignedAsQuery = hostContext.Configuration.GetValue("OAuth:SignedAsQuery", false);
            options.SignedAsBody = hostContext.Configuration.GetValue("OAuth:SignedAsBody", false);
        }).ConfigureHttpClient(client =>
        {
            var assembly = Assembly.GetEntryAssembly();
            var productName = assembly?.GetCustomAttribute<AssemblyProductAttribute>()?.Product;
            var productVersion =
                assembly?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ??
                assembly?.GetName().Version?.ToString();
            if (!string.IsNullOrEmpty(productName) && !string.IsNullOrEmpty(productVersion))
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(productName, productVersion));
            }
        });
    }).Build();

var configuration = host.Services.GetRequiredService<IConfiguration>();

Console.WriteLine("Creating a client...");
var oauthClient = host.Services.GetRequiredService<OAuthHttpClient>();

Console.WriteLine("Sending a request...");
var method = new HttpMethod(configuration.GetValue("Request:Method", HttpMethod.Get.Method)!);
var request = new HttpRequestMessage(method, configuration.GetValue<Uri>("Request:Uri"));
var accept = configuration["Request:Accept"];
if (!string.IsNullOrWhiteSpace(accept))
{
    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(accept));
}

var body = configuration.GetSection("Request:Body").Get<IDictionary<string, string>>();
if (body != null)
{
    request.Content = new FormUrlEncodedContent(body);
}

var response = await oauthClient.HttpClient.SendAsync(request).ConfigureAwait(false);

Console.WriteLine("Response data:");
var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
Console.WriteLine(data);