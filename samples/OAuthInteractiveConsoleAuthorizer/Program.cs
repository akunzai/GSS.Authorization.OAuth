using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Reflection;
using GSS.Authorization.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddOptions<AuthorizerOptions>()
    .Configure(options =>
    {
        options.ClientCredentials = new OAuthCredential(
            builder.Configuration["OAuth:ClientId"]!,
            builder.Configuration["OAuth:ClientSecret"]!);
        options.CallBack = builder.Configuration.GetValue<Uri>("OAuth:Callback");
        options.TemporaryCredentialRequestUri =
            builder.Configuration.GetValue<Uri>("OAuth:TemporaryCredentialRequestUri")!;
        options.ResourceOwnerAuthorizeUri =
            builder.Configuration.GetValue<Uri>("OAuth:ResourceOwnerAuthorizeUri")!;
        options.TokenRequestUri = builder.Configuration.GetValue<Uri>("OAuth:TokenRequestUri")!;
    })
    .PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), true));
builder.Services.AddSingleton<IRequestSigner, HmacSha1RequestSigner>();
builder.Services.AddHttpClient<InteractiveConsoleAuthorizer>()
    .ConfigureHttpClient(client =>
    {
        client.BaseAddress = builder.Configuration.GetValue<Uri>("OAuth:BaseAddress");
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
builder.Services.AddTransient<IAuthorizer>(resolver => resolver.GetRequiredService<InteractiveConsoleAuthorizer>());
var host = builder.Build();

var authorizer = host.Services.GetRequiredService<IAuthorizer>();
var tokenCredentials = await authorizer.GrantAccessAsync().ConfigureAwait(false);
Console.WriteLine("Token Credentials ...");
Console.WriteLine($"Key: {tokenCredentials.Key}");
Console.WriteLine($"Secret: {tokenCredentials.Secret}");
Console.WriteLine("Press any key to exit...");
Console.ReadKey();
