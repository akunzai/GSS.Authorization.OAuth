using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Reflection;
using GSS.Authorization.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var host = Host.CreateDefaultBuilder()
    .ConfigureServices((context, services) =>
    {
        services.AddOptions<AuthorizerOptions>()
            .Configure(options =>
            {
                options.ClientCredentials = new OAuthCredential(
                    context.Configuration["OAuth:ClientId"]!,
                    context.Configuration["OAuth:ClientSecret"]!);
                options.CallBack = context.Configuration.GetValue<Uri>("OAuth:Callback");
                options.TemporaryCredentialRequestUri =
                    context.Configuration.GetValue<Uri>("OAuth:TemporaryCredentialRequestUri")!;
                options.ResourceOwnerAuthorizeUri =
                    context.Configuration.GetValue<Uri>("OAuth:ResourceOwnerAuthorizeUri")!;
                options.TokenRequestUri = context.Configuration.GetValue<Uri>("OAuth:TokenRequestUri")!;
            })
            .PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), true));
        services.AddSingleton<IRequestSigner, HmacSha1RequestSigner>();
        services.AddHttpClient<InteractiveConsoleAuthorizer>()
            .ConfigureHttpClient(client =>
            {
                client.BaseAddress = context.Configuration.GetValue<Uri>("OAuth:BaseAddress");
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
        services.AddTransient<IAuthorizer>(resolver => resolver.GetRequiredService<InteractiveConsoleAuthorizer>());
    }).Build();

var authorizer = host.Services.GetRequiredService<IAuthorizer>();
var tokenCredentials = await authorizer.GrantAccessAsync().ConfigureAwait(false);
Console.WriteLine("Token Credentials ...");
Console.WriteLine($"Key: {tokenCredentials.Key}");
Console.WriteLine($"Secret: {tokenCredentials.Secret}");
Console.WriteLine("Press any key to exit...");
Console.ReadKey();
