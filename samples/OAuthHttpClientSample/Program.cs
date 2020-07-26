using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using GSS.Authorization.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OAuthHttpClientSample
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                   {
                       options.ClientCredentials = new OAuthCredential(
                           hostContext.Configuration["OAuth:ClientId"],
                           hostContext.Configuration["OAuth:ClientSecret"]);
                       options.TokenCredentials = new OAuthCredential(
                               hostContext.Configuration["OAuth:TokenId"],
                               hostContext.Configuration["OAuth:TokenSecret"]);
                       options.SignedAsQuery = hostContext.Configuration.GetValue("OAuth:SignedAsQuery", false);
                       options.SignedAsBody = hostContext.Configuration.GetValue("OAuth:SignedAsBody", false);
                   }).ConfigureHttpClient(client =>
                   {
                       client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                   });
                }).Build();
            var configuration = host.Services.GetRequiredService<IConfiguration>();

            Console.WriteLine("Creating a client...");
            var oauthClient = host.Services.GetRequiredService<OAuthHttpClient>();

            Console.WriteLine("Sending a request...");
            var method = new HttpMethod(configuration.GetValue("Request:Method", HttpMethod.Get.Method));
            var request = new HttpRequestMessage(method, configuration.GetValue<Uri>("Request:Uri"));
            var body = configuration.GetSection("Request:Body").Get<IDictionary<string, string>>();
            if (body != null)
            {
                request.Content = new FormUrlEncodedContent(body);
            }
            var response = await oauthClient.HttpClient.SendAsync(request).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);
        }
    }
}
