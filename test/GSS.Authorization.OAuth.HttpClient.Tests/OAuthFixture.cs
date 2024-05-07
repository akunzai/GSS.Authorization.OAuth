using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GSS.Authorization.OAuth.HttpClient.Tests;

public class OAuthFixture
{
    public OAuthFixture()
    {
        Configuration = Host.CreateDefaultBuilder().Build()
            .Services.GetRequiredService<IConfiguration>();
    }

    public IConfiguration Configuration { get; }
}