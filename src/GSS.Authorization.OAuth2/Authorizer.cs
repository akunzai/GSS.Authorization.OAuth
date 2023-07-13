using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth2;

/// <summary>
/// Typed HttpClient to get access token
/// </summary>
public abstract class Authorizer : IAuthorizer
{
    protected Authorizer(HttpClient client)
    {
        Client = client;
    }

    protected HttpClient Client { get; }

    public abstract Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}