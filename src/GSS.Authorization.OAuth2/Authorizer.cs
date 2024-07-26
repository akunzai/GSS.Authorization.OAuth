using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth2;

/// <summary>
/// Typed HttpClient to get access token
/// </summary>
public abstract class Authorizer(HttpClient client) : IAuthorizer
{
    protected HttpClient Client { get; } = client;

    public abstract Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}