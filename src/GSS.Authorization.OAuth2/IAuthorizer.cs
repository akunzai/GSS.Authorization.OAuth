using System.Threading;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth2;

public interface IAuthorizer
{
    Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default);
}