using System.Threading;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth
{
    public interface IAuthorizer
    {
        Task<OAuthCredential> GrantAccessAsync(CancellationToken cancellationToken = default);
    }
}
