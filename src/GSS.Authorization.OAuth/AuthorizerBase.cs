using System;
using System.Collections.Specialized;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;

namespace GSS.Authorization.OAuth
{
    public abstract class AuthorizerBase : IAuthorizer
    {
        private readonly AuthorizerOptions _options;
        private readonly HttpClient _httpClient;
        private readonly IRequestSigner _signer;

        protected AuthorizerBase(
            AuthorizerOptions options,
            HttpClient httpClient,
            IRequestSigner signer)
        {
            _options = options;
            _httpClient = httpClient;
            _signer = signer;
        }

        public async Task<OAuthCredential> GrantAccessAsync(CancellationToken cancellationToken = default)
        {
            // Step 1: Temporary Credentials, see http://tools.ietf.org/html/rfc5849#section-2.1
            var temporaryCredentials = await GetTemporaryCredentialAsync(cancellationToken).ConfigureAwait(false);

            // Step 2: Resource Owner Authorization, see http://tools.ietf.org/html/rfc5849#section-2.2
            var verificationCode = await GetVerificationCodeAsync(temporaryCredentials, cancellationToken).ConfigureAwait(false);

            // Step 3: Token Credentials, see https://tools.ietf.org/html/rfc5849#section-2.3
            return await GetTokenCredentialAsync(temporaryCredentials, verificationCode, cancellationToken).ConfigureAwait(false);
        }

        protected internal virtual async Task<OAuthCredential> GetTemporaryCredentialAsync(CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.TemporaryCredentialRequestUri);
            request.Headers.Authorization = _signer.GetAuthorizationHeader(
                request.Method,
                request.RequestUri.IsAbsoluteUri ? request.RequestUri : new Uri(_httpClient.BaseAddress, request.RequestUri),
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthCallback] = _options.CallBack == null ? OAuthDefaults.OutOfBand : _options.CallBack.AbsoluteUri
                });
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var formData = await response.Content.ReadAsFormDataAsync(cancellationToken).ConfigureAwait(false);
            HandleOAuthException(response, formData);
            return new OAuthCredential(formData[OAuthDefaults.OAuthToken], formData[OAuthDefaults.OAuthTokenSecret]);
        }

        protected internal virtual async Task<string> GetVerificationCodeAsync(OAuthCredential temporaryCredentials, CancellationToken cancellationToken = default)
        {
            var authorizeUri = QueryHelpers.AddQueryString(_options.ResourceOwnerAuthorizeUri.ToString(),
                OAuthDefaults.OAuthToken, temporaryCredentials.Key);
            using var authorizeResponse = await _httpClient.GetAsync(authorizeUri, cancellationToken).ConfigureAwait(false);
            authorizeResponse.EnsureSuccessStatusCode();
            using var response = await AuthorizeAsync(_options.ResourceOwnerCredentials, temporaryCredentials, authorizeResponse.Content, cancellationToken).ConfigureAwait(false);
            return await GetVerificationCodeAsync(response, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Asking the resource owner to authorize the requested access
        /// </summary>
        /// <param name="resourceOwnerCredentials">the resource owner resourceOwnerCredentials</param>
        /// <param name="temporaryCredentials"></param>
        /// <param name="authorizePage"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public abstract Task<HttpResponseMessage> AuthorizeAsync(NetworkCredential resourceOwnerCredentials, OAuthCredential temporaryCredentials, HttpContent authorizePage,
            CancellationToken cancellationToken = default);

        public virtual Task<string> GetVerificationCodeAsync(HttpResponseMessage response,
            CancellationToken cancellationToken = default)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response));
            return Task.FromResult((string)QueryHelpers.ParseQuery(response.Headers.Location.Query)[OAuthDefaults.OAuthVerifier]);
        }

        protected internal virtual async Task<OAuthCredential> GetTokenCredentialAsync(OAuthCredential temporaryCredentials, string verificationCode, CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.TokenRequestUri);
            request.Headers.Authorization = _signer.GetAuthorizationHeader(
                request.Method,
                request.RequestUri.IsAbsoluteUri ? request.RequestUri : new Uri(_httpClient.BaseAddress, request.RequestUri),
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthVerifier] = verificationCode
                }, temporaryCredentials);
            var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var formData = await response.Content.ReadAsFormDataAsync(cancellationToken).ConfigureAwait(false);
            HandleOAuthException(response, formData);
            return new OAuthCredential(formData[OAuthDefaults.OAuthToken], formData[OAuthDefaults.OAuthTokenSecret]);
        }

        protected virtual void HandleOAuthException(HttpResponseMessage request, NameValueCollection formData)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            if (formData == null)
                throw new ArgumentNullException(nameof(formData));
            if (request.IsSuccessStatusCode)
                return;
            var oauthProblem = formData[OAuthDefaults.OAuthProblem];
            if (string.IsNullOrWhiteSpace(oauthProblem))
                request.EnsureSuccessStatusCode();
            throw oauthProblem switch
            {
                OAuthDefaults.ParameterAbsent => new OAuthException($"Missing parameters: {formData[OAuthDefaults.OAuthParametersAbsent]}"),
                _ => new OAuthException(string.Join(",", formData)),
            };
        }
    }
}
