using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace GSS.Authorization.OAuth
{
    public abstract class AuthorizerBase : IAuthorizer
    {
        private const string UrlEncodedContentType = "application/x-www-form-urlencoded";
        private readonly AuthorizerOptions _options;
        private readonly HttpClient _httpClient;
        private readonly IRequestSigner _signer;

        protected AuthorizerBase(
            IOptions<AuthorizerOptions> options,
            HttpClient httpClient,
            IRequestSigner signer)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            _options = options.Value;
            _httpClient = httpClient;
            _signer = signer;
        }

        public async Task<OAuthCredential> GrantAccessAsync(CancellationToken cancellationToken = default)
        {
            // Step 1: Temporary Credentials, see http://tools.ietf.org/html/rfc5849#section-2.1
            var temporaryCredentials = await GetTemporaryCredentialAsync(cancellationToken).ConfigureAwait(false);

            // Step 2: Resource Owner Authorization, see http://tools.ietf.org/html/rfc5849#section-2.2
            var authorizeUriWithToken = QueryHelpers.AddQueryString(_options.ResourceOwnerAuthorizeUri.ToString(),
                OAuthDefaults.OAuthToken, temporaryCredentials.Key);
            var authorizationUri = _options.ResourceOwnerAuthorizeUri.IsAbsoluteUri
                ? new Uri(authorizeUriWithToken)
                : new Uri(_httpClient.BaseAddress, authorizeUriWithToken);
            var verificationCode =
                await GetVerificationCodeAsync(authorizationUri, cancellationToken).ConfigureAwait(false);

            // Step 3: Token Credentials, see https://www.rfc-editor.org/rfc/rfc5849#section-2.3
            return await GetTokenCredentialAsync(temporaryCredentials, verificationCode, cancellationToken)
                .ConfigureAwait(false);
        }

        protected internal virtual async Task<OAuthCredential> GetTemporaryCredentialAsync(
            CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.TemporaryCredentialRequestUri);
            request.Headers.Authorization = _signer.GetAuthorizationHeader(
                request.Method,
                request.RequestUri.IsAbsoluteUri
                    ? request.RequestUri
                    : new Uri(_httpClient.BaseAddress, request.RequestUri),
                _options,
                new Dictionary<string, StringValues>
                {
                    [OAuthDefaults.OAuthCallback] = _options.CallBack == null
                        ? OAuthDefaults.OutOfBand
                        : _options.CallBack.AbsoluteUri
                });
            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (!string.Equals(response.Content.Headers?.ContentType?.MediaType, UrlEncodedContentType, StringComparison.OrdinalIgnoreCase))
            {
                throw new HttpRequestException($"Invalid response with media-type: {response.Content.Headers?.ContentType?.MediaType}");
            }
            var urlEncoded = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var formData = QueryHelpers.ParseQuery(urlEncoded);
            HandleOAuthException(response, formData);
            return new OAuthCredential(formData[OAuthDefaults.OAuthToken], formData[OAuthDefaults.OAuthTokenSecret]);
        }

        /// <summary>
        /// authorize resource owner and get the verification code
        /// </summary>
        /// <param name="authorizationUri"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>the verification code</returns>
        public abstract Task<string> GetVerificationCodeAsync(Uri authorizationUri,
            CancellationToken cancellationToken = default);

        protected internal virtual async Task<OAuthCredential> GetTokenCredentialAsync(
            OAuthCredential temporaryCredentials, string verificationCode,
            CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _options.TokenRequestUri);
            request.Headers.Authorization = _signer.GetAuthorizationHeader(
                request.Method,
                request.RequestUri.IsAbsoluteUri
                    ? request.RequestUri
                    : new Uri(_httpClient.BaseAddress, request.RequestUri),
                _options,
                new Dictionary<string, StringValues>
                {
                    [OAuthDefaults.OAuthVerifier] = verificationCode
                }, temporaryCredentials);
            var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (!string.Equals(response.Content.Headers?.ContentType?.MediaType, UrlEncodedContentType, StringComparison.OrdinalIgnoreCase))
            {
                throw new HttpRequestException($"Invalid response with media-type: {response.Content.Headers?.ContentType?.MediaType}");
            }
            var urlEncoded = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var formData = QueryHelpers.ParseQuery(urlEncoded);
            HandleOAuthException(response, formData);
            return new OAuthCredential(formData[OAuthDefaults.OAuthToken], formData[OAuthDefaults.OAuthTokenSecret]);
        }

        protected virtual void HandleOAuthException(HttpResponseMessage request,
            IDictionary<string, StringValues> formData)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            if (formData == null)
                throw new ArgumentNullException(nameof(formData));
            if (!formData.ContainsKey(OAuthDefaults.OAuthProblem))
            {
                return;
            }
            var oauthProblem = formData[OAuthDefaults.OAuthProblem].ToString();
            if (string.IsNullOrWhiteSpace(oauthProblem))
                return;
            throw oauthProblem switch
            {
                OAuthDefaults.ParameterAbsent => new OAuthException(
                    $"Missing parameters: {formData[OAuthDefaults.OAuthParametersAbsent]}"),
                _ => new OAuthException(string.Join(",", formData)),
            };
        }
    }
}