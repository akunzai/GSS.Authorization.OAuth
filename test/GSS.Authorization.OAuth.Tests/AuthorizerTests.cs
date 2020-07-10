using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Primitives;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth.Tests
{
    public class AuthorizerTests
    {
        private readonly AuthorizerOptions _options = new AuthorizerOptions
        {
            ClientCredentials = new OAuthCredential("dpf43f3p2l4k3l03", "kd94hf93k423kf44"),
            TemporaryCredentialRequestUri = new Uri("https://photos.example.net/initiate"),
            ResourceOwnerAuthorizeUri = new Uri("https://photos.example.net/authorize"),
            TokenRequestUri = new Uri("https://photos.example.net/token"),
            CallBack = new Uri("http://printer.example.com/ready"),
            Realm = "Photos",
            ProvideVersion = false
        };
        private readonly MockHttpMessageHandler _mockHttp = new MockHttpMessageHandler();
        private readonly IRequestSigner _signer = new HmacSha1RequestSigner();

        [Fact]
        public async Task GetTemporaryCredentialAsync()
        {
            // Arrange
            var expected = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            _options.NonceProvider = () => "wIjqoS";
            _options.TimestampProvider = () => "137131200";
            var authorizer = new FakeAuthorizer(_options, _mockHttp.ToHttpClient(), _signer);
            var authorizationHeader = _signer.GetAuthorizationHeader(HttpMethod.Post, _options.TemporaryCredentialRequestUri,
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthCallback] = _options.CallBack == null ? OAuthDefaults.OutOfBand : _options.CallBack.AbsoluteUri
                });
            _mockHttp.When(HttpMethod.Post, _options.TemporaryCredentialRequestUri.ToString())
                .WithHeaders("Authorization", authorizationHeader.ToString())
                .Respond(new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    [OAuthDefaults.OAuthToken] = expected.Key,
                    [OAuthDefaults.OAuthTokenSecret] = expected.Secret,
                    ["oauth_callback_confirmed"] = "true"
                }));

            // Act
            var actual = await authorizer.GetTemporaryCredentialAsync().ConfigureAwait(false);

            // Assert
            Assert.Equal(expected.Key, actual.Key);
            Assert.Equal(expected.Secret, actual.Secret);
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task GetVerificationCodeAsync()
        {
            // Arrange
            var authorizeHtml = $@"<form action='{_options.ResourceOwnerAuthorizeUri}' method='post'>
<input type='text' name='uid'>
<input type='password' name='pwd'>
<button type='submit'>Login</button></form>";
            var temporaryCredential = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            var mockHttp = new MockHttpMessageHandler();
            var authorizer = new FakeAuthorizer(_options, mockHttp.ToHttpClient(), _signer)
            {
                VerificationCode = "hfdp7dh39dks9884"
            };
            mockHttp.When(HttpMethod.Get, _options.ResourceOwnerAuthorizeUri.ToString())
                .WithQueryString(OAuthDefaults.OAuthToken, temporaryCredential.Key)
                .Respond(new StringContent(authorizeHtml, Encoding.UTF8, "text/html"));

            // Act
            var actual = await authorizer.GetVerificationCodeAsync(temporaryCredential).ConfigureAwait(false);

            // Assert
            Assert.Equal(authorizer.VerificationCode, actual);
            Assert.Equal(authorizeHtml, authorizer.AuthorizeHtml);
            mockHttp.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task GetTokenCredentialAsync()
        {
            // Arrange
            var expected = new OAuthCredential("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");
            _options.NonceProvider = () => "walatlh";
            _options.TimestampProvider = () => "137131201";
            var temporaryCredential = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            var mockHttp = new MockHttpMessageHandler();
            var authorizer = new FakeAuthorizer(_options, mockHttp.ToHttpClient(), _signer)
            {
                VerificationCode = "hfdp7dh39dks9884"
            };
            var authorizationHeader = _signer.GetAuthorizationHeader(HttpMethod.Post, _options.TokenRequestUri,
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthVerifier] = authorizer.VerificationCode
                }, temporaryCredential);
            mockHttp.When(HttpMethod.Post, _options.TokenRequestUri.ToString())
                .WithHeaders("Authorization", authorizationHeader.ToString())
                .Respond(new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    [OAuthDefaults.OAuthToken] = expected.Key,
                    [OAuthDefaults.OAuthTokenSecret] = expected.Secret
                }));

            // Act
            var actual = await authorizer.GetTokenCredentialAsync(temporaryCredential, authorizer.VerificationCode).ConfigureAwait(false);

            // Assert
            Assert.Equal(expected.Key, actual.Key);
            Assert.Equal(expected.Secret, actual.Secret);
            mockHttp.VerifyNoOutstandingRequest();
        }
    }
}
