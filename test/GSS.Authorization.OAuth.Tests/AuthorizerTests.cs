using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth.Tests
{
    // see https://tools.ietf.org/html/rfc5849#section-1.2
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
            var authorizer = new FakeAuthorizer(Options.Create(_options), _mockHttp.ToHttpClient(), _signer);

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
            var expected = "hfdp7dh39dks9884";
            var authorizeHtml = $@"<form action='{_options.ResourceOwnerAuthorizeUri}' method='post'>
<input type='text' name='uid'>
<input type='password' name='pwd'>
<button type='submit'>Login</button></form>";
            var temporaryCredentials = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            var authorizeUri = new Uri(QueryHelpers.AddQueryString(_options.ResourceOwnerAuthorizeUri.ToString(), OAuthDefaults.OAuthToken, temporaryCredentials.Key));
            _mockHttp.When(HttpMethod.Get, authorizeUri.ToString())
                .Respond(new StringContent(authorizeHtml, Encoding.UTF8, "text/html"));
            var authorizer = new FakeAuthorizer(Options.Create(_options), _mockHttp.ToHttpClient(), _signer)
            {
                VerificationCode = expected
            };

            // Act
            var actual = await authorizer.GetVerificationCodeAsync(authorizeUri).ConfigureAwait(false);

            // Assert
            Assert.Equal(expected, actual);
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task GetTokenCredentialAsync()
        {
            // Arrange
            var expected = new OAuthCredential("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");
            var verificationCode = "hfdp7dh39dks9884";
            _options.NonceProvider = () => "walatlh";
            _options.TimestampProvider = () => "137131201";
            var temporaryCredential = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            var authorizationHeader = _signer.GetAuthorizationHeader(HttpMethod.Post, _options.TokenRequestUri,
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthVerifier] = verificationCode
                }, temporaryCredential);
            _mockHttp.When(HttpMethod.Post, _options.TokenRequestUri.ToString())
                .WithHeaders("Authorization", authorizationHeader.ToString())
                .Respond(new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    [OAuthDefaults.OAuthToken] = expected.Key,
                    [OAuthDefaults.OAuthTokenSecret] = expected.Secret
                }));
            var authorizer = new FakeAuthorizer(Options.Create(_options), _mockHttp.ToHttpClient(), _signer)
            {
                VerificationCode = verificationCode
            };

            // Act
            var actual = await authorizer.GetTokenCredentialAsync(temporaryCredential, authorizer.VerificationCode).ConfigureAwait(false);

            // Assert
            Assert.Equal(expected.Key, actual.Key);
            Assert.Equal(expected.Secret, actual.Secret);
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task GrantAccessAsync()
        {
            // Arrange
            var expected = new OAuthCredential("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");
            var temporaryCredentials = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
            var verificationCode = "hfdp7dh39dks9884";
            _options.NonceProvider = () => "walatlh";
            _options.TimestampProvider = () => "137131201";
            _mockHttp.When(HttpMethod.Post, _options.TemporaryCredentialRequestUri.ToString())
                .WithHeaders("Authorization", _signer.GetAuthorizationHeader(HttpMethod.Post, _options.TemporaryCredentialRequestUri,
                    _options,
                    new NameValueCollection
                    {
                        [OAuthDefaults.OAuthCallback] = _options.CallBack == null ? OAuthDefaults.OutOfBand : _options.CallBack.AbsoluteUri
                    }).ToString())
                .Respond(new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    [OAuthDefaults.OAuthToken] = temporaryCredentials.Key,
                    [OAuthDefaults.OAuthTokenSecret] = temporaryCredentials.Secret,
                    ["oauth_callback_confirmed"] = "true"
                }));
            var header = _signer.GetAuthorizationHeader(HttpMethod.Post, _options.TokenRequestUri,
                _options,
                new NameValueCollection
                {
                    [OAuthDefaults.OAuthVerifier] = verificationCode
                }, temporaryCredentials);
            _mockHttp.When(HttpMethod.Post, _options.TokenRequestUri.ToString())
                .WithHeaders("Authorization", header.ToString())
                .Respond(new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    [OAuthDefaults.OAuthToken] = expected.Key,
                    [OAuthDefaults.OAuthTokenSecret] = expected.Secret
                }));
            var authorizer = new FakeAuthorizer(Options.Create(_options), _mockHttp.ToHttpClient(), _signer)
            {
                VerificationCode = verificationCode
            };

            // Act
            var actual = await authorizer.GrantAccessAsync().ConfigureAwait(false);

            // Assert
            Assert.Equal(expected.Key, actual.Key);
            Assert.Equal(expected.Secret, actual.Secret);
            _mockHttp.VerifyNoOutstandingRequest();
        }
    }
}
