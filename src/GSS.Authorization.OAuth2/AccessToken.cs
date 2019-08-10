using System;
using Newtonsoft.Json;

namespace GSS.Authorization.OAuth2
{
    public class AccessToken
    {
        public static readonly AccessToken Empty = new AccessToken();

        [JsonProperty("access_token")]
        public string Token { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresInSeconds { get; set; }

        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);
    }
}
