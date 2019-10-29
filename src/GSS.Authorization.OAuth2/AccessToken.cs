using System;
using System.Text.Json.Serialization;

namespace GSS.Authorization.OAuth2
{
    public class AccessToken
    {
        public static readonly AccessToken Empty = new AccessToken();

        [JsonPropertyName("access_token")]
        public string Token { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresInSeconds { get; set; }

        [JsonIgnore]
        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);
    }
}
