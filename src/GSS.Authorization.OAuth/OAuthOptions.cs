using System;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Cryptography;

namespace GSS.Authorization.OAuth;

public class OAuthOptions
{
    private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();

    [Required]
    public OAuthCredential ClientCredentials { get; set; }

    [Required]
    public Func<string> NonceProvider { get; set; } = () =>
    {
        // Hexadecimal rather than Base64: oauthlib, which backs a large share of OAuth 1.0
        // servers, rejects a nonce containing anything but letters and digits, and accepts
        // only 20 to 30 of them. Base64 fails on '+', '/' and '='.
        var bytes = new byte[12];
        _randomNumberGenerator.GetNonZeroBytes(bytes);
        return BitConverter.ToString(bytes).Replace("-", string.Empty);
    };

    [Required]
    public Func<string> TimestampProvider { get; set; } = () =>
        DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Provides the version of the authentication process as defined in this specification. see https://www.rfc-editor.org/rfc/rfc5849#section-3.1
    /// </summary>
    public bool ProvideVersion { get; set; }

    /// <summary>
    /// The realm parameter defines a protection realm per (https://www.rfc-editor.org/rfc/rfc2617). see https://www.rfc-editor.org/rfc/rfc5849#section-3.5.1
    /// </summary>
    public string? Realm { get; set; }

    /// <summary>
    /// The Percent-Encoder, see https://www.rfc-editor.org/rfc/rfc3986#section-2.1
    /// by default, the <see cref="Uri.EscapeDataString(string)"/> is RFC3986 compliant.
    /// </summary>
    public Func<string, string> PercentEncoder { get; set; } = Uri.EscapeDataString;
}