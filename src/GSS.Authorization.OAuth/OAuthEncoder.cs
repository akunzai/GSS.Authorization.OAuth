using System;
using System.Collections.Generic;
using System.Text;

namespace GSS.Authorization.OAuth
{
    public static class OAuthEncoder
    {
        private static readonly IDictionary<string, string> _uriRfc3986EscapeChars = new Dictionary<string, string>
        {
            ["!"] = "%21",
            ["*"] = "%2A",
            ["'"] = "%27",
            ["("] = "%28",
            [")"] = "%29",
        };

        /// <summary>
        /// Percent-Encoding, see https://tools.ietf.org/html/rfc3986#section-2.1
        /// </summary>
        /// <returns>The encoded string.</returns>
        /// <param name='value'>The string to encode.</param>
        public static string PercentEncode(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            var escaped = new StringBuilder(Uri.EscapeDataString(value));

            foreach (var escapeChar in _uriRfc3986EscapeChars)
            {
                escaped.Replace(escapeChar.Key, escapeChar.Value);
            }
            return escaped.ToString();
        }
    }
}
