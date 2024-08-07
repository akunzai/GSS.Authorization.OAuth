using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace GSS.Authorization.OAuth;

[DebuggerDisplay("Key = {Key}")]
public readonly struct OAuthCredential(string key, string secret) : IEquatable<OAuthCredential>
{
    public string Key { get; } = key;

    public string Secret { get; } = secret;

    public override bool Equals(object? obj)
    {
        return obj is OAuthCredential token && Equals(token);
    }

    public bool Equals(OAuthCredential other)
    {
        return Key == other.Key &&
               Secret == other.Secret;
    }

    public override int GetHashCode()
    {
        var hashCode = -1923984941;
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Key);
        hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Secret);
        return hashCode;
    }

    public static bool operator ==(OAuthCredential left, OAuthCredential right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(OAuthCredential left, OAuthCredential right)
    {
        return !(left == right);
    }
}