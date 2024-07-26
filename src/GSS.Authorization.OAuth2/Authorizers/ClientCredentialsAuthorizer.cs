using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace GSS.Authorization.OAuth2;

public class ClientCredentialsAuthorizer(
    HttpClient client,
    IOptions<AuthorizerOptions> options) : AccessTokenAuthorizerBase(client, options)
{
    protected override void PrepareFormData(IDictionary<string, string> formData)
    {
        if (formData == null)
            throw new ArgumentNullException(nameof(formData));
        formData[AuthorizerDefaults.GrantType] = AuthorizerDefaults.ClientCredentials;
    }
}