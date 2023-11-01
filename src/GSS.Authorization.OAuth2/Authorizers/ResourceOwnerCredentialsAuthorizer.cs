using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace GSS.Authorization.OAuth2;

public class ResourceOwnerCredentialsAuthorizer : AccessTokenAuthorizerBase
{
    public ResourceOwnerCredentialsAuthorizer(
        HttpClient client,
        IOptions<AuthorizerOptions> options)
        : base(client, options)
    {
#pragma warning disable CA2208 // Instantiate argument exceptions correctly
        if (options.Value.Credentials == null)
        {
            throw new ArgumentNullException(nameof(options.Value.Credentials));
        }
        if (string.IsNullOrWhiteSpace(options.Value.Credentials.UserName))
        {
            throw new ArgumentNullException(nameof(options.Value.Credentials.UserName));
        }

        if (string.IsNullOrWhiteSpace(options.Value.Credentials.Password))
        {
            throw new ArgumentNullException(nameof(options.Value.Credentials.Password));
        }
#pragma warning restore CA2208 // Instantiate argument exceptions correctly
    }

    protected override void PrepareFormData(IDictionary<string, string> formData)
    {
        if (formData == null)
            throw new ArgumentNullException(nameof(formData));
        formData[AuthorizerDefaults.GrantType] = AuthorizerDefaults.Password;
        if (Options.Credentials == null)
        {
#pragma warning disable CA2208 // Instantiate argument exceptions correctly
            throw new ArgumentNullException(nameof(Options.Credentials));
#pragma warning restore CA2208 // Instantiate argument exceptions correctly
        }

        formData[AuthorizerDefaults.Username] = Options.Credentials.UserName;
        formData[AuthorizerDefaults.Password] = Options.Credentials.Password;
    }
}