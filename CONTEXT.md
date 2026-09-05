# GSS.Authorization.OAuth

OAuth 1.0 and OAuth 2.0 authorized `HttpClient`s. The library's job is to attach the right
credential to an outgoing request, and to obtain that credential when it does not have one.

## Language

### Identity

**Client name**:
The identity a single set of OAuth configuration belongs to. Every client name has its own
options, its own request signer or authorizer, and its own credential. It is the same name
`HttpClientFactory` registers the `HttpClient` under, whether that name was given explicitly or
derived from a typed client.
_Avoid_: instance, registration, profile

### OAuth 1.0

**Client Credentials**:
The key and secret identifying the calling application to the service provider.
_Avoid_: consumer credentials, app credentials, API key

**Temporary Credentials**:
The short-lived key and secret obtained before the resource owner authorizes access.
_Avoid_: request token

**Token Credentials**:
The key and secret representing an authorized resource owner, used to sign resource requests.
_Avoid_: access token (that term belongs to OAuth 2.0)

**Verification Code**:
The value the resource owner returns after authorizing, exchanged for Token Credentials.
_Avoid_: verifier, PIN, auth code

**Request Signer**:
The module that turns a request plus a set of credentials into a signature, per a named
signature method such as HMAC-SHA1 or PLAINTEXT.
_Avoid_: signature provider, hasher

### OAuth 2.0

**Access Token**:
The bearer credential a client presents to a protected resource.
_Avoid_: token credentials (that term belongs to OAuth 1.0), bearer

**Authorizer**:
The module that obtains an Access Token from the authorization server under one grant flow.
_Avoid_: token provider, token client, credential fetcher

**Grant Flow**:
The exchange by which an Authorizer obtains an Access Token, such as Client Credentials or
Resource Owner Credentials.
_Avoid_: grant type (that is the wire parameter), flow strategy

### Shared

**Access Token Endpoint**:
The authorization server address an Authorizer posts to in order to obtain an Access Token.
_Avoid_: token URL, auth endpoint
