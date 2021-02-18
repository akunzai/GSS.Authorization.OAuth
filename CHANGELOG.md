# ChangeLog

All notable changes to this project will be documented in this file.

## 2021-02-20

### GSS.Authorization.OAuth(.HttpClient)? 2.0.0

- Removed dependencies of Microsoft.AspNet.WebApi.Client
- Removed obsolete code

## 2020-12-21

### GSS.Authorization.OAuth 1.3.1

- Fixes compiler warnings

### GSS.Authorization.OAuth2 2.1.0

- Update target from netcoreapp3.0 to netcoreapp3.1 (https://dotnet.microsoft.com/platform/support/policy/dotnet-core)

### GSS.Authorization.OAuth2.HttpClient 2.1.1

- Remove unnecessary logs

## 2020-09-15

### GSS.Authorization.OAuth2.HttpClient 2.1.0

- Handle WWW-Authenticate response error (https://tools.ietf.org/html/rfc6750#section-3)

## 2020-07-27

### GSS.Authorization.OAuth 1.3.0

- Obsolete OAuthEncoder

### GSS.Authorization.OAuth 1.2.0

- Support to customize the percent encoder

### GSS.Authorization.OAuth.HttpClient 1.3.2

- Changed the generic type constraint from RequestSignerBase to IRequestSigner

## 2020-07-26

### GSS.Authorization.OAuth.HttpClient 1.3.1

- Fixed null Request.Content during SignedAsBody

### GSS.Authorization.OAuth.HttpClient 1.3.0

- Support to signed as form body

## 2020-07-16

### GSS.Authorization.OAuth.HttpClient 1.2.1

- Fixed null extended OAuthHttpHandlerOptions

## 2020-07-15

### GSS.Authorization.OAuth.HttpClient 1.2.0

- Support extended OAuthHttpHandlerOptions

## 2020-07-14

### GSS.Authorization.OAuth 1.1.0

- Refactoring AuthorizerBase
- Add InteractiveConsoleAuthorizer

### GSS.Authorization.OAuth.HttpClient 1.1.0

- Add OAuthHttpHandlerOptions.TokenCredentials to simplify configuration

## 2020-07-13

### GSS.Authorization.OAuth(.HttpClient)? 1.0.0

- Initial Release

## 2019-10-30

### GSS.Authorization.OAuth2(.HttpClient)? 2.0.0

- Support .Net Core 3.0
- Replace Newtonsoft.Json by System.Text.Json
- Use nullable reference types

### GSS.Authorization.OAuth2.HttpClient 1.5.1

- Avoid register duplicated OAuth2 Authorizer
- Fixes OAuth2 Authorizer type might not matched as desired

## 2019-08-10

### GSS.Authorization.OAuth2 1.5.0

- Optimize JSON deserializing
- Remove obsolete code

### GSS.Authorization.OAuth2.HttpClient 1.5.0

- Simplify accessToken caching by MemoryCache

## 2019-03-11

### GSS.Authorization.OAuth2.HttpClient 1.4.1

- Force renew accessToken for Unauthorized response

## 2019-02-26

### GSS.Authorization.OAuth2(.HttpClient)? 1.4.0

- Signing assembly with Strong Name

## 2018-12-02

### GSS.Authorization.OAuth2 1.3.0

- Add Authorizer as abstract class of IAuthorizer to inject HttpClient
- Make all authorizers as typed clients
- Obsolete AuthorizerHttpClient

### GSS.Authorization.OAuth2.HttpClient 1.3.0

- Allow each typed clients to use different authorizer

## 2018-12-01

### GSS.Authorization.OAuth2 1.2.0

- Add Required DataAnnotations for AuthorizerOptions

### GSS.Authorization.OAuth2.HttpClient 1.2.0

- Add AddOAuth2HttpClient extension methods for IServiceCollection

## 2018-10-17

### GSS.Authorization.OAuth2 1.1.0

- Add custom error handler
- Change to return null when HTTP Response not successful

### GSS.Authorization.OAuth2.HttpClient 1.1.0

- Fix accessToken cache never expired
- Fix SemaphoreFullException
- Add optimize accessToken caching with ValueTask

## 2018-10-15

### GSS.Authorization.OAuth2(.HttpClient)? 1.0.0

- Initial Release
