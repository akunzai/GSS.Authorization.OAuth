# ChangeLog

All notable changes to this project will be documented in this file.

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