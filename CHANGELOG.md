# ChangeLog

All notable changes to this project will be documented in this file.

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