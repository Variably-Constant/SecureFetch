---
title: How To Follow Redirects
weight: 6
---

A 301, 302, 303, 307 or 308 response with a Location is followed, to https:// addresses only, up to `-MaximumRedirection` redirects. Source: `src/lib.rs` (`process`, `redirect_location`, `redirected_target`, `resolve_reference`, `Outgoing::redirected`).

## Where the response came from

```powershell
$latest = Invoke-SecureFetch https://github.com/PowerShell/PowerShell/releases/latest
$latest.FinalUri
$latest.Redirects
$moved = Invoke-SecureFetch https://httpbin.org/redirect/2
$moved | Format-List Uri, FinalUri, Redirects, StatusCode
```

```text
https://github.com/PowerShell/PowerShell/releases/tag/v7.6.6
https://github.com/PowerShell/PowerShell/releases/tag/v7.6.6

Uri        : https://httpbin.org/redirect/2
FinalUri   : https://httpbin.org/get
Redirects  : {https://httpbin.org/relative-redirect/1, https://httpbin.org/get}
StatusCode : 200
```

`Uri` stays the address given; `FinalUri` is the address the last request went to, written out whole; `Redirects` holds each address followed, in order. A relative Location resolves against the address that answered, as RFC 3986 resolves a reference. `Protocol`, `KeyExchange` and `CipherSuite` describe the last connection.

## The limit, and what is refused

`-MaximumRedirection` takes 0 to 50, and 5 when not given. One more redirect than it allows is `SecureFetchTooManyRedirects` (LimitsExceeded); 0 writes a redirect as the response it is. A redirect to an address that is not https:// is never followed: `SecureFetchRedirectNotHttps` (SecurityError). Each error record's `TargetObject` is the redirect response.

```powershell
Invoke-SecureFetch https://httpbin.org/redirect/3 -MaximumRedirection 1 -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
(Invoke-SecureFetch https://httpbin.org/redirect/3 -MaximumRedirection 0).StatusCode
Invoke-SecureFetch 'https://httpbin.org/redirect-to?url=http://example.com/' -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
```

```text
SecureFetchTooManyRedirects,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
https://httpbin.org/redirect/3 kept redirecting past -MaximumRedirection 1: after 1 redirect, a 302 from https://httpbin.org/relative-redirect/2 led to /relative-redirect/1
302
SecureFetchRedirectNotHttps,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
https://httpbin.org/redirect-to?url=http://example.com/ redirected to http://example.com/, which is not an https:// address, so it is not followed
```

An https:// Location that cannot be sent, such as one with no host, a bad port or user information, is the server's fault: `SecureFetchBadResponse` (ProtocolError), naming the Location, with the redirect response as its `TargetObject`. So are Location fields that disagree, though that record carries no response.

```powershell
Invoke-SecureFetch 'https://httpbin.org/redirect-to?url=https%3A%2F%2Fuser%40example.com%2F' -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
$failed[0].TargetObject.StatusCode
```

```text
SecureFetchBadResponse,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
the response from httpbin.org redirected to https://user@example.com/, which cannot be sent: https://***@example.com/ carries user information, which this cmdlet does not send
302
```

A 300, a 304, and a redirect without a Location are written as the responses they are.

## What the next request carries

- A 303, and a 301 or 302 answering a POST, is followed with a GET (a HEAD stays a HEAD) without the body, its Content-Type, or the `-Headers` fields that describe content (Content-Type, Content-Encoding, Content-Language, Content-Location). A 307 or 308 keeps the method and the body. Here httpbin.org answered a POST with a 303 to postman-echo.com/get, which saw a GET with no body, and with a 307 to postman-echo.com/post, which echoed the body sent again:

  ```powershell
  $seeOther = Invoke-SecureFetch 'https://httpbin.org/redirect-to?url=https://postman-echo.com/get&status_code=303' -Method POST -Body 'SecureFetch test'
  $seeOther.FinalUri
  ($seeOther.Content | ConvertFrom-Json).headers.PSObject.Properties.Name -contains 'content-length'
  $temporary = Invoke-SecureFetch 'https://httpbin.org/redirect-to?url=https://postman-echo.com/post&status_code=307' -Method POST -Body 'SecureFetch test'
  $temporary.FinalUri
  ($temporary.Content | ConvertFrom-Json).data
  ```

  ```text
  https://postman-echo.com/get
  False
  https://postman-echo.com/post
  SecureFetch test
  ```

- When a redirect leads to another host or port, Authorization and Cookie fields from `-Headers` are not sent on. In an end-to-end run, synthetic ones were echoed back after a redirect that stayed on postman-echo.com, and after a redirect to httpbin.org its echo of the fields it received listed Accept, Accept-Encoding, Host, User-Agent and X-Amzn-Trace-Id, with no Authorization or Cookie.
- Each hop asks the system proxy afresh, and under `-KeepAlive` reuses a kept connection to its host.
