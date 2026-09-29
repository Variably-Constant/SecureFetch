---
title: How To Use A Proxy
weight: 8
---

Through an HTTP proxy the module sends CONNECT and runs its own TLS inside the tunnel, so the key exchange is still between the module and the server. Source: `src/lib.rs` (`InvokeSecureFetch::proxy_for`, `ProxyAddress`, `system_proxy`, `tunnel`).

## -Proxy and -ProxyCredential

Here a test proxy on 127.0.0.1:3128 asked for Basic credentials; `$credential` is a `PSCredential` holding them:

```powershell
$viaProxy = Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace -Proxy http://127.0.0.1:3128 -ProxyCredential $credential
$viaProxy.KeyExchange
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace -Proxy http://127.0.0.1:3128 -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].CategoryInfo.Category
$failed[0].Exception.Message
```

```text
X25519MLKEM768
SecureFetchProxy,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
AuthenticationError
the proxy http://127.0.0.1:3128 asks for credentials (407 Proxy Authentication Required); give them with -ProxyCredential
```

- `-Proxy` is an `http://host:port` address; the port is 80 when not given. An https:// proxy, another scheme, user information or a path in the address, no host, a port outside 1 to 65535, or `-Proxy` together with `-NoProxy`, is refused before any connection as `SecureFetchProxy` (InvalidArgument).
- `-ProxyCredential` is sent as Basic `Proxy-Authorization`. A proxy that needs NTLM or Negotiate cannot be used.
- The proxy's host name is resolved on this machine; the server's name goes to the proxy in the CONNECT line, and the proxy resolves it.
- A proxy that cannot be reached, answers CONNECT with anything but 2xx, or sends bytes after its 2xx answer is `SecureFetchProxy` (ConnectionError); a 407 is `SecureFetchProxy` (AuthenticationError).
- Under `-KeepAlive` a kept connection is reused only through the same proxy; each redirect is its own CONNECT unless it is.

## The system proxy

Without `-Proxy`, each request, redirects included, asks .NET which proxy the system names for its address, the way the host's own web cmdlets ask:

- PowerShell 7: `[System.Net.Http.HttpClient]::DefaultProxy`, which reads the `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` variables and, when they are not set, the user's proxy settings on Windows and the system's on macOS; on Linux the variables alone.
- Windows PowerShell 5.1: `[System.Net.WebRequest]::GetSystemWebProxy()`, which reads the Windows settings.

`-NoProxy` goes direct. `-ProxyCredential` goes to whichever proxy is used. On a Windows 11 Pro 10.0.26200 machine with no proxy configured, child processes run with `HTTPS_PROXY` naming the test proxy showed the difference: in PowerShell 7 the request went through the proxy, and not with `-NoProxy` or with `NO_PROXY` naming the host; in Windows PowerShell it went direct in all three, since 5.1's system proxy comes from the Windows settings alone.
