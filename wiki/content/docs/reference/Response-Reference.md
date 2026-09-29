---
title: SecureFetch.Response Reference
weight: 2
---

The object `Invoke-SecureFetch` writes for each address, and the `TargetObject` of the error records that carry a response. Source: `src/lib.rs` (`Response`, `InvokeSecureFetch::response`, `header_table`, `text_of`).

```powershell
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace | Get-Member -MemberType Property | Select-Object Name, Definition
```

```text
Name              Definition
----              ----------
CipherSuite       string CipherSuite {get;set;}
Content           string Content {get;set;}
ContentBytes      byte[] ContentBytes {get;set;}
FinalUri          string FinalUri {get;set;}
Headers           System.Object Headers {get;set;}
KeyExchange       string KeyExchange {get;set;}
Protocol          string Protocol {get;set;}
Redirects         string[] Redirects {get;set;}
StatusCode        int StatusCode {get;set;}
StatusDescription string StatusDescription {get;set;}
Trailers          System.Object Trailers {get;set;}
Uri               string Uri {get;set;}
```

| Property | Type | Holds |
|---|---|---|
| `Uri` | `string` | the address as given |
| `FinalUri` | `string` | the address the last request was sent to, written out whole: when no redirect was followed, `Uri` as it was sent, with https:// in lower case, no port when it is 443, `/` when no path was given, bytes a request target cannot carry escaped as `%XX`, and no fragment (`https://example.com` is written `https://example.com/`); else the last address redirected to |
| `Redirects` | `string[]` | each address a redirect led to, in the order followed; empty when none was |
| `StatusCode` | `int` | the status code, such as 200 |
| `StatusDescription` | `string` | the reason phrase; empty when the server sent none |
| `Protocol` | `string` | the TLS version of the last connection: `TLSv1_3` or `TLSv1_2` |
| `KeyExchange` | `string` | the key exchange group its handshake agreed, such as `X25519MLKEM768`, `X25519` or `secp256r1` |
| `CipherSuite` | `string` | the cipher suite, such as `TLS13_AES_256_GCM_SHA384` |
| `Headers` | declared `object`, holding an `OrderedDictionary` | one key per field name, matched without regard to case, in the order each name first arrived, each holding a `string[]` of every value sent under it |
| `Trailers` | declared `object`, holding an `OrderedDictionary` | the trailer fields a chunked body ended with, shaped like `Headers`; empty when there were none |
| `Content` | `string` | the body, its content codings undone, decoded by a byte order mark at its start, else by the Content-Type's charset label as the WHATWG Encoding Standard reads it, else as UTF-8; a sequence the encoding cannot read becomes U+FFFD; empty when `-OutFile` took the body |
| `ContentBytes` | `byte[]` | the body's bytes, its content codings undone: the bytes `Content` was decoded from; empty when `-OutFile` took the body |

## An example

```powershell
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace | Select-Object Uri, StatusCode, StatusDescription, Protocol, KeyExchange, CipherSuite
```

```text
Uri               : https://pq.cloudflareresearch.com/cdn-cgi/trace
StatusCode        : 200
StatusDescription : OK
Protocol          : TLSv1_3
KeyExchange       : X25519MLKEM768
CipherSuite       : TLS13_AES_256_GCM_SHA384
```

After redirects:

```powershell
$moved = Invoke-SecureFetch https://httpbin.org/redirect/2
$moved | Format-List Uri, FinalUri, Redirects, StatusCode
```

```text
Uri        : https://httpbin.org/redirect/2
FinalUri   : https://httpbin.org/get
Redirects  : {https://httpbin.org/relative-redirect/1, https://httpbin.org/get}
StatusCode : 200
```

`Headers` and `Trailers`:

```powershell
$r = Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace
$r.Headers.GetType().FullName
$r.Headers['content-type']
$r.Headers.Keys -join ', '
```

```text
System.Collections.Specialized.OrderedDictionary
text/plain
Date, Content-Type, Transfer-Encoding, Connection, If-Modified-Since, Expires, Access-Control-Allow-Origin, Content-Encoding, Server, CF-RAY
```

`Content` and `ContentBytes` are shown in [How To Read Compressed And Encoded Bodies](How-To-Read-Compressed-And-Encoded-Bodies.md); `-OutFile -PassThru`'s empty ones in [How To Download To A File](How-To-Download-To-A-File.md).
