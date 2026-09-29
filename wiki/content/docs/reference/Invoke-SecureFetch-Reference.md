---
title: Invoke-SecureFetch Reference
weight: 1
---

The module's one cmdlet. Source: `src/lib.rs` (`InvokeSecureFetch`, `impl Default for InvokeSecureFetch`, `impl Cmdlet for InvokeSecureFetch`).

## Syntax

```powershell
Get-Command Invoke-SecureFetch -Syntax
```

```text
Invoke-SecureFetch [-Uri] <string> [-Method <string>] [-Headers <IDictionary>] [-Body <Object>] [-ContentType <string>] [-TimeoutSeconds <ulong>] [-SkipHttpErrorCheck] [-RequirePostQuantum] [-KeepAlive] [-NoCompression] [-MaximumDecodedBytes <ulong>] [-MaximumRedirection <int>] [-OutFile <string>] [-PassThru] [-Proxy <string>] [-ProxyCredential <pscredential>] [-NoProxy] [-TrustedRoots <string[]>] [-RootCertificate <X509Certificate2[]>] [<CommonParameters>]
```

Windows PowerShell 5.1 prints `<uint64>` where PowerShell 7 prints `<ulong>`; the types are the same. The cmdlet writes `SecureFetch.Response` objects ([SecureFetch.Response Reference](Response-Reference.md)) and raises the error records in the [Error Reference](Error-Reference.md).

## Parameters

```powershell
(Get-Command Invoke-SecureFetch).Parameters.Values | Where-Object { $_.Name -notin [System.Management.Automation.PSCmdlet]::CommonParameters } | Select-Object Name, @{ n = 'Type'; e = { $_.ParameterType.Name } } | Format-Table -AutoSize
```

```text
Name                Type
----                ----
Uri                 String
Method              String
Headers             IDictionary
Body                Object
ContentType         String
TimeoutSeconds      UInt64
SkipHttpErrorCheck  SwitchParameter
RequirePostQuantum  SwitchParameter
KeepAlive           SwitchParameter
NoCompression       SwitchParameter
MaximumDecodedBytes UInt64
MaximumRedirection  Int32
OutFile             String
PassThru            SwitchParameter
Proxy               String
ProxyCredential     PSCredential
NoProxy             SwitchParameter
TrustedRoots        String[]
RootCertificate     X509Certificate2[]
```

| Parameter | Type | Default | Accepts | Does |
|---|---|---|---|---|
| `-Uri` | `string` | (mandatory) | position 0, and pipeline input | the https:// address to request; the scheme matches without regard to case, the port is 443 when not given, and a fragment is dropped. Another scheme, user information, no host, a host that is neither a DNS name nor an IP address, and a port outside 1 to 65535 are refused before connecting |
| `-Method` | `string` | GET | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, in any case | the request method, sent upper-cased |
| `-Headers` | `IDictionary` | none | a hashtable, an `[ordered]` one, any dictionary; values are strings or arrays of strings | header fields to send, one line per string, after the ones the cmdlet sends: User-Agent `SecureFetch/<version>`, Accept `*/*` and Accept-Encoding. An entry named User-Agent, Accept or Accept-Encoding replaces that field, and an empty array leaves it out. A name must be a token; a value may carry no control byte but tab; Host, Content-Length, Transfer-Encoding, Connection, TE, Trailer, Upgrade, Keep-Alive and Proxy-Connection, which the cmdlet writes itself, cannot be given |
| `-Body` | `Object` | none | a string or a `byte[]` | the request body: a string as UTF-8, bytes as they are, framed by Content-Length |
| `-ContentType` | `string` | text/plain; charset=utf-8 for a string body, application/octet-stream for bytes | any text without control bytes other than tab | the body's Content-Type, sent as given. Giving Content-Type both here and in `-Headers` is refused, and with a string body, which is sent as UTF-8, so is a Content-Type naming another charset |
| `-TimeoutSeconds` | `UInt64` | 30 | 1 to 300 | the bound on name resolution, the connection, and each read or write |
| `-SkipHttpErrorCheck` | switch | off | | writes a 4xx or 5xx response instead of raising `SecureFetchHttpStatus` |
| `-RequirePostQuantum` | switch | off | | offers only TLS 1.3 with X25519MLKEM768, so a server without them is refused as `SecureFetchNotPostQuantum` before anything but the handshake is sent |
| `-KeepAlive` | switch | off | | keeps each connection after its response for the next request to the same host and port, reached through the same proxy or none, whether a redirect or the next piped address; the kept connections close when the invocation ends. When the server has closed a kept connection, a GET, HEAD, OPTIONS, PUT or DELETE is sent once more on a new connection, and a POST or PATCH fails as `SecureFetchConnection` rather than being sent twice |
| `-NoCompression` | switch | off | | asks for the identity encoding alone instead of gzip, deflate, br and zstd |
| `-MaximumDecodedBytes` | `UInt64` | 268435456 (256 MiB) | | the most bytes a body sent with a content coding may decode to; past it, `SecureFetchTooLarge` |
| `-MaximumRedirection` | `Int32` | 5 | 0 to 50 | the most redirects to follow; one more is `SecureFetchTooManyRedirects`, and 0 writes a redirect as the response it is |
| `-OutFile` | `string` | none | a file system path, relative to the current location | writes the body to that file as it arrives, through a temporary file that replaces it once the whole body has arrived; nothing is written to the pipeline |
| `-PassThru` | switch | off | | with `-OutFile`, also writes the response, its `Content` and `ContentBytes` empty; without `-OutFile` the response is written anyway |
| `-Proxy` | `string` | the system's proxy for each address | `http://host[:port]`, port 80 when not given | tunnels each request through that HTTP proxy with CONNECT. An https:// proxy, another scheme, user information, a path, no host, a port outside 1 to 65535, and `-Proxy` given with `-NoProxy` are refused before connecting |
| `-ProxyCredential` | `PSCredential` | none | | the proxy's user name and password, sent as Basic Proxy-Authorization to whichever proxy is used |
| `-NoProxy` | switch | off | | connects directly rather than through the proxy the system names |
| `-TrustedRoots` | `string[]` | Bundled, Windows on Windows; Bundled elsewhere | Bundled, Windows, None, in any case | where the roots a server's certificate must chain to come from: the bundled Mozilla roots, the Windows store, or neither; Windows on a system without a Windows certificate store is refused before any connection |
| `-RootCertificate` | `X509Certificate2[]` | none | certificate objects | roots trusted beside whatever `-TrustedRoots` names |

The method, header fields, body, `-OutFile` path, proxy choice and roots are checked before any connection is made, and a parameter that cannot be used is refused for each record with its own error id.

## Examples

These are the examples the cmdlet's help carries:

```powershell
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace
'https://pq.cloudflareresearch.com/cdn-cgi/trace' | Invoke-SecureFetch -TimeoutSeconds 10 | Select-Object StatusCode, Protocol, KeyExchange, CipherSuite
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/no-such-page -SkipHttpErrorCheck
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace -RequirePostQuantum
Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body '{"name":"value"}' -ContentType 'application/json' -Headers @{ 'X-Example' = '42' }
(Invoke-SecureFetch https://github.com/PowerShell/PowerShell/releases/latest).FinalUri
Invoke-SecureFetch https://speed.cloudflare.com/__down?bytes=1048576 -OutFile .\down.bin -PassThru
```

The how-to pages run each family of parameters with its output: [methods, headers and bodies](How-To-Send-Methods-Headers-And-Bodies.md), [errors](How-To-Handle-Errors.md), [post-quantum TLS](How-To-Require-Post-Quantum-TLS.md), [timeouts and stopping](How-To-Bound-And-Stop-Requests.md), [the pipeline and kept connections](How-To-Pipe-Addresses-And-Keep-Connections.md), [redirects](How-To-Follow-Redirects.md), [files](How-To-Download-To-A-File.md), [proxies](How-To-Use-A-Proxy.md), [roots](How-To-Choose-Trusted-Roots.md), and [compressed and encoded bodies](How-To-Read-Compressed-And-Encoded-Bodies.md).
