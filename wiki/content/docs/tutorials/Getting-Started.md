---
title: Getting Started
weight: 1
---

From installing the module to a first response, in PowerShell 7 or Windows PowerShell 5.1. Source: `src/lib.rs`, and the module manifest cargo-pwrs writes from `Cargo.toml`.

## What it runs on

- Windows PowerShell 5.1, or PowerShell 7.4 or later. On an earlier PowerShell 7 the import stops with a message saying the module needs 7.4 or later.
- Windows x64, Linux x64 with glibc 2.28 or newer, macOS on arm64 and FreeBSD x64: the module carries a native library for each. On any other platform the import fails with a message naming the library and the platform it looked for.
- Nothing else: the TLS stack, its Mozilla roots and the decoders are compiled into the module, and on Windows so is the C runtime, so no Visual C++ Redistributable is needed.

## Install

From the PowerShell Gallery, for the current user:

```powershell
Install-Module SecureFetch -Scope CurrentUser
```

PowerShell 7.4 and later also take `Install-PSResource SecureFetch`. The first install from the Gallery on a machine can ask whether to trust the PowerShell Gallery and, in Windows PowerShell, whether to install the NuGet provider first; both are needed to install from it.

PowerShell loads the module the first time `Invoke-SecureFetch` runs; `Import-Module SecureFetch` loads it at once. To build the module yourself instead, see [Building From Source](Building-From-Source.md).

## A first request

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

`KeyExchange` is the group the handshake agreed. Cloudflare's trace page reports what its own side saw, so the same fact shows from both ends:

```powershell
$r = Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace
$r.Content -split "`n" | Select-String '^(http|tls|kex)='
```

```text
http=http/1.1
tls=TLSv1.3
kex=X25519MLKEM768
```

## What came back

The object is a `SecureFetch.Response`. `Headers` is an ordered dictionary whose keys ignore case, each holding a string array:

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

`Content` is the body as text and `ContentBytes` its bytes; the [SecureFetch.Response Reference](Response-Reference.md) lists every property with its type.

## Help at the prompt

The module carries the cmdlet's help, written from the same source as the [Invoke-SecureFetch Reference](Invoke-SecureFetch-Reference.md):

```powershell
(Get-Help Invoke-SecureFetch).Synopsis
(Get-Help Invoke-SecureFetch -Parameter KeepAlive).description.Text
```

```text
Sends a request to an https:// address with TLS from rustls inside the module and writes the response with what the handshake negotiated.
Keeps each connection open after its response and reuses it for the next request to the same host and port through the same proxy, whether a redirect or the next piped address. When the server has closed the kept connection, a GET, HEAD, OPTIONS, PUT or DELETE is sent once more on a new connection, and a POST or PATCH fails as SecureFetchConnection rather than being sent twice.
```

## Next

- Send something other than a GET: [How To Send Methods, Headers And Bodies](How-To-Send-Methods-Headers-And-Bodies.md).
- Handle what fails: [How To Handle Errors](How-To-Handle-Errors.md).
- Insist on the post-quantum key exchange: [How To Require Post-Quantum TLS](How-To-Require-Post-Quantum-TLS.md).
- Save a download to a file: [How To Download To A File](How-To-Download-To-A-File.md).
