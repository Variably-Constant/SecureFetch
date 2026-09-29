---
title: How To Pipe Addresses And Keep Connections
weight: 5
---

`-Uri` takes one address by position or many from the pipeline, and each is requested on its own, redirects included. Source: `src/lib.rs` (`process`, `take_idle`, `exchange`, `persistent`).

## Many addresses

```powershell
'https://pq.cloudflareresearch.com/cdn-cgi/trace', 'https://www.debian.org/' | Invoke-SecureFetch | Format-Table Uri, StatusCode, Protocol, KeyExchange -AutoSize
```

```text
Uri                                             StatusCode Protocol KeyExchange
---                                             ---------- -------- -----------
https://pq.cloudflareresearch.com/cdn-cgi/trace        200 TLSv1_3  X25519MLKEM768
https://www.debian.org/                                200 TLSv1_3  X25519
```

The method, header fields, body and roots are read and checked on the first record and used for every one after it.

## One connection for many requests

Each request asks the server to close its connection (`Connection: close`) and the module closes it too. `-KeepAlive` keeps each connection after its response, when HTTP/1.1 framing and the server allow it, and reuses it for the next request to the same host and port through the same proxy, whether that is a redirect or the next piped address:

```powershell
$uris = 1..5 | ForEach-Object { 'https://pq.cloudflareresearch.com/cdn-cgi/trace' }
'without -KeepAlive: ' + [int](Measure-Command { $uris | Invoke-SecureFetch | Out-Null }).TotalMilliseconds + ' ms'
'with -KeepAlive:    ' + [int](Measure-Command { $uris | Invoke-SecureFetch -KeepAlive | Out-Null }).TotalMilliseconds + ' ms'
```

```text
without -KeepAlive: 428 ms
with -KeepAlive:    148 ms
```

(Windows PowerShell: 457 and 153 ms.)

Kept connections close when the invocation ends. When the server has closed a kept connection while it sat idle, a GET, HEAD, OPTIONS, PUT or DELETE is sent once more on a new connection. A POST or PATCH is not sent twice, since repeating it may not be safe, and fails as `SecureFetchConnection`: in an end-to-end run, a POST after postman-echo.com closed a kept connection, seen closed after 399 idle seconds, failed that way, and no new connection was opened, while a HEAD after lwn.net closed one, seen closed after 6 idle seconds, was answered on a new connection.
