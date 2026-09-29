---
title: Why A Module Of Its Own
weight: 1
---

PowerShell's web cmdlets get TLS from .NET, which on Windows hands it to SChannel, the Windows TLS stack: [.NET Framework](https://learn.microsoft.com/dotnet/framework/network-programming/tls) under Windows PowerShell 5.1 and [.NET](https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting) under PowerShell 7. Microsoft documents SChannel's TLS 1.3 as starting with [Windows 11 and Windows Server 2022](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-), and its [ML-KEM groups](https://learn.microsoft.com/windows/win32/secauthn/tls-supported-groups-in-windows-11-24h2-and-later) as available only in Insider Preview builds, disabled by default.

On Windows 11 Pro 10.0.26200, asked for Cloudflare's trace page, the host's own `Invoke-WebRequest` got TLS 1.3 with the classical X25519 in both hosts:

```powershell
(Invoke-WebRequest https://pq.cloudflareresearch.com/cdn-cgi/trace -UseBasicParsing).Content -split "`n" | Select-String '^(http|tls|kex)='
```

```text
http=http/1.1
tls=TLSv1.3
kex=X25519
```

`Invoke-SecureFetch`, asked for the same page, got X25519MLKEM768:

```text
http=http/1.1
tls=TLSv1.3
kex=X25519MLKEM768
```

## What the module carries

The TLS stack is [rustls](https://github.com/rustls/rustls) 0.23 over its aws-lc-rs provider, compiled into the module's native library. Its default key exchange groups put the X25519MLKEM768 hybrid first, then X25519, secp256r1 and secp384r1, with TLS 1.3 and 1.2 enabled; `-RequirePostQuantum` narrows that to TLS 1.3 and X25519MLKEM768 alone. The HTTP/1.1 client, content decoding and charset decoding are the module's own too.

`dumpbin /dependents` of the native library, built on Windows 11 Pro 10.0.26200, lists no Windows TLS library. Built with the C runtime linked in by `.cargo/config.toml`, its imports are `KERNEL32.dll` (listed a second time as `kernel32.dll`), `ntdll.dll`, `WS2_32.dll`, `bcryptprimitives.dll`, `api-ms-win-core-synch-l1-2-0.dll` and `crypt32.dll`, the last only to read the Windows certificate store; there is no `VCRUNTIME140.dll` and no `api-ms-win-crt-*` set.

## What it leaves alone

It secures only the connections it makes. `Invoke-WebRequest`, `Invoke-RestMethod` and every other module keep the host's TLS stack, unchanged, in the same session.
