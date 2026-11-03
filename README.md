<div align="center">

# SecureFetch

**HTTPS from PowerShell over TLS 1.3 with the X25519MLKEM768 post-quantum hybrid key exchange, from rustls inside the module.**

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/SecureFetch?style=flat-square)](https://www.powershellgallery.com/packages/SecureFetch)
[![Wiki](https://img.shields.io/github/actions/workflow/status/Variably-Constant/SecureFetch/wiki-deploy.yml?branch=main&label=wiki&style=flat-square)](https://variably-constant.github.io/SecureFetch/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.4%2B%20%7C%205.1-5391FE.svg?style=flat-square)](https://learn.microsoft.com/powershell/)

**[Wiki](https://variably-constant.github.io/SecureFetch/)** | [Getting started](https://variably-constant.github.io/SecureFetch/docs/tutorials/getting-started/) | [Reference](https://variably-constant.github.io/SecureFetch/docs/reference/invoke-securefetch-reference/) | [Changelog](https://github.com/Variably-Constant/SecureFetch/blob/main/CHANGELOG.md)

`Invoke-SecureFetch` makes HTTPS requests with its own TLS stack, [rustls](https://github.com/rustls/rustls), inside the module, and every response names the key exchange its handshake agreed. On Windows, neither PowerShell nor .NET offers X25519MLKEM768 by default: both get TLS from SChannel, whose ML-KEM support is Insider Preview only. SecureFetch runs in Windows PowerShell 5.1 and PowerShell 7.4 or later, and is built with [PoWerRuSt](https://github.com/Variably-Constant/PWRS).

</div>

---

<details>
<summary><b>Table of contents</b></summary>

- [Features](#features)
- [Quick start](#quick-start)
- [Why SecureFetch](#why-securefetch)
- [What it can do](#what-it-can-do)
- [Tested platforms](#tested-platforms)
- [Limitations](#limitations)
- [Building from source](#building-from-source)
- [Repository layout](#repository-layout)
- [Supported platforms](#supported-platforms)
- [Wiki](#wiki)
- [Credits and influences](#credits-and-influences)
- [Use of AI tools](#use-of-ai-tools)
- [License](#license)
- [Contributing](#contributing)

</details>

---

## Features

- One cmdlet, `Invoke-SecureFetch`, writes a [`SecureFetch.Response`](https://variably-constant.github.io/SecureFetch/docs/reference/response-reference/) for each https:// address, with the protocol version, key exchange and cipher suite its handshake agreed.
- TLS from rustls over aws-lc-rs, which offers X25519MLKEM768 first; [`-RequirePostQuantum`](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-require-post-quantum-tls/) refuses a server that cannot agree it, before the request is sent.
- Certificates verified against the bundled Mozilla roots and, on Windows, the Windows store, or [a choice of roots](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-choose-trusted-roots/).
- [Methods, headers and bodies](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-send-methods-headers-and-bodies/): GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS.
- [Redirects](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-follow-redirects/), to https:// addresses only, up to a limit.
- [Downloads to a file](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-download-to-a-file/) as the body arrives, replacing the file only once the body is whole.
- [HTTP proxies](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-use-a-proxy/) through CONNECT, the system's by default, with TLS end to end; `-ProxyCredential` takes a credential, or a user name and prompts for the password.
- [gzip, deflate, br and zstd bodies](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-read-compressed-and-encoded-bodies/) decoded within a bound, and text decoded by its charset.
- [Kept connections](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-pipe-addresses-and-reuse-connections/) for the next request to the same host and port, piped or redirected.
- [An error record](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-handle-errors/) with its own id for each way a request fails; a 4xx or 5xx carries the response.
- [A stop ends a request at once](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-set-timeouts-and-stop-requests/), and `-TimeoutSeconds` bounds every wait.
- `Invoke-WebRequest` and every other module go on using the host's TLS stack.
- `Get-Help Invoke-SecureFetch -Online` opens the cmdlet's reference page in the wiki.

## Quick start

```powershell
Install-Module SecureFetch -Scope CurrentUser
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

The module runs on Windows x64, Linux x64, macOS on arm64 and FreeBSD x64, and needs nothing else installed: the TLS stack, its roots and the decoders are compiled into it, and on Windows so is the C runtime. The wiki's [Getting Started](https://variably-constant.github.io/SecureFetch/docs/tutorials/getting-started/) goes on from here.

## Why SecureFetch

PowerShell's web cmdlets get TLS from .NET, which on Windows hands it to SChannel, the Windows TLS stack: [.NET Framework](https://learn.microsoft.com/dotnet/framework/network-programming/tls) under Windows PowerShell 5.1 and [.NET](https://learn.microsoft.com/dotnet/core/extensions/sslstream-troubleshooting) under PowerShell 7. Microsoft documents SChannel's TLS 1.3 as starting with [Windows 11 and Windows Server 2022](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-), and its [ML-KEM groups](https://learn.microsoft.com/windows/win32/secauthn/tls-supported-groups-in-windows-11-24h2-and-later) as available only in Insider Preview builds, disabled by default. On Windows 11 Pro 10.0.26200, asked for Cloudflare's trace page, the host's own `Invoke-WebRequest` got TLS 1.3 with the classical X25519 in both hosts, where `Invoke-SecureFetch` got X25519MLKEM768:

```powershell
(Invoke-WebRequest https://pq.cloudflareresearch.com/cdn-cgi/trace -UseBasicParsing).Content -split "`n" | Select-String '^(http|tls|kex)='
(Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace).Content -split "`n" | Select-String '^(http|tls|kex)='
```

```text
http=http/1.1
tls=TLSv1.3
kex=X25519
http=http/1.1
tls=TLSv1.3
kex=X25519MLKEM768
```

SecureFetch has its own TLS stack. `dumpbin /dependents` of the module's native library, built on Windows 11 Pro 10.0.26200, lists no Windows TLS library: its imports are `KERNEL32.dll` (listed a second time as `kernel32.dll`), `ntdll.dll`, `WS2_32.dll`, `bcryptprimitives.dll`, `api-ms-win-core-synch-l1-2-0.dll` and `crypt32.dll`, the last to read the Windows certificate store, with no `VCRUNTIME140.dll` and no `api-ms-win-crt-*` set. The wiki's [Why SecureFetch](https://variably-constant.github.io/SecureFetch/docs/explanation/why-securefetch/) says more.

## What it can do

Each line below is a task the wiki's how-to pages run with its output.

```powershell
# A method, header fields and a body; postman-echo.com echoes what it received.
$sent = Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body 'SecureFetch test' -Headers @{ 'X-Example' = '42' }
($sent.Content | ConvertFrom-Json).data

# Redirects, and where the response came from.
(Invoke-SecureFetch https://github.com/PowerShell/PowerShell/releases/latest).FinalUri

# A download straight to a file.
Invoke-SecureFetch https://raw.githubusercontent.com/PowerShell/PowerShell/v7.4.0/assets/Powershell_256.png -OutFile .\Powershell_256.png
(Get-FileHash .\Powershell_256.png -Algorithm SHA256).Hash

# Only TLS 1.3 with X25519MLKEM768, or no request at all.
Invoke-SecureFetch https://www.debian.org/ -RequirePostQuantum -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
```

```text
SecureFetch test
https://github.com/PowerShell/PowerShell/releases/tag/v7.6.9
1734E52435CF6CDDDEF2B340039986A8487FDD1CEAED44D1B93B39293E4A9DD4
SecureFetchNotPostQuantum,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
```

Each feature above links its how-to page. Every parameter, every property of `SecureFetch.Response` with its type, and every error id are in the wiki's reference: [Invoke-SecureFetch](https://variably-constant.github.io/SecureFetch/docs/reference/invoke-securefetch-reference/), [SecureFetch.Response](https://variably-constant.github.io/SecureFetch/docs/reference/response-reference/), [Errors](https://variably-constant.github.io/SecureFetch/docs/reference/error-reference/).

## Tested platforms

Built from this repository's committed files with PoWerRuSt 1.0.0, cargo-pwrs 1.0.0, Rust 1.98.1 and Pester 6.2.0. Windows 11, AlmaLinux and FreeBSD built the module, clippy clean, and passed its Rust unit tests. Windows 10 ran the Windows 11 build and Ubuntu the AlmaLinux build; Windows Server 2019 installed the package with `Install-Module` from a local repository. Neither Windows 10 nor Server 2019 had the Visual C++ Redistributable.

| Platform | Hosts | Pester tests passed |
|---|---|---|
| Windows 11 Pro 10.0.26200, x64 | PowerShell 7.6.9, 7.5.11 and 7.4.20, Windows PowerShell 5.1.26100.9711 | 69 in each host |
| Windows 10 Pro 22H2, x64 | PowerShell 7.6.6, Windows PowerShell 5.1.19041.6456 | 69 in each host |
| Windows Server 2019, x64 | PowerShell 7.6.6, Windows PowerShell 5.1.17763.2931 | 69 in each host |
| AlmaLinux 8.10, x64, glibc 2.28, in a container | PowerShell 7.6.9 | 67 |
| Ubuntu 24.04, x64 | PowerShell 7.6.9 | 67 |
| FreeBSD 15.0-RELEASE, x64 | PowerShell 7.5.5 | 67 |

None failed; the tests skipped are for other systems. CI runs the suite at every push on Windows, Ubuntu and macOS, and built and tested the package's macOS arm64 library from the released commit. [Tested Platforms](https://variably-constant.github.io/SecureFetch/docs/reference/tested-platforms/) in the wiki has the details. Not run: arm64 other than macOS, and FreeBSD 13 and 14.

## Limitations

- Proxies are http:// only, reached with CONNECT, with Basic credentials; NTLM, Negotiate and https:// proxies are not supported.
- A redirect to http:// is never followed.
- A request body is sent whole from memory, framed by Content-Length; there is no streamed upload.
- Transfer codings other than chunked, and content codings other than gzip, deflate, br, zstd and identity, are refused as `SecureFetchEncoding`.
- `-MaximumDecodedBytes` bounds only a body sent with a content coding; any other is bounded by memory, or by the disk under `-OutFile`.
- `-KeepAlive` reuses a connection only for a request to the same host and port through the same proxy, within one invocation.
- Without `-OutFile` the body is held in memory twice, as `ContentBytes` and as `Content`.
- Trust in the Windows certificate store comes from its Root store alone: the Disallowed store is not consulted, and a root Windows downloads on demand is missing until Windows has fetched it. The default on Windows includes that store, so what a server's certificate must chain to there depends on the machine.
- A refusal writes an address's user information as `***`, but PowerShell keeps the command as written in the error record's `InvocationInfo`.
- A stop does not wait for the thread making the request: on Windows that thread and its connection end when the server sends or closes, or when that step's `-TimeoutSeconds` wait runs out, and a download's temporary file goes with it.

## Building from source

The module builds from this repository with [PoWerRuSt](https://crates.io/crates/PoWerRuSt) 1.0.0 from crates.io, which `Cargo.toml` names, and with cargo-pwrs 1.0.0, which has to be the version `Cargo.toml` pins PoWerRuSt to, since the two move together:

```powershell
cargo install cargo-pwrs --version 1.0.0 --locked
cargo pwrs build --release
Import-Module .\target\pwrs\SecureFetch\SecureFetch.psd1
```

```powershell
cargo build --release
cargo clippy --release --all-targets -- -D warnings
cargo pwrs test --release
```

The TLS code adds aws-lc-sys, which compiles C and, on x86-64 Windows, NASM assembly. The wiki's [Building From Source](https://variably-constant.github.io/SecureFetch/docs/building/building-from-source/) lists what the build needs, and [How To Run The Tests](https://variably-constant.github.io/SecureFetch/docs/building/how-to-run-the-tests/) what each test layer covers and which hosts it talks to.

## Repository layout

| Path | Role |
|---|---|
| `src/lib.rs` | the cmdlet, its HTTP/1.1 client, the TLS configuration and root sources, and the Rust unit tests |
| `tests/SecureFetch.Tests.ps1` | the Pester suite, run in PowerShell 7 and in Windows PowerShell 5.1 |
| `wiki/content/docs` | the wiki's pages, which [Wiki](#wiki) describes |
| `wiki/hugo.yaml`, `wiki/go.mod`, `wiki/layouts`, `wiki/i18n` | the Hugo site the wiki is published as, on the Hextra theme |
| `.cargo/config.toml` | links the C runtime into the native library |
| `.github/workflows/ci.yml` | at every push, on windows-latest, ubuntu-latest and macos-latest: installs cargo-pwrs 1.0.0, and NASM 3.02 on Windows, and runs the three commands under [Building from source](#building-from-source) |
| `.github/workflows/wiki-deploy.yml` | builds the wiki with Hugo and publishes it to GitHub Pages at every push to main |
| `.github/workflows/verify-gallery.yml` | started by hand after a publish: installs the published version from the PowerShell Gallery on Windows, Linux and macOS and runs the Pester suite against it |
| `licenses/alloc-stdlib-0.3.0/LICENSE` | the license text alloc-stdlib 0.3.0's package lacks, which the notices quote |
| `Cargo.toml`, `Cargo.lock` | the crate and its dependencies, PoWerRuSt 1.0.0 from crates.io and the rest at their newest releases, and the exact versions every build compiles |
| `CHANGELOG.md` | what changed in each version |
| `LICENSE` | MIT |

## Supported platforms

- **Hosts:** PowerShell 7.4 or later everywhere and Windows PowerShell 5.1 on Windows; [Tested platforms](#tested-platforms) lists the versions run.
- **Platforms:** Windows x64, Linux x64 with glibc 2.28 or newer, FreeBSD x64 and macOS arm64; [Tested platforms](#tested-platforms) says where each was run.
- **Rust:** 1.98 or later, the `rust-version` in `Cargo.toml`; edition 2024. The module ships from the `release` profile with fat LTO, one codegen unit, and `panic = "unwind"`, which PWRS needs to catch a panic at its boundary.

## Wiki

The documentation is published at [variably-constant.github.io/SecureFetch](https://variably-constant.github.io/SecureFetch/), built from [`wiki/content/docs`](https://github.com/Variably-Constant/SecureFetch/tree/main/wiki/content/docs) by the Diataxis framework: a tutorial, ten how-to guides, two explanations, four reference pages (`Invoke-SecureFetch`, `SecureFetch.Response`, errors, and the tested platforms), and two pages on building from source and running the tests. Every example on them was run in both hosts, with the output it printed.

## Credits and influences

- **[rustls](https://github.com/rustls/rustls)**, over **[aws-lc-rs](https://github.com/aws/aws-lc-rs)**, is the TLS stack, key exchange and certificate verification; **[webpki-roots](https://github.com/rustls/webpki-roots)** carries the Mozilla root program's roots.
- **[flate2](https://github.com/rust-lang/flate2-rs)**, **[brotli-decompressor](https://github.com/dropbox/rust-brotli-decompressor)** and **[ruzstd](https://github.com/KillingSpark/zstd-rs)** decode gzip and deflate, br and zstd bodies; **[encoding_rs](https://github.com/hsivonen/encoding_rs)** decodes text by the WHATWG Encoding Standard; **[schannel](https://github.com/steffengy/schannel-rs)** reads the Windows certificate store.
- **[PWRS (PoWerRuSt)](https://github.com/Variably-Constant/PWRS)** turns the crate into a module both hosts load.
- The request and response handling follows [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) and [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), redirects resolve by [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986), proxy credentials are [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617) Basic, and text is decoded by the [WHATWG Encoding Standard](https://encoding.spec.whatwg.org/).
- `Invoke-WebRequest` gave the names of the parameters it shares: `-Uri`, `-Method`, `-Headers`, `-Body`, `-ContentType`, `-TimeoutSeconds`, `-SkipHttpErrorCheck`, `-MaximumRedirection`, `-OutFile`, `-PassThru`, `-Proxy`, `-ProxyCredential` and `-NoProxy`.
- The wiki is built with [Hugo](https://gohugo.io/) on the [Hextra](https://github.com/imfing/hextra) theme.

## Use of AI tools

The author used Claude (Anthropic) via the Claude Code CLI for code development, tests and documentation drafting during the preparation of this repository. Every design decision was the author's, ruled on questions put to the author. The implementation, the Rust unit tests, the Pester suite in both hosts and the end-to-end runs were checked through `cargo clippy` with warnings denied, `cargo pwrs test` in both hosts, and module runs on Windows x64 against the servers this README names.

## License

MIT, in [LICENSE](https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE). The native library also compiles in rustls, aws-lc-rs, aws-lc-sys, webpki-roots, flate2, brotli-decompressor, ruzstd, encoding_rs, schannel, PoWerRuSt and their dependencies, each under its own license. cargo-pwrs writes the module's notices into its folder: `THIRD-PARTY-NOTICES.txt` at the root, for the assemblies PWRS compiles, and one in each of `runtimes\win-x64`, `runtimes\linux-x64`, `runtimes\osx-arm64` and `runtimes\freebsd-x64`, with the license and license files of each crate compiled into that native library. alloc-stdlib 0.3.0, which brotli-decompressor links, packages no license file, so the module supplies it: [licenses/alloc-stdlib-0.3.0/LICENSE](https://github.com/Variably-Constant/SecureFetch/blob/main/licenses/alloc-stdlib-0.3.0/LICENSE) is the LICENSE of [github.com/dropbox/rust-alloc-no-stdlib](https://github.com/dropbox/rust-alloc-no-stdlib/blob/0.3.0/LICENSE) at its tag 0.3.0, the source the crate was packaged from, named for that crate and version in `Cargo.toml`'s `[package.metadata.pwrs.license-files]`.

## Contributing

Issues and pull requests go to [github.com/Variably-Constant/SecureFetch](https://github.com/Variably-Constant/SecureFetch).
