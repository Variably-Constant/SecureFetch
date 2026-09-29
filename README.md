<div align="center">

# SecureFetch

**HTTPS from PowerShell over TLS 1.3 with the X25519MLKEM768 post-quantum hybrid key exchange, from rustls inside the module.**

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/SecureFetch?style=flat-square)](https://www.powershellgallery.com/packages/SecureFetch)
[![Wiki](https://img.shields.io/github/actions/workflow/status/Variably-Constant/SecureFetch/wiki-deploy.yml?branch=main&label=wiki&style=flat-square)](https://variably-constant.github.io/SecureFetch/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.4%2B%20%7C%205.1-5391FE.svg?style=flat-square)](https://learn.microsoft.com/powershell/)

**[Wiki](https://variably-constant.github.io/SecureFetch/)** | [Getting started](https://variably-constant.github.io/SecureFetch/docs/tutorials/getting-started/) | [Reference](https://variably-constant.github.io/SecureFetch/docs/reference/invoke-securefetch-reference/) | [Changelog](https://github.com/Variably-Constant/SecureFetch/blob/main/CHANGELOG.md)

`Invoke-SecureFetch` makes HTTPS requests with its own TLS stack, [rustls](https://github.com/rustls/rustls), inside the module, and every response says which key exchange carried it. It runs in Windows PowerShell 5.1 and PowerShell 7.4 or later, and is built with [PoWerRuSt](https://github.com/Variably-Constant/PWRS).

</div>

---

<details>
<summary><b>Table of contents</b></summary>

- [Features](#features)
- [Quick start](#quick-start)
- [Why a module of its own](#why-a-module-of-its-own)
- [What it can do](#what-it-can-do)
- [Where it has been run](#where-it-has-been-run)
- [Limits](#limits)
- [Building from source](#building-from-source)
- [Repository layout](#repository-layout)
- [Platforms](#platforms)
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
- [HTTP proxies](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-use-a-proxy/) through CONNECT, the system's by default, with TLS end to end.
- [gzip, deflate, br and zstd bodies](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-read-compressed-and-encoded-bodies/) decoded within a bound, and text decoded by its charset.
- [Kept connections](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-pipe-addresses-and-keep-connections/) for the next request to the same host and port, piped or redirected.
- [An error record](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-handle-errors/) with its own id for each way a request fails; a 4xx or 5xx carries the response.
- [A stop ends a request at once](https://variably-constant.github.io/SecureFetch/docs/how-to/how-to-bound-and-stop-requests/), and `-TimeoutSeconds` bounds every wait.
- `Invoke-WebRequest` and every other module keep the host's TLS stack.

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

## Why a module of its own

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

SecureFetch carries its own TLS stack. `dumpbin /dependents` of the module's native library, built on Windows 11 Pro 10.0.26200, lists no Windows TLS library: its imports are `KERNEL32.dll` (listed a second time as `kernel32.dll`), `ntdll.dll`, `WS2_32.dll`, `bcryptprimitives.dll`, `api-ms-win-core-synch-l1-2-0.dll` and `crypt32.dll`, the last to read the Windows certificate store, with no `VCRUNTIME140.dll` and no `api-ms-win-crt-*` set. The wiki's [Why A Module Of Its Own](https://variably-constant.github.io/SecureFetch/docs/explanation/why-a-module-of-its-own/) says more.

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
https://github.com/PowerShell/PowerShell/releases/tag/v7.6.6
1734E52435CF6CDDDEF2B340039986A8487FDD1CEAED44D1B93B39293E4A9DD4
SecureFetchNotPostQuantum,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
```

Each feature above links its how-to page. Every parameter, every property of `SecureFetch.Response` with its type, and every error id are in the wiki's reference: [Invoke-SecureFetch](https://variably-constant.github.io/SecureFetch/docs/reference/invoke-securefetch-reference/), [SecureFetch.Response](https://variably-constant.github.io/SecureFetch/docs/reference/response-reference/), [Errors](https://variably-constant.github.io/SecureFetch/docs/reference/error-reference/).

## Where it has been run

From this repository's committed files, with PoWerRuSt 0.3.0 and cargo-pwrs 0.3.0 from crates.io, Rust 1.98.1 and Pester 6.2.0. Windows 11, an AlmaLinux container and FreeBSD built the module with the release build and clippy clean and passed its Rust unit tests and the Pester suite; Ubuntu ran the suite against the AlmaLinux build, Windows 10 against the Windows 11 build, and Windows Server 2019 against the package, installed with `Install-Module` from a local repository.

| Platform | Hosts |
|---|---|
| Windows 11 Pro 10.0.26200, x64 | PowerShell 7.6.6, Windows PowerShell 5.1.26100.9444 |
| Windows 10 Pro 22H2 10.0.19045, x64, without the Visual C++ Redistributable | PowerShell 7.6.6, Windows PowerShell 5.1.19041.6456 |
| Windows Server 2019, x64, without the Visual C++ Redistributable | PowerShell 7.6.6, Windows PowerShell 5.1.17763.2931 |
| AlmaLinux 8.10, x64, glibc 2.28, in a container | PowerShell 7.6.6 |
| Ubuntu 24.04, x64 | PowerShell 7.6.5 |
| FreeBSD 15.0-RELEASE, x64 | PowerShell 7.5.5 |

The Windows builds pass 53 unit tests and 66 Pester tests in each host, the others 52 and 64; none failed, and the Pester tests left out are the ones for other systems. On Windows 11 every example in this README and in the wiki ran in both hosts with the output shown, and the notices list the 30 crates compiled into the native library, each with its license text. The repository's CI builds the module and runs the suite at every push, on Windows in both hosts and on Ubuntu and macOS in PowerShell 7; the package's macOS arm64 library is the one CI built and tested from the released commit. The wiki's [Where It Has Been Run](https://variably-constant.github.io/SecureFetch/docs/reference/where-it-has-been-run/) has each run's machine and versions, and each feature's end-to-end run, row by row. Not run: arm64 anywhere but macOS, and FreeBSD 13 and 14.

## Limits

- Proxies are http:// only, reached with CONNECT, with Basic credentials; NTLM, Negotiate and https:// proxies are not supported.
- A redirect to http:// is never followed; a 300, a 304 or a redirect without a Location is written as it is.
- A request body is sent whole from memory, framed by Content-Length; there is no streamed upload.
- Transfer codings other than chunked, and content codings other than gzip, deflate, br, zstd and identity, are refused as `SecureFetchEncoding`.
- `-MaximumDecodedBytes` bounds only a body sent with a content coding; any other is bounded by memory, or by the disk under `-OutFile`.
- `-KeepAlive` reuses a connection only for a request to the same host and port through the same proxy, within one invocation.
- Without `-OutFile` the body is held in memory twice, as `ContentBytes` and as `Content`.
- Charset labels are read as the WHATWG Encoding Standard reads them (`iso-8859-1` decodes as windows-1252); an unknown label, or none, decodes as UTF-8.
- Trusting the Windows store means a `crypt32.dll` import and, on Windows, a default that depends on the machine's store (elsewhere the default is the bundled roots alone); the Disallowed store is not consulted, and a root Windows downloads on demand is absent until Windows fetches it.
- A refusal writes an address's user information as `***`, but PowerShell keeps the command as written in the error record's `InvocationInfo`.
- Without `-RequirePostQuantum` the key exchange is reported, not required, and TLS 1.2 is accepted.
- A stop does not wait for the thread making the request: on Windows that thread and its connection end when the server sends or closes, or when that step's `-TimeoutSeconds` wait runs out, and a download's temporary file goes with it.

## Building from source

The module builds from this repository with [PoWerRuSt](https://crates.io/crates/PoWerRuSt) 0.3.0 from crates.io, which `Cargo.toml` names, and with cargo-pwrs 0.3.0, which has to be the version `Cargo.toml` pins PoWerRuSt to, since the two move together:

```powershell
cargo install cargo-pwrs --version 0.3.0 --locked
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
| `wiki/content/docs` | the documentation, organized by the Diataxis framework: tutorials, how-to guides, explanations and reference pages, and a section for building from source |
| `wiki/hugo.yaml`, `wiki/go.mod`, `wiki/layouts`, `wiki/i18n` | the Hugo site the wiki is published as, on the Hextra theme |
| `.cargo/config.toml` | links the C runtime into the native library |
| `.github/workflows/ci.yml` | a GitHub Actions workflow with a job each for windows-latest, ubuntu-latest and macos-latest: cargo-pwrs 0.3.0 (and NASM 3.02 on Windows), then the three commands under [Building from source](#building-from-source), at every push |
| `.github/workflows/wiki-deploy.yml` | builds the wiki with Hugo and publishes it to GitHub Pages at every push to main |
| `.github/workflows/verify-gallery.yml` | started by hand after a publish: installs the published version from the PowerShell Gallery on Windows, Linux and macOS and runs the Pester suite against it |
| `licenses/alloc-stdlib-0.3.0/LICENSE` | the license text alloc-stdlib 0.3.0's package lacks, which the notices quote |
| `Cargo.toml`, `Cargo.lock` | the crate and its dependencies, PoWerRuSt 0.3.0 from crates.io and the rest at their newest releases, and the exact versions every build compiles |
| `CHANGELOG.md` | what changed in each version |
| `LICENSE` | MIT |

## Platforms

- **Hosts:** PowerShell 7.4 or later everywhere and Windows PowerShell 5.1 on Windows; run on PowerShell 7.5.5, 7.6.5 and 7.6.6, and on Windows PowerShell 5.1.17763.2931, 5.1.19041.6456 and 5.1.26100.9444.
- **Platforms:** Windows x64 (Windows 11, Windows 10 and Windows Server 2019), Linux x64 with glibc 2.28 or newer (built on AlmaLinux 8.10 and run there and on Ubuntu 24.04), FreeBSD x64 (15.0), and macOS arm64, whose library CI builds and tests, as [Where it has been run](#where-it-has-been-run) reports. Arm64 other than macOS has not been tried.
- **Rust:** 1.98 or later, the `rust-version` in `Cargo.toml`; edition 2024. The module ships from the `release` profile with fat LTO, one codegen unit, and `panic = "unwind"`, which PWRS needs to catch a panic at its boundary.

## Wiki

The documentation is published at [variably-constant.github.io/SecureFetch](https://variably-constant.github.io/SecureFetch/), built from [`wiki/content/docs`](https://github.com/Variably-Constant/SecureFetch/tree/main/wiki/content/docs) by the Diataxis framework: a tutorial, ten how-to guides, two explanations, four reference pages (`Invoke-SecureFetch`, `SecureFetch.Response`, errors, and where it has been run), and two pages on building from source and running the tests. Every example on them was run in both hosts, with the output it printed.

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

MIT, in [LICENSE](https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE). The native library also compiles in rustls, aws-lc-rs, aws-lc-sys, webpki-roots, flate2, brotli-decompressor, ruzstd, encoding_rs, schannel, PoWerRuSt and their dependencies, each under its own license. cargo-pwrs writes the notices the module carries into its folder: `THIRD-PARTY-NOTICES.txt` at the root, for the assemblies PWRS compiles, and `runtimes\win-x64\THIRD-PARTY-NOTICES.txt`, with the license and license files of each crate compiled into the native library. alloc-stdlib 0.3.0, which brotli-decompressor links, packages no license file, so the module supplies it: [licenses/alloc-stdlib-0.3.0/LICENSE](https://github.com/Variably-Constant/SecureFetch/blob/main/licenses/alloc-stdlib-0.3.0/LICENSE) is the LICENSE of [github.com/dropbox/rust-alloc-no-stdlib](https://github.com/dropbox/rust-alloc-no-stdlib/blob/0.3.0/LICENSE) at its tag 0.3.0, the source the crate was packaged from, named for that crate and version in `Cargo.toml`'s `[package.metadata.pwrs.license-files]`.

## Contributing

Issues and pull requests go to [github.com/Variably-Constant/SecureFetch](https://github.com/Variably-Constant/SecureFetch).
