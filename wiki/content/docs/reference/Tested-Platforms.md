---
title: Tested Platforms
weight: 4
aliases:
  - /docs/reference/where-it-has-been-run/
---

What has been built and run, on what, and what it showed. The first table is the Windows 11 machine every example on these pages ran on: each row is a run built from the repository's committed files, with the release module that `cargo pwrs build --release` wrote imported from its folder in both hosts. [Other platforms](#other-platforms) lists the build and the test suite on five more. Nothing else has been run; the list at the end names what has not.

| | |
|---|---|
| Machine | AMD Ryzen 9 7900X, Windows 11 Pro 10.0.26200, with the Visual Studio 2022 Build Tools (MSVC 14.44) and NASM on `PATH` |
| Builds | every row, and the examples in the README and on these pages, from the code these pages describe |
| Hosts | PowerShell 7.6.9 and Windows PowerShell 5.1.26100.9711, with Pester 6.2.0 in both; the suite also in PowerShell 7.4.20 and 7.5.11 |
| Built with | rustc 1.98.1; cargo-pwrs 1.0.0 and PoWerRuSt 1.0.0 from crates.io, rustls 0.23.46, aws-lc-rs 1.19.0, aws-lc-sys 0.47.0, webpki-roots 1.0.11, flate2 1.1.10 (zlib-rs 0.6.8), brotli-decompressor 6.2.0, ruzstd 0.9.1, encoding_rs 0.8.44, schannel 0.1.30 (windows-sys 0.61.2), `-C target-feature=+crt-static` from `.cargo/config.toml`, and no `RUSTFLAGS` or `AWS_LC_SYS_*` variable set |
| Result | `cargo clippy --release --all-targets -- -D warnings` clean; `cargo pwrs test --release` built the module and passed 53 Rust unit tests, then 69 Pester tests in each host with none failed; in each host the 2 tests for systems without a Windows certificate store were skipped. The same 69 passed, 2 skipped, in PowerShell 7.4.20 and 7.5.11 |
| Notices | `cargo pwrs build --release` wrote `runtimes\win-x64\THIRD-PARTY-NOTICES.txt` (221429 bytes), listing the 28 crates compiled into the native library, each with its license, the license files its package carries and its page on crates.io; alloc-stdlib 0.3.0, whose package carries none, has `licenses/alloc-stdlib-0.3.0/LICENSE`, which the module supplies. `THIRD-PARTY-NOTICES.txt` at the module folder's root (7527 bytes) covers the assemblies PWRS compiles |
| Files | in both hosts, speed.cloudflare.com's 99,999,999-byte body written through `-OutFile` while the host process's working set, sampled every 100 ms, went from 101.8 MiB to at most 113.5 MiB in PowerShell 7 and from 134.2 MiB to at most 141.1 MiB in Windows PowerShell; the download took 12.0 and 12.3 s over this connection |
| Stopped | requests blocked in a TLS handshake a local server never answered, in a response postman-echo.com delayed by 10 s, in a connection attempt to 10.255.255.1, and in resolving a single-label name that does not exist, each stopped five times through `PowerShell.Stop()` as Ctrl+C would: `Stop()` returned within 0.5 ms, and the first stop in each process after 2.9 ms in PowerShell 7 and 23 ms in Windows PowerShell; 1.9 and 3.4 of the 24 logical processors were busy on average |
| Timed out | with `-TimeoutSeconds 1`, resolving a single-label name that does not exist ended as `SecureFetchTimeout` after 1040 to 1063 ms in PowerShell 7 and 1039 to 1065 ms in Windows PowerShell, three runs each, where the system resolver took 1237 to 1264 ms to report such a name missing |
| Messages | in both hosts: `-Proxy https://127.0.0.1:3128` refused as `SecureFetchProxy` (InvalidArgument); a proxy at 127.0.0.1:1, where nothing listens, as `SecureFetchProxy` (ConnectionError); a local listener answering 407 as `SecureFetchProxy` (AuthenticationError); and under `-KeepAlive`, a POST to lwn.net after the server closed the kept connection during 9 idle seconds as `SecureFetchConnection`, not sent again; each message is the one [Error Reference](Error-Reference.md) quotes |
| Examples | the 35 examples on these pages, each page's in order in a process of its own, in both hosts: every one printed the output its page shows, apart from the three on the trusted-roots and proxy pages that need a local test server, a root added to the machine's store or a test proxy, and the reference page's list of the help's examples, shown without output. The suite's own tests of those three cases passed, and the proxy's 407 message was checked against a local listener |

## Other platforms

From the same committed files, with PoWerRuSt 1.0.0 and cargo-pwrs 1.0.0 from crates.io, Rust 1.98.1 and Pester 6.2.0. The AlmaLinux container and the FreeBSD machine built the module themselves with `cargo build --release`, `cargo clippy --release --all-targets -- -D warnings` and `cargo pwrs test --release`, all clean. The Ubuntu machine ran the suite against the AlmaLinux build, the Windows 10 machine against the Windows 11 build, and the Windows Server 2019 machine against the package, installed from a local repository. The Pester tests a platform skips are the ones for other systems, 2 in each host on Windows and 4 elsewhere, which [How To Run The Tests](How-To-Run-The-Tests.md) names, and the Windows builds run one unit test more, the one that reads the Windows store.

| Platform | Machine | Built with | Result |
|---|---|---|---|
| Windows 10 Pro 22H2 10.0.19045, x64 | a fresh install in a QEMU virtual machine on the Windows 11 machine, with software CPU emulation, 4 vCPUs and 4 GB; without the Visual C++ Redistributable, `vcruntime140.dll` absent from `System32`; elevated | the Windows 11 build, with the C runtime linked in | in Windows PowerShell 5.1.19041.6456 on .NET Framework release 528372 and then in PowerShell 7.6.6 on .NET 10.0.12, extracted from its official zip: in each host the module imported, pq.cloudflareresearch.com answered 200 over TLSv1_3 with X25519MLKEM768 and TLS13_AES_256_GCM_SHA384, and 69 Pester tests passed, 2 skipped; `vcruntime140.dll` was still absent afterward |
| Windows Server 2019 Standard Evaluation 10.0.17763, x64 | a fresh install in a QEMU virtual machine on the Windows 11 machine, with software CPU emulation, 4 vCPUs and 4 GB; without the Visual C++ Redistributable, `vcruntime140.dll` absent from `System32`; elevated | the package, holding the Windows 11, AlmaLinux and FreeBSD libraries, in a local repository | in Windows PowerShell 5.1.17763.2931 on .NET Framework release 461814, `Install-Module` (PowerShellGet 1.0.0.1) installed 0.2.0 from the repository, and in PowerShell 7.6.6 on .NET 10.0.12, extracted from its official zip, so did `Install-Module` (PowerShellGet 2.2.5) and `Install-PSResource` (PSResourceGet 1.2.0), both with the same Windows library; in each host the installed module carried win-x64, linux-x64 and freebsd-x64, imported, pq.cloudflareresearch.com answered 200 over TLSv1_3 with X25519MLKEM768 and TLS13_AES_256_GCM_SHA384, and 69 Pester tests passed, 2 skipped; `vcruntime140.dll` was still absent afterward |
| AlmaLinux 8.10, x86_64, glibc 2.28 | a `quay.io/pypa/manylinux_2_28_x86_64` container on the Ubuntu machine below | rustc 1.98.1, gcc 14.2.1 | 52 unit tests, then 67 Pester tests passed in PowerShell 7.6.9, 4 skipped; the library asks for no glibc symbol version newer than GLIBC_2.28 |
| Ubuntu 24.04.4 LTS, x86_64, glibc 2.39 | a virtual machine on an AMD Ryzen 7 5700G | the AlmaLinux build above | 67 Pester tests passed in PowerShell 7.6.9, 4 skipped |
| FreeBSD 15.0-RELEASE, amd64 | a virtual machine on the same AMD Ryzen 7 5700G | rustc 1.98.1, clang 19.1.7 | 52 unit tests, then 67 Pester tests passed in PowerShell 7.5.5 on .NET 9.0.14, 4 skipped; the library needs `libc.so.7`, `libthr.so.3` and `libgcc_s.so.1` at symbol versions no newer than FBSD_1.6, which FreeBSD 13.0 added. PowerShell there reports none of Windows, Linux and macOS, which Pester's platform check refuses, so Pester was imported after `$IsLinux` was set to true in the global scope |

The repository's CI builds the module and runs the suite at every push, on Windows in both hosts and on Ubuntu and macOS in PowerShell 7; the package's macOS arm64 library is the one CI built and tested from the released commit.

## Not yet tested

- Windows, Linux and FreeBSD on arm64; macOS is the only arm64 system built.
- FreeBSD 13 and 14.
- The examples on these pages and the measurements in the first table, anywhere but the Windows 11 machine; on the other platforms the Pester suite is what ran.
