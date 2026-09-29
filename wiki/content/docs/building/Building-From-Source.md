---
title: Building From Source
weight: 1
---

From a checkout of the repository to a module folder that imports in PowerShell 7 and, on Windows, in Windows PowerShell 5.1. Installing from the PowerShell Gallery, as [Getting Started](Getting-Started.md) does, needs none of this. Source: `Cargo.toml`, `.cargo/config.toml`, `src/lib.rs`.

## What the build needs

- Windows x64, Linux x64, FreeBSD x64 or macOS arm64: the module has been built and its suite run on each, as [Where It Has Been Run](Where-It-Has-Been-Run.md) reports. Windows PowerShell 5.1 is on Windows alone; elsewhere the host is PowerShell 7.
- Rust 1.98 or later: `Cargo.toml` names `rust-version = "1.98"` and edition 2024, so an older rustc refuses the crate.
- [PoWerRuSt](https://crates.io/crates/PoWerRuSt) 0.3.0 from crates.io, which `Cargo.toml` names, and cargo-pwrs 0.3.0: `cargo install cargo-pwrs --version 0.3.0 --locked` installs the tool the runs on these pages used, and `cargo install cargo-pwrs` without a version takes the newest, which has to be the version `Cargo.toml` pins PoWerRuSt to, since the tool and the crate move together. PWRS's [Getting Started](https://variably-constant.github.io/PWRS/docs/tutorials/getting-started/) lists what cargo-pwrs needs beside Rust.
- A C compiler for aws-lc-sys, the C cryptography under rustls. On Windows that is the Visual Studio Build Tools (MSVC), with NASM on `PATH` for its x86-64 assembly; aws-lc-sys's [README](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-sys/README.md) describes `AWS_LC_SYS_PREBUILT_NASM=1` for a machine without NASM, and the Windows builds these pages report used NASM. On Linux, FreeBSD and macOS it is the system's `cc`: gcc 14.2.1 in the Linux build these pages report and clang 19.1.7 on the FreeBSD machine. A Linux library asks for the glibc it was built against; the package's is built in a `quay.io/pypa/manylinux_2_28_x86_64` container (AlmaLinux 8, glibc 2.28), so it loads on glibc 2.28 and newer.

## Build

From the repository's root:

```powershell
cargo pwrs build --release
```

The module folder is `target\pwrs\SecureFetch`, under `CARGO_TARGET_DIR` when that is set. Beside the manifest and the libraries it holds `THIRD-PARTY-NOTICES.txt`, for the assemblies PWRS compiles, and under `runtimes` a folder for the platform it was built on (`win-x64`, `linux-x64`, `freebsd-x64` or `osx-arm64`) holding the native library and a `THIRD-PARTY-NOTICES.txt` with the license and license files of each crate compiled into it. On Windows, `.cargo/config.toml` links the C runtime into the native library (`-C target-feature=+crt-static`), so the module does not need the Visual C++ Redistributable; a `RUSTFLAGS` variable replaces those flags, so a Windows build that sets one adds `-C target-feature=+crt-static` to it.

`cargo pwrs test --release` runs the Rust unit tests, builds the module, and runs `tests/SecureFetch.Tests.ps1` in `pwsh` and, on Windows, in `powershell.exe`; see [How To Run The Tests](How-To-Run-The-Tests.md).

## Import the folder

```powershell
Import-Module .\target\pwrs\SecureFetch\SecureFetch.psd1
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace | Select-Object Protocol, KeyExchange
```

```text
Protocol KeyExchange
-------- -----------
TLSv1_3  X25519MLKEM768
```

From here the module behaves as the installed one does, and [Getting Started](Getting-Started.md) goes on from its first request.
