---
title: How To Run The Tests
weight: 11
---

Two layers: Rust unit tests in `src/lib.rs`, and the Pester suite in `tests/SecureFetch.Tests.ps1`, run against the built module in PowerShell 7 and, on Windows, in Windows PowerShell 5.1. Source: `src/lib.rs` (`mod tests`), `tests/SecureFetch.Tests.ps1`, and cargo-pwrs's `test` command.

```powershell
cargo pwrs test --release
```

`cargo pwrs` here is cargo-pwrs 0.3.0, installed from crates.io as [Building From Source](Building-From-Source.md) sets it up. This runs `cargo test`, builds the module, and runs the Pester suite in `pwsh` and then, on Windows, in `powershell.exe`, with `PWRS_MODULE` set to the module folder. Each host prints a line such as `pwrs pester host=7.6.6 pester=6.2.0 passed=<n> failed=<n>`, and a failing host ends the run. The runner loads Pester from `PWRS_PESTER_PATH` when set, else from `target\pester\Pester` when that folder exists, else from the host's module path.

## What the unit tests cover

Taking addresses, responses and Location references apart (the RFC 3986 section 5.4 examples included), framing and chunked bodies, content codings and the decoded-size bound, charsets and byte order marks, the request each set of parameters sends, header and body refusals, addresses quoted in refusals with their user information masked, redirect rules, proxy addresses and Basic credentials, the choice of roots and, on Windows, the Windows store, the `-OutFile` temporary file, and stopping and bounding a request, through PWRS's fake host where the cmdlet's own phase runs.

## What the Pester suite talks to

The Contexts that talk to pq.cloudflareresearch.com, postman-echo.com, httpbin.org, github.com, raw.githubusercontent.com, www.messenger.com, www.google.com, badssl.com and www.debian.org need the network; each test marks itself skipped when its host's port 443 cannot be reached, so a machine without a route out still passes. badssl.com drops a connection now and then, so the tests that ask it make a request that fails as `SecureFetchConnection` once more, writing a line that starts with `RETRY` and names the address, the time, the host's version and the first attempt's message; any other result is judged as the first attempt's would be. Only postman-echo.com, an echo service, is sent anything but a GET or a HEAD: POST, PUT, PATCH, DELETE and OPTIONS requests, header values, and synthetic bodies built from "SecureFetch test" and a new GUID. httpbin.org receives two of those bodies, which the redirect tests POST through its redirect-to endpoint on their way to postman-echo.com. Every request to any other public host is a GET or a HEAD.

Between them the two layers raise every error id in the [Error Reference](Error-Reference.md) but two. The Pester suite raises all except `SecureFetchBadHost`, `SecureFetchTruncated`, `SecureFetchEncoding`, `SecureFetchConnection`, `SecureFetchStopped` and `SecureFetchOutOfMemory`; the unit tests check the first three and `SecureFetchStopped`, the last by running the cmdlet's phase against a stop, since a stopped pipeline keeps PowerShell's own `PipelineStopped` record in its error stream instead. No test raises `SecureFetchConnection` or `SecureFetchOutOfMemory`.

Two Contexts run servers of their own on 127.0.0.1 inside the Pester process: a CONNECT proxy, and an HTTPS server on a certificate issued by a private root made in memory, which counts the connections it accepts and the requests each carries, so closing each connection by default and keeping one under `-KeepAlive` are checked on every system. On Windows the roots test adds that root to `LocalMachine\Root` for the test and removes it in a `finally`, writing each add and remove, with the root's thumbprint and time, to `securefetch-test-roots.log` in the system's temporary folder; it needs an elevated session and marks itself skipped without one.

## What depends on the system

Six Pester tests run on some systems only. Four run on Windows: the two that trust a root through the Windows certificate store, the one where Windows refuses to replace a file another handle holds open, and the one that reads this process's connections to a public server through `Get-NetTCPConnection`. Two run everywhere else: `-TrustedRoots Windows` refused on a system without that store, and a file another handle holds open replaced while that handle goes on reading what it opened. So a run reports 2 skipped on Windows and 4 elsewhere, before any skip for a host that cannot be reached. The unit test that reads the Windows store is compiled on Windows alone, so Windows runs one unit test more.
