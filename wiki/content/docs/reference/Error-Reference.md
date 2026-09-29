---
title: Error Reference
weight: 3
---

Every error record `Invoke-SecureFetch` raises, by the id its `FullyQualifiedErrorId` starts with (the rest is `,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand`). Source: `src/lib.rs`; every `PsError::new` there names one of these ids. A record is non-terminating unless `-ErrorAction Stop` makes it terminating, so the pipeline goes on to the next address. A message that quotes an address given to `-Uri` or `-Proxy`, or a proxy the system names, writes the user information in it as `***`, so a password given there does not reach the record; PowerShell still fills the record's `InvocationInfo` with the command as written. The messages below are from runs on Windows 11 Pro 10.0.26200, in both hosts unless noted: the `SecureFetchProxy` messages for an https:// `-Proxy` and for a proxy that cannot be reached, and the `SecureFetchConnection` message, from the end-to-end runs in [Where It Has Been Run](Where-It-Has-Been-Run.md), and every other from the run of the examples on these pages.

## Refused before any connection

| Id | Category | When | A message from a run |
|---|---|---|---|
| `SecureFetchNotHttps` | InvalidArgument | the address is not https:// | `http://example.com/ is not an https:// address` |
| `SecureFetchUserInfo` | InvalidArgument | the address carries user information, which the message writes as `***` | `https://***@example.com/ carries user information, which this cmdlet does not send` (given `https://user:secret@example.com/`) |
| `SecureFetchBadHost` | InvalidArgument | there is no host, it is neither a DNS name nor an IP address, or an IPv6 address opened with `[` is not closed or is followed by something other than `:` and a port | `https:///index.html names no host` |
| `SecureFetchBadPort` | InvalidArgument | the port is not a number from 1 to 65535 | `tls is not a port: invalid digit found in string` |
| `SecureFetchBadHeader` | InvalidArgument | a `-Headers` name that is not a token or is a field the cmdlet writes itself, a value that is not a string or an array of strings, a value or `-ContentType` carrying a control byte other than tab, Content-Type given both in `-Headers` and by `-ContentType` or Accept-Encoding given in `-Headers` with `-NoCompression` (the message quotes both values), or a string body whose Content-Type names a charset other than UTF-8 | `Host cannot be set through -Headers: SecureFetch writes the Host field itself` |
| `SecureFetchBadBody` | InvalidArgument | `-Body` is neither a string nor a byte array | `-Body takes a string or a byte array, not a System.Int32` |
| `SecureFetchBadOutFile` | InvalidArgument | `-OutFile` cannot be resolved, is not a file system path, is in a folder that does not exist, or names a folder | `-OutFile HKCU:\Software\SecureFetch-docs is a path of the Registry provider, not a file system path` |
| `SecureFetchProxy` | InvalidArgument | `-Proxy` is not an http:// address, carries user information or a path, names no host or a port outside 1 to 65535, or comes with `-NoProxy` | `-Proxy https://127.0.0.1:3128 is an https:// proxy, which this version does not support` |
| `SecureFetchRootStore` | InvalidArgument | `-TrustedRoots` names None beside another source, or the roots chosen trust nothing | `no root is trusted: -TrustedRoots names no source of roots and no -RootCertificate is given, so no server could be verified` |

## Reaching the server

| Id | Category | When | A message from a run |
|---|---|---|---|
| `SecureFetchResolve` | ConnectionError | the host name does not resolve | `cannot resolve securefetch.invalid: No such host is known. (os error 11001)` |
| `SecureFetchConnect` | ConnectionError | no address of the host accepts a connection | `cannot connect to 127.0.0.1 (127.0.0.1:1: No connection could be made because the target machine actively refused it. (os error 10061))` |
| `SecureFetchTimeout` | OperationTimeout | a wait runs past `-TimeoutSeconds` | `127.0.0.1 kept the connection waiting longer than 2 s` |
| `SecureFetchProxy` | ConnectionError | the proxy cannot be resolved or reached, answers CONNECT with anything but 2xx or sends bytes after its 2xx answer, or is a proxy the system names whose address cannot be used, such as an https:// one | `the proxy http://127.0.0.1:1 could not be used: cannot connect to 127.0.0.1 (127.0.0.1:1: No connection could be made because the target machine actively refused it. (os error 10061))` |
| `SecureFetchProxy` | AuthenticationError | the proxy answers 407 | `the proxy http://127.0.0.1:3128 asks for credentials (407 Proxy Authentication Required); give them with -ProxyCredential` |
| `SecureFetchRootStore` | SecurityError | the Windows certificate store cannot be opened, `-TrustedRoots Windows` is given on a system without that store, or a `-RootCertificate` cannot be used as a root; each is refused before any connection | `the -RootCertificate CN=Oversized example root (thumbprint B325565D4EDA325444C5791B9037CA4F2DEB59A9) cannot be used as a root: invalid peer certificate: BadEncoding` (PowerShell 7, a certificate longer than rustls-webpki reads; no run failed to open the store) |
| `SecureFetchTls` | SecurityError | the handshake or the exchange fails, a certificate that does not verify included | `the TLS exchange with localhost failed: invalid peer certificate: UnknownIssuer` |
| `SecureFetchNotPostQuantum` | SecurityError | `-RequirePostQuantum` was given and the server did not complete a TLS 1.3 handshake with X25519MLKEM768; nothing but the handshake was sent | `www.debian.org did not complete a TLS 1.3 handshake with X25519MLKEM768, the only key exchange -RequirePostQuantum offers: received fatal alert: HandshakeFailure` |
| `SecureFetchConnection` | ConnectionError | the connection fails some other way, or under `-KeepAlive` the server closed a kept connection before answering a POST or PATCH, which is not sent twice | `postman-echo.com closed the connection kept from an earlier request before answering this POST; a POST is not idempotent, so it is not sent again on a new connection` |

## The response

| Id | Category | When | A message from a run |
|---|---|---|---|
| `SecureFetchBadResponse` | ProtocolError | the response is not well-formed HTTP: a bad status line, field line or chunk size, a chunk longer than its size, a Content-Length that is not a number or disagrees with another, no end to the header section, a 101, Transfer-Encoding beside Content-Length or in an HTTP/1.0 response, a body that does not decode under its Content-Encoding, a redirect whose Location fields disagree, or a redirect whose https:// Location cannot be sent, whose record names the Location and carries the redirect response as its `TargetObject` | `the response from httpbin.org redirected to https://user@example.com/, which cannot be sent: https://***@example.com/ carries user information, which this cmdlet does not send`; the malformed-message cases are raised by the Rust unit tests only, since no server produced one in these runs |
| `SecureFetchTruncated` | ProtocolError | the connection closes before the body ends: short of its Content-Length, or inside its chunked framing | raised by the Rust unit tests; no server produced it in these runs |
| `SecureFetchEncoding` | NotImplemented | a transfer coding other than chunked, or a Content-Encoding other than gzip, deflate, br, zstd and identity | raised by the Rust unit tests; no server produced it in these runs |
| `SecureFetchTooLarge` | LimitsExceeded | a body sent with a content coding decodes to more than `-MaximumDecodedBytes` bytes | `the gzip body from httpbin.org decodes to more than 100 bytes, the -MaximumDecodedBytes bound` |
| `SecureFetchHttpStatus` | InvalidResult | the status is 4xx or 5xx and `-SkipHttpErrorCheck` was not given; the record's `TargetObject` is the response | `https://pq.cloudflareresearch.com/cdn-cgi/securefetch-no-such-page answered 404 Not Found` |
| `SecureFetchRedirectNotHttps` | SecurityError | a redirect leads to an address that is not https://; the record's `TargetObject` is the redirect response | `https://httpbin.org/redirect-to?url=http://example.com/ redirected to http://example.com/, which is not an https:// address, so it is not followed` |
| `SecureFetchTooManyRedirects` | LimitsExceeded | following one more redirect would pass `-MaximumRedirection`; the record's `TargetObject` is that redirect response | `https://httpbin.org/redirect/3 kept redirecting past -MaximumRedirection 1: after 1 redirect, a 302 from https://httpbin.org/relative-redirect/2 led to /relative-redirect/1` |
| `SecureFetchWriteFailed` | WriteError | the body cannot be written to the `-OutFile` file; the temporary file is deleted and the target left as it was | `cannot write the body to C:\Temp\securefetch-docs-files\locked.bin: cannot replace it with C:\Temp\securefetch-docs-files\locked.bin.1fbaf65e7a60a528.securefetch-partial: Access is denied. (os error 5)` (PowerShell 7 on Windows; the target was held open by another handle without delete sharing, and kept its content; Linux, FreeBSD and macOS replace such a file instead) |

## The session

| Id | Category | When | A message from a run |
|---|---|---|---|
| `SecureFetchStopped` | OperationStopped | the pipeline stops while the request is under way | a stopped pipeline keeps PowerShell's own `PipelineStopped` record in its error stream instead, so the Rust unit tests check it by running the cmdlet's phase against a stop directly |
| `SecureFetchOutOfMemory` | ResourceUnavailable | the response, or the module's copy of a byte array `-Body`, does not fit in memory, or the system will not start a thread the request needs | not produced in any run |
