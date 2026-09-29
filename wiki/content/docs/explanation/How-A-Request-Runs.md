---
title: How A Request Runs
weight: 2
---

One record through `Invoke-SecureFetch`, from the pipeline thread to the socket and back. Source: `src/lib.rs`.

## On the pipeline thread

`process` runs once per piped address on PowerShell's pipeline thread, the only thread that may write to the pipeline. It takes the address apart (`Target::parse`), and on the first record reads and checks what every record sends (`InvokeSecureFetch::outgoing`: the method, the header fields, the body) and builds the TLS configuration (`InvokeSecureFetch::tls_config`: `-RequirePostQuantum`'s version and groups, and the roots `-TrustedRoots` and `-RootCertificate` name, read once). It resolves `-OutFile` through PowerShell's own path resolution and asks .NET for the system proxy, since both need the session. Anything that cannot be sent is refused here, before any connection.

## On the worker thread

Each request then runs on a worker thread of its own (`exchange`), while the pipeline thread waits for it in 50 ms steps, asking at each whether the pipeline is stopping. A stop marks the request stopped, shuts its connection down, and ends the phase at once with `SecureFetchStopped`; the worker is not waited for and ends when the step it is blocked in returns.

The worker:

1. tries a connection kept from an earlier request for the same host, port and proxy, under `-KeepAlive`, whether that request was for an earlier piped address or was the redirect that led here;
2. otherwise resolves the host on a thread of its own, bounded by `-TimeoutSeconds` because the system resolver cannot be interrupted, and connects, or connects to the proxy and asks it for a tunnel with CONNECT;
3. completes the TLS handshake before anything else is written, so under `-RequirePostQuantum` a refused server has been sent nothing but the handshake; every new connection makes a full handshake, with session resumption off;
4. writes the request head, then the body in 64 KiB pieces, checking for a stop between them;
5. reads the status line and header section, skipping 1xx responses, and decides where the body goes: into memory, or into the `-OutFile` temporary file when the response is the one to be written;
6. reads the body as its framing says (Content-Length, chunked with trailer fields, or until close; none for HEAD, 204 and 304), through a decoder for each content coding, bounded by `-MaximumDecodedBytes`;
7. keeps the connection for the next request when `-KeepAlive` asks and the response allows it: HTTP/1.1, no `Connection: close`, and a body that ended where its framing said rather than at the connection's close.

Each read and write is bounded by `-TimeoutSeconds`; each read is reserved before it is kept, so a response too large for the allocator is `SecureFetchOutOfMemory` rather than the end of the session.

## Back on the pipeline thread

A redirect to follow starts the next request, with the method, body and credentials the rules in [How To Follow Redirects](How-To-Follow-Redirects.md) give. The last response becomes a `SecureFetch.Response`: `Headers` and `Trailers` as ordered dictionaries, `Content` decoded from `ContentBytes` by the WHATWG Encoding Standard's rules. A 4xx or 5xx is raised as `SecureFetchHttpStatus` carrying it, unless `-SkipHttpErrorCheck`; otherwise it is written, unless `-OutFile` took the body and `-PassThru` was not given.
