---
title: How To Bound And Stop Requests
weight: 4
---

`-TimeoutSeconds` bounds each wait; a stop, such as Ctrl+C, ends the cmdlet at once. Source: `src/lib.rs` (`resolve`, `connect`, `Input`, `wait_on`, `Cancel`).

## -TimeoutSeconds

From 1 to 300, and 30 when not given. It bounds name resolution, the connection, and each read or write, separately: a response that keeps arriving, however slowly, is not cut off, but a server that goes quiet for longer than the bound is. Here a local listener accepts the connection and never answers:

```powershell
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
try {
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-SecureFetch "https://127.0.0.1:$($listener.LocalEndpoint.Port)/" -TimeoutSeconds 2 -ErrorAction SilentlyContinue -ErrorVariable failed
    $failed[0].FullyQualifiedErrorId
    $failed[0].Exception.Message
    'returned after ' + [math]::Round($clock.Elapsed.TotalSeconds, 1) + ' s'
} finally {
    $listener.Stop()
}
```

```text
SecureFetchTimeout,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
127.0.0.1 kept the connection waiting longer than 2 s
returned after 2 s
```

Name resolution runs on a thread of its own, since the system resolver cannot be interrupted, and is waited on for at most the bound: resolving a single-label name that does not exist ended as `SecureFetchTimeout` after 1013 ms in PowerShell 7 and 1051 ms in Windows PowerShell with `-TimeoutSeconds 1`, where the system resolver took 2692 and 2710 ms to report the name missing.

## Stopping

Each request runs on a worker thread while the pipeline thread waits for it in 50 ms steps, asking at each whether the pipeline is stopping, so a stop ends the cmdlet whatever the request is waiting on. Measured through `PowerShell.Stop()`, as Ctrl+C would stop it: requests blocked in a TLS handshake a local server never answered, in a response postman-echo.com delayed by 10 s, in a connection attempt to 10.255.255.1, and in name resolution returned from `Stop()` after 30, 15, 30 and 61 ms in PowerShell 7, and after 46, 30, 14 and 3 ms in Windows PowerShell, each pipeline left Stopped with PowerShell's own `PipelineStopped` record in its error stream.

A stopped worker is not waited for. On Windows, shutting a socket down does not end a receive already blocked on it (measured on Windows 11 build 26200), so that thread and its connection end when the server sends or closes, or when that step's own `-TimeoutSeconds` wait runs out; a connection attempt in progress also runs to its own wait. An `-OutFile` download's temporary file is deleted when that thread ends.
