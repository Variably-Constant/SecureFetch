---
title: How To Set Timeouts And Stop Requests
weight: 4
aliases:
  - /docs/how-to/how-to-bound-and-stop-requests/
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
returned after 2.1 s
```

Name resolution runs on a thread of its own, since the system resolver cannot be interrupted, and is waited on for at most the bound: resolving a single-label name that does not exist ended as `SecureFetchTimeout` after 1040 to 1063 ms in PowerShell 7 and 1039 to 1065 ms in Windows PowerShell with `-TimeoutSeconds 1`, three runs in each, where the system resolver took 1237 to 1264 ms to report such a name missing.

## Stopping

Each request runs on a worker thread while the pipeline thread waits for it. A stop wakes the pipeline thread at once and ends the cmdlet, whatever the request is waiting on. Measured through `PowerShell.Stop()`, as Ctrl+C would stop it, five times in each host, a request blocked in any of four places returned from `Stop()` within 0.5 ms: a TLS handshake a local server never answered, a response postman-echo.com delayed by 10 s, a connection attempt to 10.255.255.1, and resolving a single-label name that does not exist. The first stop in each process took longer, 2.9 ms in PowerShell 7 and 23 ms in Windows PowerShell. Each pipeline was left Stopped, and `EndInvoke` raised PowerShell's `PipelineStoppedException`. On average 1.9 of the machine's 24 logical processors were busy during the PowerShell 7 runs, and 3.4 during the Windows PowerShell ones.

A stopped worker is not waited for. On Windows, shutting a socket down does not end a receive already blocked on it (measured on Windows 11 build 26200), so that thread and its connection end when the server sends or closes, or when that step's own `-TimeoutSeconds` wait runs out; a connection attempt in progress also runs to its own wait. An `-OutFile` download's temporary file is deleted when that thread ends.
