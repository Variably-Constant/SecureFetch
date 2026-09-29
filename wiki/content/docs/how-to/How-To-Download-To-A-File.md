---
title: How To Download To A File
weight: 7
---

`-OutFile` writes the body to a file as it arrives, in pieces of up to 64 KiB, instead of holding it in memory. Source: `src/lib.rs` (`out_file_path`, `FileSink`, `Job::to_file`).

```powershell
Invoke-SecureFetch https://raw.githubusercontent.com/PowerShell/PowerShell/v7.4.0/assets/Powershell_256.png -OutFile .\Powershell_256.png
(Get-FileHash .\Powershell_256.png -Algorithm SHA256).Hash
```

```text
1734E52435CF6CDDDEF2B340039986A8487FDD1CEAED44D1B93B39293E4A9DD4
```

That hash is the one `Invoke-WebRequest` gave for the same file.

## The path

The path is resolved by PowerShell's own path resolution, as `Invoke-WebRequest` resolves it: a relative path against the current location, and a drive such as `TestDrive:\` to the folder it maps. It must resolve, be a file system path, be in a folder that exists, and not be a folder itself; anything else is `SecureFetchBadOutFile` (InvalidArgument) before any connection is made. A folder that exists but cannot be written to is found only when the temporary file is created, after the response has begun, as `SecureFetchWriteFailed`.

## Nothing written, unless -PassThru

With `-OutFile` nothing goes to the pipeline. `-PassThru` writes the response as well, its `Content` and `ContentBytes` empty since the body went to the file:

```powershell
$passed = Invoke-SecureFetch https://raw.githubusercontent.com/PowerShell/PowerShell/v7.4.0/assets/Powershell_256.png -OutFile .\again.png -PassThru
$passed | Format-List StatusCode, Content, ContentBytes
(Get-Item .\again.png).Length
```

```text
StatusCode   : 200
Content      :
ContentBytes : {}

9494
```

## When the target is replaced

The body goes to a temporary file in the target's folder, named after it with 16 random hexadecimal digits and `.securefetch-partial` added. Only once the whole body has arrived is the temporary file made durable and renamed over the target, which replaces a file already there. On a response cut short, a failure, a timeout or a stop, the temporary file is deleted and the target is left as it was; a failure to create, write or rename it is `SecureFetchWriteFailed` (WriteError). On Windows, a target another handle holds open without delete sharing cannot be renamed over, so it is `SecureFetchWriteFailed` and keeps its content; on Linux, FreeBSD and macOS the rename replaces it, and the open handle goes on reading the content it opened. The suite checks each: the first on Windows, the second on the others.

- A redirect that is followed writes nothing: only the last response's body goes to the file.
- A 4xx or 5xx raised as `SecureFetchHttpStatus` writes nothing, and the record's `TargetObject` carries the body in `Content` and `ContentBytes`. With `-SkipHttpErrorCheck` such a body goes to the file.
- A HEAD, or an empty body, replaces the target with an empty file.
- Several piped addresses with one `-OutFile` replace the file in turn, so the last one wins.
- `-MaximumDecodedBytes` bounds a body sent with a content coding here as in memory.
- After a stop, the temporary file is deleted when the request's own thread ends, which on Windows can be up to `-TimeoutSeconds` later.
