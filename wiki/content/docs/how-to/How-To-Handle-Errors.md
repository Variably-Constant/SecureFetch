---
title: How To Handle Errors
weight: 2
---

Every failure is an error record whose id and category say what failed. Source: `src/lib.rs`; the ids are listed in the [Error Reference](Error-Reference.md).

## Read the id

The id is the first part of `FullyQualifiedErrorId`:

```powershell
Invoke-SecureFetch http://example.com/ -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].CategoryInfo.Category
$failed[0].Exception.Message
```

```text
SecureFetchNotHttps,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
InvalidArgument
http://example.com/ is not an https:// address
```

An error record for one address does not stop the pipeline: the next piped address is still requested.

## A 4xx or 5xx status

A 4xx or 5xx status is an error record too, `SecureFetchHttpStatus` (InvalidResult), as `Invoke-WebRequest` raises it in PowerShell 7, and the record's `TargetObject` is the whole response. `-SkipHttpErrorCheck` writes such a response instead:

```powershell
$missing = 'https://pq.cloudflareresearch.com/cdn-cgi/securefetch-no-such-page'
Invoke-SecureFetch $missing -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
$failed[0].TargetObject.StatusCode
(Invoke-SecureFetch $missing -SkipHttpErrorCheck).StatusDescription
```

```text
SecureFetchHttpStatus,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
https://pq.cloudflareresearch.com/cdn-cgi/securefetch-no-such-page answered 404 Not Found
404
Not Found
```

Every other final status is written as a response, a 3xx among them when it is not a redirect to follow: a 300 or 304, a redirect without a Location, or any redirect under `-MaximumRedirection 0`. A redirect that is not followed because it leads to an address that is not https://, or would pass `-MaximumRedirection`, is an error record carrying the redirect response, as [How To Follow Redirects](How-To-Follow-Redirects.md) shows.

## Stop on the first failure

`-ErrorAction Stop` makes the record a terminating error that `try`/`catch` receives:

```powershell
try {
    Invoke-SecureFetch https://expired.badssl.com/ -ErrorAction Stop
} catch {
    $_.FullyQualifiedErrorId
    $_.Exception.Message
}
```

```text
SecureFetchTls,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
the TLS exchange with expired.badssl.com failed: invalid peer certificate: certificate expired: verification time 1790665212 (UNIX), but certificate is not valid after 1428883199 (361782013 seconds ago)
```

(Windows PowerShell ran it 19 seconds later, so its two times were 19 higher.)

## Which failures happen before anything is sent

These are refused before any connection is made, so nothing reaches a server: an address that cannot be sent (`SecureFetchNotHttps`, `SecureFetchUserInfo`, `SecureFetchBadHost`, `SecureFetchBadPort`), a header or body that cannot be sent (`SecureFetchBadHeader`, `SecureFetchBadBody`), an `-OutFile` path that cannot be used (`SecureFetchBadOutFile`), a `-Proxy` that cannot be used (`SecureFetchProxy`, InvalidArgument), and roots that cannot be used (`SecureFetchRootStore`): a choice that trusts nothing or names None beside a source, the Windows store where there is none or it cannot be opened, and a `-RootCertificate` rustls cannot take. Under `-RequirePostQuantum`, a server that cannot agree TLS 1.3 with X25519MLKEM768 is sent nothing but the handshake.
