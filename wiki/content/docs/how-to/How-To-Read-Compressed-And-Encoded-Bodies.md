---
title: How To Read Compressed And Encoded Bodies
weight: 10
---

How a body travels and how it becomes `Content` and `ContentBytes`. Source: `src/lib.rs` (`content_codings`, `decode`, `framing`, `Body`, `text_of`, `charset_label`).

## Content codings

Requests ask for `gzip, deflate, br, zstd`, and bodies sent in them are decoded as they arrive, through flate2, brotli-decompressor and ruzstd. `-NoCompression` asks for `identity` alone. A body that decodes to more than `-MaximumDecodedBytes` (256 MiB when not given) is `SecureFetchTooLarge` (LimitsExceeded):

```powershell
$r = Invoke-SecureFetch https://httpbin.org/gzip
$r.Headers['Content-Encoding']
($r.Content | ConvertFrom-Json).gzipped
$plain = Invoke-SecureFetch https://httpbin.org/headers -NoCompression
($plain.Content | ConvertFrom-Json).headers.'Accept-Encoding'
Invoke-SecureFetch https://httpbin.org/gzip -MaximumDecodedBytes 100 -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
```

```text
gzip
True
identity
SecureFetchTooLarge,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
the gzip body from httpbin.org decodes to more than 100 bytes, the -MaximumDecodedBytes bound
```

- `deflate` is read as the zlib format RFC 9110 defines, or as raw deflate when the first two bytes are not a zlib header, since some servers send that.
- `x-gzip` is read as gzip, and coding names match without regard to case.
- Several codings stack in the order the server applied them.
- A body whose bytes do not decode under its coding is `SecureFetchBadResponse`; a coding other than these (and identity) is `SecureFetchEncoding` (NotImplemented).
- `-MaximumDecodedBytes` bounds only a body sent with a content coding; one sent without is bounded by memory alone, or by the disk under `-OutFile`.

## Content and ContentBytes

`ContentBytes` is the body's bytes, its codings undone. `Content` is those bytes as text, decoded the way the WHATWG Encoding Standard has a browser decode them, through encoding_rs: a byte order mark at the start picks UTF-8, UTF-16LE or UTF-16BE; otherwise the Content-Type's charset label, looked up in the standard's table (so `iso-8859-1` and `latin1` read as windows-1252, and `utf-16` as UTF-16LE); otherwise UTF-8. A sequence the encoding cannot read becomes U+FFFD, so a binary body belongs in `ContentBytes`:

```powershell
$page = Invoke-SecureFetch https://httpbin.org/encoding/utf8
$page.Headers['Content-Type']
$page.ContentBytes.Length
$page.Content.Length
$png = Invoke-SecureFetch https://httpbin.org/image/png
($png.ContentBytes[0..7] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
```

```text
text/html; charset=utf-8
14239
7808
89 50 4E 47 0D 0A 1A 0A
```

## Framing, chunked bodies and trailers

A body ends where its Content-Length or chunked framing says, so a server that keeps the connection open is not waited for; only a body with neither runs until the connection closes. Chunked bodies are decoded, and their trailer fields land in `Trailers`, shaped like `Headers`:

```powershell
$stream = Invoke-SecureFetch https://postman-echo.com/stream/3
$stream.Headers['Transfer-Encoding']
$stream.Trailers.Count
($stream.Content -split "`n").Count
```

```text
chunked
0
37
```

Interim 1xx responses are read and dropped, 204 and 304 responses and responses to HEAD carry no body, and a 101 is refused since no upgrade is asked for. A response cut short of its framing is `SecureFetchTruncated`; framing that cannot be trusted, such as Transfer-Encoding beside Content-Length, is `SecureFetchBadResponse`.
