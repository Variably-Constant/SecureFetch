---
title: How To Send Methods, Headers And Bodies
weight: 1
---

`-Method`, `-Headers`, `-Body` and `-ContentType` shape the request. Source: `src/lib.rs` (`Outgoing`, `header_entries`, `payload_of`). The examples send synthetic bodies to postman-echo.com, an echo service that answers with JSON describing what it received.

## A method and a body

```powershell
$sent = Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body 'SecureFetch test' -Headers @{ 'X-Example' = '42' }
$echoed = $sent.Content | ConvertFrom-Json
$echoed.data
$echoed.headers.'content-type'
$echoed.headers.'x-example'
```

```text
SecureFetch test
text/plain; charset=utf-8
42
```

- `-Method` takes GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS, in any case, and sends it upper-cased; GET when not given.
- `-Body` takes a string, sent as UTF-8, or a byte array, sent as it is. It is always framed by `Content-Length`, with any method. A POST, PUT or PATCH without a body sends `Content-Length: 0`.
- Without `-ContentType`, a string body goes with `text/plain; charset=utf-8` and a byte array with `application/octet-stream`; nothing is sent without a body.

## A body of a given type

`-ContentType` is sent as given:

```powershell
$body = @{ name = 'SecureFetch test' } | ConvertTo-Json -Compress
$sent = Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body $body -ContentType 'application/json'
($sent.Content | ConvertFrom-Json).json.name
```

```text
SecureFetch test
```

A byte array goes as it is:

```powershell
$bytes = [System.Text.Encoding]::UTF8.GetBytes('SecureFetch test bytes')
$sent = Invoke-SecureFetch https://postman-echo.com/put -Method PUT -Body $bytes
$echoed = ($sent.Content | ConvertFrom-Json)
$echoed.headers.'content-type'
$echoed.headers.'content-length'
```

```text
application/octet-stream
22
```

A string body is always sent as UTF-8, so a Content-Type naming another charset, from `-ContentType` or from `-Headers`, is refused before any connection is made.

## Header fields

`-Headers` takes a dictionary: a hashtable, an `[ordered]` one, or any `IDictionary`. A value is a string, or an array of strings sent as one field line each. An entry named User-Agent, Accept or Accept-Encoding replaces the one the cmdlet sends, and an empty array leaves that field out:

```powershell
$headers = [ordered]@{ 'User-Agent' = 'SecureFetch-example/1.0'; 'Accept' = 'application/json'; 'X-Multi' = 'one', 'two' }
$echoed = (Invoke-SecureFetch https://postman-echo.com/get -Headers $headers).Content | ConvertFrom-Json
$echoed.headers.'user-agent'
$echoed.headers.accept
$echoed.headers.'x-multi'
```

```text
SecureFetch-example/1.0
application/json
one, two
```

(The echo server joins the two `X-Multi` lines into one value.)

## What is refused before connecting

A field name that is not a token, a field the cmdlet writes itself (Host, Content-Length, Transfer-Encoding, Connection, TE, Trailer, Upgrade, Keep-Alive, Proxy-Connection), a value carrying a control byte other than tab, and a value that is not a string or an array of strings are refused as `SecureFetchBadHeader`; a body of any other type is `SecureFetchBadBody`. Nothing is sent:

```powershell
Invoke-SecureFetch https://postman-echo.com/get -Headers @{ Host = 'example.com' } -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body 5 -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
```

```text
SecureFetchBadHeader,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
Host cannot be set through -Headers: SecureFetch writes the Host field itself
SecureFetchBadBody,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
-Body takes a string or a byte array, not a System.Int32
```

A field given twice, as Content-Type in `-Headers` beside `-ContentType` or Accept-Encoding in `-Headers` beside `-NoCompression`, is refused the same way, and the message quotes both values; a value of another type is named with its type:

```powershell
Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body 'SecureFetch test' -ContentType 'text/plain' -Headers @{ 'Content-Type' = 'text/csv' } -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].Exception.Message
Invoke-SecureFetch https://postman-echo.com/get -Headers @{ 'X-Retry' = 3 } -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].Exception.Message
```

```text
Content-Type is given both in -Headers, as "text/csv", and by -ContentType, as "text/plain"; give one of them
the X-Retry value is a System.Int32; a -Headers value is a string or an array of strings
```

## HEAD

A response to HEAD carries no body, whatever its fields announce:

```powershell
$head = Invoke-SecureFetch https://httpbin.org/bytes/1024 -Method HEAD
$head.Headers['Content-Length']
$head.ContentBytes.Length
```

```text
1024
0
```

## Sending again on a kept connection

Under `-KeepAlive`, when the server has closed a kept connection before answering, a GET, HEAD, OPTIONS, PUT or DELETE is sent once more on a new connection; a POST or PATCH is not sent twice and fails as `SecureFetchConnection`. See [How To Pipe Addresses And Keep Connections](How-To-Pipe-Addresses-And-Keep-Connections.md).
