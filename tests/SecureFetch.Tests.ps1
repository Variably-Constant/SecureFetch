# Written in the syntax Pester 5 and Pester 6 share; runs in pwsh and in
# Windows PowerShell. PWRS_MODULE points at the built module folder.
#
# The module makes its own TLS connections through rustls. The Contexts
# that talk to pq.cloudflareresearch.com, postman-echo.com, httpbin.org,
# github.com, raw.githubusercontent.com, www.messenger.com, www.google.com,
# badssl.com and www.debian.org need the network, and each test marks
# itself skipped when its host's port 443 cannot be reached, so a machine
# without a route out still passes. badssl.com drops a connection now and
# then, so a request to it that fails as SecureFetchConnection is made once
# more, with a RETRY line written to the host; every other result is judged
# as the first attempt's would be. Only postman-echo.com, an echo
# service, is sent anything but a GET or a HEAD: POST, PUT, PATCH, DELETE
# and OPTIONS requests, header values, and synthetic bodies built from
# "SecureFetch test" and a new GUID; httpbin.org is sent two of those
# bodies, by the redirect tests that POST through its redirect-to endpoint
# on their way to postman-echo.com. Every request to another public host
# is a GET or a HEAD, and every other test stays on this machine. The tests that read the Windows certificate store, the one that
# reads this process's connections through Get-NetTCPConnection, and the
# one that needs Windows to refuse a rename over a file held open run on
# Windows alone; the one that shows the rename succeeding, and the one that
# shows -TrustedRoots Windows refused, run everywhere else. The flag is set
# at discovery, since $IsWindows does not exist in Windows PowerShell.
$script:onWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
BeforeAll {
    $module = $env:PWRS_MODULE
    if (-not $module) { throw 'PWRS_MODULE is not set' }
    Import-Module (Join-Path $module 'SecureFetch.psd1') -Force -ErrorAction Stop

    # Whether a TCP connection to port 443 of $name opens within five
    # seconds. A name that does not resolve, or a refusal, is a no.
    function script:Test-Port443([string] $name) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            return $client.ConnectAsync($name, 443).Wait(5000)
        } catch [System.AggregateException], [System.Net.Sockets.SocketException] {
            return $false
        } finally {
            $client.Dispose()
        }
    }

    # Runs Invoke-SecureFetch with $Parameters against a badssl.com address
    # and returns what it wrote and its error records. A first attempt that
    # fails as SecureFetchConnection, as one whose connection the server
    # drops does, is made once more, after a line naming the address, the
    # time, the host's version and that attempt's message is written to the
    # host, so a run's output shows each retry. Whatever else either attempt
    # gives goes back to the test to judge.
    function script:Invoke-BadSsl([hashtable] $Parameters) {
        $written = @(Invoke-SecureFetch @Parameters -ErrorAction SilentlyContinue -ErrorVariable failed)
        if ($failed.Count -and $failed[0].FullyQualifiedErrorId -like 'SecureFetchConnection,*') {
            Write-Host ('RETRY ' + $Parameters.Uri + ' at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') + ' in PowerShell ' + $PSVersionTable.PSVersion + ' after SecureFetchConnection: ' + $failed[0].Exception.Message)
            $written = @(Invoke-SecureFetch @Parameters -ErrorAction SilentlyContinue -ErrorVariable failed)
        }
        [pscustomobject]@{ Written = $written; Failed = @($failed) }
    }

    $script:endpoint = 'pq.cloudflareresearch.com'
    $script:online = Test-Port443 $endpoint
    $script:badssl = Test-Port443 'expired.badssl.com'

    # A CONNECT proxy for the tests, run in a runspace of its own: it takes
    # one connection at a time on $Listener and reads the request head. When
    # the head lacks the Proxy-Authorization value $Expected it answers 407;
    # otherwise it connects to the host and port CONNECT names, answers 200,
    # and relays bytes both ways until either side closes. Each request line
    # it reads goes into $Log.
    $script:proxyScript = {
        param($Listener, $Log, $Expected)
        while ($true) {
            try {
                $client = $Listener.AcceptTcpClient()
            } catch {
                $Log.Enqueue('STOPPED ' + $_.Exception.Message)
                return
            }
            $stream = $client.GetStream()
            $head = [System.Text.StringBuilder]::new()
            $one = New-Object byte[] 1
            while (-not $head.ToString().EndsWith("`r`n`r`n")) {
                if ($stream.Read($one, 0, 1) -le 0) { break }
                $null = $head.Append([char]$one[0])
            }
            $lines = $head.ToString() -split "`r`n"
            $Log.Enqueue($lines[0])
            if ($lines -notcontains ('Proxy-Authorization: ' + $Expected)) {
                $reply = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 407 Proxy Authentication Required`r`nProxy-Authenticate: Basic realm=`"SecureFetch test`"`r`nContent-Length: 0`r`nConnection: close`r`n`r`n")
                $stream.Write($reply, 0, $reply.Length)
                $client.Dispose()
                continue
            }
            $hostPort = ($lines[0] -split ' ')[1]
            $colon = $hostPort.LastIndexOf(':')
            $server = [System.Net.Sockets.TcpClient]::new()
            $server.Connect($hostPort.Substring(0, $colon).Trim('[', ']'), [int]$hostPort.Substring($colon + 1))
            $reply = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 Connection Established`r`n`r`n")
            $stream.Write($reply, 0, $reply.Length)
            $upstream = $server.GetStream()
            $up = $stream.CopyToAsync($upstream)
            $down = $upstream.CopyToAsync($stream)
            $null = [System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]@($up, $down))
            $server.Dispose()
            $client.Dispose()
        }
    }
}

Describe 'Invoke-SecureFetch' {
    It 'declares SecureFetch.Response as its output' {
        (Get-Command Invoke-SecureFetch).OutputType.Name | Should -Be 'SecureFetch.Response'
    }

    It 'takes its manifest author, company, copyright, description, links, icon, release notes and tags from Cargo.toml' {
        $manifest = Import-PowerShellDataFile (Join-Path $env:PWRS_MODULE 'SecureFetch.psd1')
        $manifest.Author | Should -BeExactly 'Mark Newton'
        $manifest.CompanyName | Should -BeExactly 'Variably Constant'
        $manifest.Copyright | Should -BeExactly '(c) 2026 Mark Newton'
        $manifest.Description | Should -BeExactly 'HTTPS requests from PowerShell over TLS 1.3 with the X25519MLKEM768 post-quantum hybrid key exchange, from rustls inside the module. Invoke-SecureFetch writes a SecureFetch.Response for each https:// address, with the protocol version, key exchange and cipher suite its handshake agreed; -RequirePostQuantum refuses a server that cannot agree X25519MLKEM768 before the request is sent. Certificates are verified against the bundled Mozilla roots and, on Windows, the Windows store, or a choice of roots. It sends GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS with headers and bodies, follows redirects to https:// addresses only, downloads to a file, goes through HTTP proxies by CONNECT, decodes gzip, deflate, br and zstd bodies, and keeps connections for the next request to the same host. Invoke-WebRequest and every other module keep the host''s own TLS stack. Bound directly to Rust with PoWerRuSt (pwrs), Rust bindings for writing PowerShell binary modules in the spirit of PyO3: the cmdlet is the library, not a wrapper over a command line. Windows x64, Linux x64 (glibc 2.28 and newer), macOS arm64 and FreeBSD x64 in one module, on PowerShell 7.4 or later and, on Windows, Windows PowerShell 5.1. Source and issues at https://github.com/Variably-Constant/SecureFetch; the binding framework at https://github.com/Variably-Constant/PWRS and https://crates.io/crates/PoWerRuSt.'
        $manifest.PrivateData.PSData.ProjectUri | Should -Be 'https://github.com/Variably-Constant/SecureFetch'
        $manifest.PrivateData.PSData.LicenseUri | Should -Be 'https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE'
        $manifest.PrivateData.PSData.IconUri | Should -Be 'https://raw.githubusercontent.com/Variably-Constant/PWRS/main/assets/PWRS.png'
        $manifest.PrivateData.PSData.ReleaseNotes | Should -BeExactly 'The first release: Invoke-SecureFetch. What is in it: https://github.com/Variably-Constant/SecureFetch/blob/main/CHANGELOG.md'
        foreach ($tag in 'powershell', 'tls', 'tls13', 'post-quantum', 'mlkem', 'rustls', 'https', 'Windows', 'Linux', 'MacOS', 'FreeBSD') {
            $manifest.PrivateData.PSData.Tags | Should -Contain $tag
        }
    }

    It 'refuses an address that is not https, by position and from the pipeline' {
        { Invoke-SecureFetch 'http://example.com/' -ErrorAction Stop } | Should -Throw '*not an https:// address*'
        { 'ftp://example.com/' | Invoke-SecureFetch -ErrorAction Stop } | Should -Throw '*not an https:// address*'
        Invoke-SecureFetch 'http://example.com/' -ErrorAction SilentlyContinue -ErrorVariable failed
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchNotHttps,*'
        $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
    }

    It 'refuses a port that is not a number' {
        { Invoke-SecureFetch 'https://example.com:tls/' -ErrorAction Stop } | Should -Throw '*is not a port*'
        Invoke-SecureFetch 'https://example.com:tls/' -ErrorAction SilentlyContinue -ErrorVariable failed
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadPort,*'
    }

    It 'refuses an address with no host or with user information' {
        { Invoke-SecureFetch 'https:///index.html' -ErrorAction Stop } | Should -Throw '*names no host*'
        { Invoke-SecureFetch 'https://user@example.com/' -ErrorAction Stop } | Should -Throw '*user information*'
        Invoke-SecureFetch 'https://user@example.com/' -ErrorAction SilentlyContinue -ErrorVariable failed
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchUserInfo,*'
    }

    It 'quotes an address it refuses with the user information masked, so no password reaches the record' {
        foreach ($case in @(
                @{ Uri = 'https://user:secret@example.com/'; Id = 'SecureFetchUserInfo'; Quoted = 'https://***@example.com/ ' },
                @{ Uri = 'http://user:secret@example.com/'; Id = 'SecureFetchNotHttps'; Quoted = 'http://***@example.com/ ' })) {
            Invoke-SecureFetch $case.Uri -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike ($case.Id + ',*')
            $failed[0].Exception.Message.StartsWith($case.Quoted) | Should -BeTrue
            $failed[0].Exception.Message | Should -Not -BeLike '*secret*'
        }
        Invoke-SecureFetch 'https://127.0.0.1:1/' -Proxy 'http://user:secret@127.0.0.1:3128' -TimeoutSeconds 5 -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchProxy,*'
        $failed[0].Exception.Message.StartsWith('-Proxy http://***@127.0.0.1:3128 ') | Should -BeTrue
        $failed[0].Exception.Message | Should -Not -BeLike '*secret*'
    }

    It 'refuses a timeout outside 1 to 300 seconds before it connects' {
        { Invoke-SecureFetch 'https://example.com/' -TimeoutSeconds 0 } | Should -Throw
        { Invoke-SecureFetch 'https://example.com/' -TimeoutSeconds 301 } | Should -Throw
    }

    It 'refuses a redirect limit outside 0 to 50 before it connects' {
        (Get-Command Invoke-SecureFetch).Parameters['MaximumRedirection'].ParameterType.FullName | Should -Be 'System.Int32'
        { Invoke-SecureFetch 'https://127.0.0.1:1/' -MaximumRedirection -1 } | Should -Throw
        { Invoke-SecureFetch 'https://127.0.0.1:1/' -MaximumRedirection 51 } | Should -Throw
    }

    It 'takes the seven methods, in any case, and a dictionary of headers' {
        $parameters = (Get-Command Invoke-SecureFetch).Parameters
        $set = $parameters['Method'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $set.ValidValues -join ',' | Should -Be 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS'
        $set.IgnoreCase | Should -BeTrue
        $parameters['Headers'].ParameterType.FullName | Should -Be 'System.Collections.IDictionary'
        $parameters['Body'].ParameterType.FullName | Should -Be 'System.Object'
        $parameters['ContentType'].ParameterType.FullName | Should -Be 'System.String'
        { Invoke-SecureFetch 'https://127.0.0.1:1/' -Method TRACE -ErrorAction Stop } | Should -Throw
    }

    # Nothing listens on 127.0.0.1 port 1, so a request that got as far as
    # connecting would fail as SecureFetchConnect instead of being refused.
    It 'refuses a header that would break the request, before it connects' {
        $cases = @(
            @{ Headers = @{ Host = 'example.com' } },
            @{ Headers = @{ 'Transfer-Encoding' = 'chunked' } },
            @{ Headers = @{ 'Bad Name' = 'x' } },
            @{ Headers = @{ 'X-Test' = "a`r`nInjected: yes" } },
            @{ Headers = @{ 'X-Test' = 'fine', "a`nb" } },
            @{ Body = 'x'; ContentType = "text/plain`nX-Injected: yes" },
            @{ Body = 'x'; ContentType = 'text/plain; charset=iso-8859-1' }
        )
        foreach ($case in $cases) {
            Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 @case -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadHeader,*'
            $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
        }
    }

    It 'refuses a field given twice, or a value that is not a string, naming what was given' {
        $cases = @(
            @{ Splat = @{ Body = 'x'; ContentType = 'text/plain'; Headers = @{ 'Content-Type' = 'text/csv' } }; Named = '"text/csv"', '"text/plain"' },
            @{ Splat = @{ NoCompression = $true; Headers = @{ 'Accept-Encoding' = 'gzip' } }; Named = '"gzip"', '"identity"' },
            @{ Splat = @{ Headers = @{ 'X-Retry' = 3 } }; Named = 'X-Retry', 'System.Int32' }
        )
        foreach ($case in $cases) {
            $splat = $case.Splat
            Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 @splat -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadHeader,*'
            $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
            foreach ($named in $case.Named) {
                $failed[0].Exception.Message | Should -BeLike "*$named*"
            }
        }
    }

    It 'refuses a body that is neither a string nor a byte array, before it connects' {
        foreach ($body in 5, @{ a = 1 }, (1, 2, 3)) {
            Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -Body $body -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadBody,*'
            $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
        }
    }

    It 'refuses a -Proxy it cannot use, before it connects' {
        $cases = @(
            @{ Splat = @{ Proxy = 'https://127.0.0.1:3128' }; Named = '*https://*' },
            @{ Splat = @{ Proxy = 'http://user:secret@127.0.0.1:3128' }; Named = '*-ProxyCredential*' },
            @{ Splat = @{ Proxy = 'http://127.0.0.1:3128'; NoProxy = $true }; Named = '*-NoProxy*' },
            @{ Splat = @{ Proxy = 'http://127.0.0.1:0' }; Named = '*port 0*' }
        )
        foreach ($case in $cases) {
            $splat = $case.Splat
            Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 @splat -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchProxy,*'
            $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
            $failed[0].Exception.Message | Should -BeLike $case.Named
        }
    }

    It 'reports a connection nobody accepts as an error' {
        { Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -ErrorAction Stop } | Should -Throw
        Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -ErrorAction SilentlyContinue -ErrorVariable failed
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchConnect,*'
        $failed[0].CategoryInfo.Category | Should -Be 'ConnectionError'
    }

    It 'reports a host name that does not resolve as an error' {
        Invoke-SecureFetch 'https://securefetch.invalid/' -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
        $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchResolve,*'
        $failed[0].CategoryInfo.Category | Should -Be 'ConnectionError'
    }

    It 'reports a server that accepts and never answers as a timeout' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = $listener.LocalEndpoint.Port
            Invoke-SecureFetch "https://127.0.0.1:$port/" -TimeoutSeconds 1 -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTimeout,*'
            $failed[0].CategoryInfo.Category | Should -Be 'OperationTimeout'
        } finally {
            $listener.Stop()
        }
    }

    Context 'when the pipeline is stopped' {
        It 'ends a request whose handshake waits on a server that never answers, within about a second' {
            # The listener takes the connection and reads the client hello,
            # so the module is then blocked reading for a server hello that
            # never comes. The request runs in a runspace of its own so this
            # thread can stop it the way Ctrl+C does, through StopProcessing.
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $runspace = [runspacefactory]::CreateRunspace()
            $runspace.Open()
            $shell = [powershell]::Create()
            $shell.Runspace = $runspace
            $server = $null
            try {
                $port = $listener.LocalEndpoint.Port
                $null = $shell.AddCommand('Import-Module').AddParameter('Name', (Join-Path $env:PWRS_MODULE 'SecureFetch.psd1')).AddStatement()
                $null = $shell.AddCommand('Invoke-SecureFetch').AddParameter('Uri', "https://127.0.0.1:$port/").AddParameter('TimeoutSeconds', 60)
                $null = $shell.BeginInvoke()
                $accept = $listener.AcceptTcpClientAsync()
                if (-not $accept.Wait(30000)) {
                    throw ('the module did not connect within 30 s: ' + (($shell.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '))
                }
                $server = $accept.Result
                $stream = $server.GetStream()
                $stream.ReadTimeout = 10000
                $record = New-Object byte[] 5
                $stream.Read($record, 0, 5) | Should -BeGreaterThan 0
                $record[0] | Should -Be 0x16
                Start-Sleep -Milliseconds 300
                $clock = [System.Diagnostics.Stopwatch]::StartNew()
                $shell.Stop()
                $clock.Stop()
                $shell.InvocationStateInfo.State | Should -Be 'Stopped'
                $clock.Elapsed.TotalSeconds | Should -BeLessThan 1.5
            } finally {
                if ($server) { $server.Dispose() }
                $listener.Stop()
                $shell.Dispose()
                $runspace.Dispose()
            }
        }
    }

    Context 'against servers whose certificates do not verify' {
        It 'refuses an expired certificate, one for another name and one from an unknown root' {
            if (-not $badssl) {
                Set-ItResult -Skipped -Because 'expired.badssl.com port 443 cannot be reached from here'
                return
            }
            foreach ($name in 'expired.badssl.com', 'wrong.host.badssl.com', 'untrusted-root.badssl.com') {
                $result = Invoke-BadSsl @{ Uri = "https://$name/" }
                $result.Written | Should -BeNullOrEmpty
                $result.Failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTls,*'
                $result.Failed[0].CategoryInfo.Category | Should -Be 'SecurityError'
                $result.Failed[0].Exception.Message | Should -BeLike '*certificate*'
            }
        }
    }

    Context 'against a server that sends a chunked body' {
        BeforeAll {
            $script:echo = 'postman-echo.com'
            $script:echoOnline = Test-Port443 $echo
        }

        It 'decodes a chunked body, ending the read where the body ends' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            # Under -KeepAlive the server keeps the connection open after
            # the body, so a read that waited for the close would run out
            # the 20-second wait instead of returning.
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            $stream = Invoke-SecureFetch "https://$echo/stream/3" -KeepAlive -TimeoutSeconds 20 -ErrorAction Stop
            $clock.Stop()
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 10
            $stream.StatusCode | Should -Be 200
            $stream.Headers['Transfer-Encoding'] | Should -Be 'chunked'
            $stream.Headers.Contains('Content-Length') | Should -BeFalse
            $stream.Content | Should -Match '"url": "https://postman-echo.com/stream/3"\s*\}\s*$'
            $stream.Trailers.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
            $stream.Trailers.Count | Should -Be 0
        }
    }

    Context 'against a server that echoes each request' {
        BeforeAll {
            $script:echo = 'postman-echo.com'
            $script:echoOnline = Test-Port443 $echo
            $script:guid = [guid]::NewGuid().ToString()
        }

        It 'sends POST, PUT, PATCH and DELETE with a string body, as UTF-8 text framed by its length' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            foreach ($method in 'POST', 'PUT', 'PATCH', 'DELETE') {
                $body = "SecureFetch test $guid $method caf$([char]0xE9)"
                $r = Invoke-SecureFetch "https://$echo/$($method.ToLowerInvariant())" -Method $method -Body $body -ErrorAction Stop
                $r.StatusCode | Should -Be 200
                $json = $r.Content | ConvertFrom-Json
                $json.data | Should -BeExactly $body
                $json.headers.'content-type' | Should -Be 'text/plain; charset=utf-8'
                $json.headers.'content-length' | Should -Be ([string][System.Text.Encoding]::UTF8.GetByteCount($body))
            }
        }

        It 'sends a byte array as it is, as application/octet-stream unless -ContentType names another type' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            $json = (Invoke-SecureFetch "https://$echo/post" -Method POST -Body ([byte[]](0..255)) -ErrorAction Stop).Content | ConvertFrom-Json
            $json.headers.'content-type' | Should -Be 'application/octet-stream'
            $json.headers.'content-length' | Should -Be '256'
            $json.data.type | Should -Be 'Buffer'
            ($json.data.data -join ',') | Should -Be ((0..255) -join ',')
            $sent = [System.Text.Encoding]::UTF8.GetBytes('{"securefetch":"' + $guid + '"}')
            $typed = (Invoke-SecureFetch "https://$echo/post" -Method POST -Body $sent -ContentType 'application/json' -ErrorAction Stop).Content | ConvertFrom-Json
            $typed.headers.'content-type' | Should -Be 'application/json'
            $typed.json.securefetch | Should -Be $guid
        }

        It 'sends the header fields given, replacing User-Agent and Accept, one line per array element' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            $headers = [ordered]@{ 'User-Agent' = "SecureFetch-Test/$guid"; Accept = 'application/json'; 'X-Multi' = 'one', 'two'; 'X-SecureFetch-Test' = $guid }
            $json = (Invoke-SecureFetch "https://$echo/get" -Headers $headers -ErrorAction Stop).Content | ConvertFrom-Json
            $json.headers.'user-agent' | Should -Be "SecureFetch-Test/$guid"
            $json.headers.accept | Should -Be 'application/json'
            $json.headers.'x-multi' | Should -Be 'one, two'
            $json.headers.'x-securefetch-test' | Should -Be $guid
            $dropped = (Invoke-SecureFetch "https://$echo/get" -Headers @{ Accept = @() } -ErrorAction Stop).Content | ConvertFrom-Json
            $dropped.headers.PSObject.Properties.Name | Should -Not -Contain 'accept'
        }

        It 'sends the method upper-cased, and Content-Length: 0 with a POST that has no body' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$echo/post" -Method post -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            ($r.Content | ConvertFrom-Json).headers.'content-length' | Should -Be '0'
        }

        It 'sends OPTIONS' {
            if (-not $echoOnline) {
                Set-ItResult -Skipped -Because "$echo port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$echo/get" -Method OPTIONS -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            ($r.Headers['Allow'] -join ',') -split ',' | Should -Contain 'GET'
        }
    }

    Context 'against servers that redirect' {
        BeforeAll {
            $script:bin = 'httpbin.org'
            $script:binOnline = Test-Port443 $bin
            $script:hub = 'github.com'
            $script:hubOnline = Test-Port443 $hub
            $script:echo = 'postman-echo.com'
            $script:echoOnline = Test-Port443 $echo
            $script:guid = [guid]::NewGuid().ToString()
        }

        It 'follows relative redirects, naming the final address and each address followed' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$bin/redirect/2" -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            $r.Uri | Should -Be "https://$bin/redirect/2"
            $r.FinalUri | Should -Be "https://$bin/get"
            $r.Redirects.GetType().FullName | Should -Be 'System.String[]'
            $r.Redirects -join ' ' | Should -Be "https://$bin/relative-redirect/1 https://$bin/get"
            ($r.Content | ConvertFrom-Json).url | Should -Be "https://$bin/get"
        }

        It 'follows an absolute redirect' {
            if (-not $hubOnline) {
                Set-ItResult -Skipped -Because "$hub port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$hub/PowerShell/PowerShell/releases/latest" -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            $r.FinalUri | Should -BeLike "https://$hub/PowerShell/PowerShell/releases/tag/v*"
            $r.Redirects.Count | Should -Be 1
        }

        It 'writes a redirect as it is under -MaximumRedirection 0' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$bin/redirect/2" -MaximumRedirection 0 -ErrorAction Stop
            $r.StatusCode | Should -Be 302
            $r.Headers['Location'] | Should -Be '/relative-redirect/1'
            $r.FinalUri | Should -Be "https://$bin/redirect/2"
            $r.Redirects.Count | Should -Be 0
        }

        It 'refuses a redirect to an http:// address, carrying the redirect' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            Invoke-SecureFetch "https://$bin/redirect-to?url=http://example.com/" -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchRedirectNotHttps,*'
            $failed[0].CategoryInfo.Category | Should -Be 'SecurityError'
            $failed[0].TargetObject.StatusCode | Should -Be 302
            $failed[0].TargetObject.Headers['Location'] | Should -Be 'http://example.com/'
        }

        It 'refuses an https Location that cannot be sent as a bad response, naming it and carrying the redirect' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            Invoke-SecureFetch "https://$bin/redirect-to?url=https%3A%2F%2Fuser%40example.com%2F" -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadResponse,*'
            $failed[0].CategoryInfo.Category | Should -Be 'ProtocolError'
            $failed[0].Exception.Message | Should -BeLike '*https://user@example.com/*'
            $failed[0].TargetObject.StatusCode | Should -Be 302
            $failed[0].TargetObject.Headers['Location'] | Should -Be 'https://user@example.com/'
        }

        It 'follows a 303 answering a POST with a GET that carries no body' {
            if (-not ($echoOnline -and $binOnline)) {
                Set-ItResult -Skipped -Because "$echo or $bin port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$bin/redirect-to?url=https://$echo/get&status_code=303" -Method POST -Body "SecureFetch test $guid" -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            $r.FinalUri | Should -Be "https://$echo/get"
            $r.Redirects -join ' ' | Should -Be "https://$echo/get"
            $echoed = ($r.Content | ConvertFrom-Json).headers.PSObject.Properties.Name
            $echoed | Should -Not -Contain 'content-length'
            $echoed | Should -Not -Contain 'content-type'
        }

        It 'follows a 307 answering a POST with the same POST and body' {
            if (-not ($echoOnline -and $binOnline)) {
                Set-ItResult -Skipped -Because "$echo or $bin port 443 cannot be reached from here"
                return
            }
            $body = "SecureFetch test $guid"
            $r = Invoke-SecureFetch "https://$bin/redirect-to?url=https://$echo/post&status_code=307" -Method POST -Body $body -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            $r.FinalUri | Should -Be "https://$echo/post"
            $r.Redirects -join ' ' | Should -Be "https://$echo/post"
            $json = $r.Content | ConvertFrom-Json
            $json.data | Should -BeExactly $body
            $json.headers.'content-type' | Should -Be 'text/plain; charset=utf-8'
        }

        It 'stops past -MaximumRedirection, carrying the last redirect' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            Invoke-SecureFetch "https://$bin/redirect/3" -MaximumRedirection 1 -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTooManyRedirects,*'
            $failed[0].CategoryInfo.Category | Should -Be 'LimitsExceeded'
            $failed[0].TargetObject.StatusCode | Should -Be 302
            $failed[0].TargetObject.FinalUri | Should -Be "https://$bin/relative-redirect/2"
            $failed[0].TargetObject.Redirects -join ' ' | Should -Be "https://$bin/relative-redirect/2"
        }

        It 'sends Authorization and Cookie on to the same host only' {
            if (-not ($echoOnline -and $binOnline)) {
                Set-ItResult -Skipped -Because "$echo or $bin port 443 cannot be reached from here"
                return
            }
            $credentials = @{ Authorization = "Bearer SecureFetch-test-$guid"; Cookie = "securefetch=$guid" }
            $same = Invoke-SecureFetch "https://$echo/redirect-to?url=https%3A%2F%2F$echo%2Fheaders" -Headers $credentials -ErrorAction Stop
            $same.FinalUri | Should -Be "https://$echo/headers"
            ($same.Content | ConvertFrom-Json).headers.authorization | Should -Be "Bearer SecureFetch-test-$guid"
            ($same.Content | ConvertFrom-Json).headers.cookie | Should -Be "securefetch=$guid"
            $other = Invoke-SecureFetch "https://$echo/redirect-to?url=https%3A%2F%2F$bin%2Fheaders" -Headers $credentials -ErrorAction Stop
            $other.FinalUri | Should -Be "https://$bin/headers"
            $sent = ($other.Content | ConvertFrom-Json).headers.PSObject.Properties.Name
            $sent | Should -Not -Contain 'Authorization'
            $sent | Should -Not -Contain 'Cookie'
        }
    }

    Context 'with a private root' {
        BeforeAll {
            # Whether this session can add a root to LocalMachine\Root: an
            # elevated one on Windows. The store tests run nowhere else.
            $script:elevated = $false
            if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
                $identity = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
                $script:elevated = $identity.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            }
            # A root and a server certificate for localhost it issued, made in
            # memory; no certificate store is touched here.
            $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
            $notAfter = [DateTimeOffset]::UtcNow.AddHours(1)
            $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
            $pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            $rootKey = [System.Security.Cryptography.RSA]::Create(2048)
            $rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=SecureFetch test root ' + [guid]::NewGuid().ToString(), $rootKey, $sha256, $pkcs1)
            $rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
            $rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign', $true))
            $rootRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootRequest.PublicKey, $false))
            $rootWithKey = $rootRequest.CreateSelfSigned($notBefore, $notAfter)
            $script:testRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rootWithKey.RawData)
            $serverKey = [System.Security.Cryptography.RSA]::Create(2048)
            $serverRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost', $serverKey, $sha256, $pkcs1)
            $names = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            $names.AddDnsName('localhost')
            $serverRequest.CertificateExtensions.Add($names.Build())
            $usages = [System.Security.Cryptography.OidCollection]::new()
            $null = $usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
            $serverRequest.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $false))
            $serial = New-Object byte[] 16
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
            $serial[0] = $serial[0] -band 0x7F
            $issued = $serverRequest.Create($rootWithKey, $notBefore, $notAfter, $serial)
            $withKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $serverKey)
            $pfx = $withKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'securefetch-test')
            $script:serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, 'securefetch-test', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            # An HTTPS server on that certificate, in a runspace of its own,
            # over TLS 1.2, which every system's own TLS stack serves. It
            # logs ACCEPTED for each connection, and for each request head it
            # reads, REQUEST with the version and whether the request asked
            # it to close, before it answers with a short text body. It
            # closes a connection after a request that asks it to, or when
            # the client closes it; a connection that sits idle for 5
            # seconds, or fails any other way, ends with an ENDED line giving
            # the reason.
            $script:tlsListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $tlsListener.Start()
            $script:tlsAddress = 'https://localhost:' + $tlsListener.LocalEndpoint.Port + '/'
            $script:tlsLog = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $script:tlsShell = [powershell]::Create()
            $null = $tlsShell.AddScript({
                    param($Listener, $Certificate, $Log)
                    $body = [System.Text.Encoding]::ASCII.GetBytes('SecureFetch test root')
                    $one = New-Object byte[] 1
                    while ($true) {
                        try {
                            $client = $Listener.AcceptTcpClient()
                        } catch {
                            $Log.Enqueue('STOPPED ' + $_.Exception.Message)
                            return
                        }
                        $Log.Enqueue('ACCEPTED')
                        try {
                            $client.ReceiveTimeout = 5000
                            $tls = [System.Net.Security.SslStream]::new($client.GetStream(), $false)
                            $tls.AuthenticateAsServer($Certificate, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                            $open = $true
                            while ($open) {
                                $head = [System.Text.StringBuilder]::new()
                                while (-not $head.ToString().EndsWith("`r`n`r`n")) {
                                    if ($tls.Read($one, 0, 1) -le 0) { break }
                                    $null = $head.Append([char]$one[0])
                                }
                                if (-not $head.ToString().EndsWith("`r`n`r`n")) { break }
                                $closing = $head.ToString() -match '(?im)^Connection:\s*close\s*$'
                                $shape = 'kept'
                                $ending = ''
                                if ($closing) {
                                    $shape = 'close'
                                    $ending = "Connection: close`r`n"
                                }
                                $Log.Enqueue('REQUEST ' + $tls.SslProtocol + ' ' + $shape)
                                $reply = [System.Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`n$ending`r`n")
                                $tls.Write($reply, 0, $reply.Length)
                                $tls.Write($body, 0, $body.Length)
                                $tls.Flush()
                                $open = -not $closing
                            }
                        } catch {
                            $Log.Enqueue('ENDED ' + $_.Exception.GetBaseException().Message)
                        } finally {
                            $client.Dispose()
                        }
                    }
                }).AddArgument($tlsListener).AddArgument($serverCertificate).AddArgument($tlsLog)
            $null = $tlsShell.BeginInvoke()
            # Each add to and remove from LocalMachine\Root is written here,
            # with its thumbprint and time, so every change to the store is on
            # record.
            $script:rootLog = Join-Path ([System.IO.Path]::GetTempPath()) 'securefetch-test-roots.log'
        }

        AfterAll {
            $tlsListener.Stop()
            $tlsShell.Stop()
            $tlsShell.Dispose()
            $serverCertificate.Dispose()
        }

        It 'trusts a root in the Windows store by default, refuses it under -TrustedRoots Bundled, and trusts it given as -RootCertificate' -Skip:(-not $onWindows) {
            if (-not $elevated) {
                Set-ItResult -Skipped -Because 'adding a root to LocalMachine\Root needs an elevated session'
                return
            }
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
            $store.Open('ReadWrite')
            $store.Add($testRoot)
            Add-Content -LiteralPath $rootLog -Value ('ADD ' + $testRoot.Thumbprint + ' ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') + ' ' + $PSVersionTable.PSVersion + ' ' + $testRoot.Subject)
            try {
                $trusted = Invoke-SecureFetch $tlsAddress -ErrorAction SilentlyContinue -ErrorVariable failed
                $failed.Count | Should -Be 0 -Because ('the server logged: ' + ($tlsLog -join ' | ') + '; the request failed: ' + (($failed | ForEach-Object { $_.Exception.Message }) -join ' | '))
                $trusted.StatusCode | Should -Be 200
                $trusted.Content | Should -BeExactly 'SecureFetch test root'
                Invoke-SecureFetch $tlsAddress -TrustedRoots Bundled -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
                $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTls,*'
                $failed[0].Exception.Message | Should -BeLike '*certificate*'
            } finally {
                $store.Remove($testRoot)
                $store.Close()
                Add-Content -LiteralPath $rootLog -Value ('REMOVE ' + $testRoot.Thumbprint + ' ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') + ' ' + $PSVersionTable.PSVersion + ' ' + $testRoot.Subject)
            }
            Invoke-SecureFetch $tlsAddress -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTls,*'
            $alone = Invoke-SecureFetch $tlsAddress -TrustedRoots None -RootCertificate $testRoot -ErrorAction Stop
            $alone.Content | Should -BeExactly 'SecureFetch test root'
        }

        It 'still verifies a public server under -TrustedRoots Bundled' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            (Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -TrustedRoots Bundled -ErrorAction Stop).StatusCode | Should -Be 200
        }

        It 'still verifies a public server under -TrustedRoots Windows, once Windows holds its root' -Skip:(-not $onWindows) {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            # A Windows that has never verified a chain to this server's root
            # holds few roots: its own TLS stack fetches the one a chain needs
            # when it verifies that chain. A store without the root is refused
            # as UnknownIssuer; then Invoke-WebRequest, which uses that stack,
            # makes Windows fetch it, and the request is made once more.
            $first = Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -TrustedRoots Windows -ErrorAction SilentlyContinue -ErrorVariable failed
            if ($failed.Count -eq 0) {
                $first.StatusCode | Should -Be 200
                return
            }
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTls,*'
            $failed[0].Exception.Message | Should -BeLike '*UnknownIssuer*'
            Write-Host ('ROOT FETCH ' + $endpoint + ' ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') + ' ' + $PSVersionTable.PSVersion + ' the Windows store lacked the root')
            $null = Invoke-WebRequest "https://$endpoint/cdn-cgi/trace" -UseBasicParsing -DisableKeepAlive -ErrorAction Stop
            (Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -TrustedRoots Windows -ErrorAction Stop).StatusCode | Should -Be 200
        }

        It 'refuses -TrustedRoots Windows on a system without a Windows certificate store, before it connects' -Skip:$onWindows {
            Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -TrustedRoots Windows -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchRootStore,*'
            $failed[0].Exception.Message | Should -BeLike '*this system has none*'
        }

        It 'refuses a choice of roots that trusts nothing, before it connects' {
            (Get-Command Invoke-SecureFetch).Parameters['RootCertificate'].ParameterType.FullName | Should -Be 'System.Security.Cryptography.X509Certificates.X509Certificate2[]'
            foreach ($choice in 'None', 'None,Bundled') {
                Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -TrustedRoots ($choice -split ',') -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
                $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchRootStore,*'
                $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
            }
        }

        It 'refuses a -RootCertificate rustls cannot take as a root, naming it, before it connects' {
            # rustls-webpki, which parses certificates for rustls, takes none
            # longer than 65535 bytes, and .NET makes one when an extension
            # carries 70000 bytes. The extension's
            # identifier is under 2.25, the arc for identifiers made from a
            # UUID (ITU-T X.667), so it names nothing that exists.
            $key = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=SecureFetch oversized test root ' + [guid]::NewGuid().ToString(), $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
                $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new('2.25.48383620782397916158158488059118089869', (New-Object byte[] 70000), $false))
                $oversized = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
                $oversized.RawData.Length | Should -BeGreaterThan 65535
                Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -TrustedRoots None -RootCertificate $oversized -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
                $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchRootStore,*'
                $failed[0].CategoryInfo.Category | Should -Be 'SecurityError'
                $failed[0].Exception.Message | Should -BeLike ('*' + $oversized.Subject + '*')
                $failed[0].Exception.Message | Should -BeLike ('*' + $oversized.Thumbprint + '*')
            } finally {
                $key.Dispose()
            }
        }

        It 'closes each connection by default and keeps one under -KeepAlive, as the local server counts them' {
            # The server logs ACCEPTED and REQUEST before it answers, so both
            # are in the log once the response has arrived; ENDED and STOPPED
            # lines belong to connections other tests left.
            $uris = @(1..3 | ForEach-Object { $tlsAddress })
            $counted = { param($from) @($tlsLog.ToArray() | Select-Object -Skip $from | Where-Object { $_ -like 'ACCEPTED*' -or $_ -like 'REQUEST*' }) -join ' | ' }
            $seen = $tlsLog.Count
            $closed = @($uris | Invoke-SecureFetch -TrustedRoots None -RootCertificate $testRoot -ErrorAction Stop)
            $closed.Count | Should -Be 3
            $closed[0].Content | Should -BeExactly 'SecureFetch test root'
            (& $counted $seen) | Should -BeExactly 'ACCEPTED | REQUEST Tls12 close | ACCEPTED | REQUEST Tls12 close | ACCEPTED | REQUEST Tls12 close'
            $seen = $tlsLog.Count
            $kept = @($uris | Invoke-SecureFetch -KeepAlive -TrustedRoots None -RootCertificate $testRoot -ErrorAction Stop)
            $kept.Count | Should -Be 3
            $kept[2].Content | Should -BeExactly 'SecureFetch test root'
            (& $counted $seen) | Should -BeExactly 'ACCEPTED | REQUEST Tls12 kept | REQUEST Tls12 kept | REQUEST Tls12 kept'
        }
    }

    Context 'through an HTTP proxy' {
        BeforeAll {
            $script:proxyListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $proxyListener.Start()
            $script:proxyAddress = 'http://127.0.0.1:' + $proxyListener.LocalEndpoint.Port
            $script:proxyLog = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
            $expected = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('securefetch:test-password'))
            $script:proxyShell = [powershell]::Create()
            $null = $proxyShell.AddScript($proxyScript).AddArgument($proxyListener).AddArgument($proxyLog).AddArgument($expected)
            $null = $proxyShell.BeginInvoke()
            $script:proxyCredential = [pscredential]::new('securefetch', (ConvertTo-SecureString 'test-password' -AsPlainText -Force))
        }

        AfterAll {
            $proxyListener.Stop()
            $proxyShell.Stop()
            $proxyShell.Dispose()
        }

        It 'tunnels through the proxy with CONNECT, and the handshake still agrees X25519MLKEM768' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -Proxy $proxyAddress -ProxyCredential $proxyCredential -ErrorAction Stop
            $r.StatusCode | Should -Be 200
            $r.KeyExchange | Should -Be 'X25519MLKEM768'
            $r.Content | Should -Match 'kex=X25519MLKEM768'
            $proxyLog.ToArray() | Should -Contain "CONNECT $($endpoint):443 HTTP/1.1"
        }

        It 'reports a proxy that asks for credentials as SecureFetchProxy, AuthenticationError' {
            Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -Proxy $proxyAddress -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchProxy,*'
            $failed[0].CategoryInfo.Category | Should -Be 'AuthenticationError'
            $failed[0].Exception.Message | Should -BeLike '*407*'
        }

        It 'reports a proxy nobody answers as SecureFetchProxy, ConnectionError' {
            Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -Proxy 'http://127.0.0.1:1' -TimeoutSeconds 5 -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchProxy,*'
            $failed[0].CategoryInfo.Category | Should -Be 'ConnectionError'
        }
    }

    Context 'when the body goes to a file' {
        BeforeAll {
            $script:raw = 'raw.githubusercontent.com'
            $script:rawOnline = Test-Port443 $raw
            # PowerShell's 256-pixel logo at the tag v7.4.0; its size and
            # SHA-256 were read with Invoke-WebRequest, not this module.
            $script:pinned = "https://$raw/PowerShell/PowerShell/v7.4.0/assets/Powershell_256.png"
            $script:pinnedHash = '1734E52435CF6CDDDEF2B340039986A8487FDD1CEAED44D1B93B39293E4A9DD4'
        }

        It 'writes a binary body byte for byte over the file that was there, writing nothing to the pipeline' {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            $file = Join-Path $TestDrive 'logo.png'
            Set-Content -LiteralPath $file -Value 'the file as it was'
            $written = @(Invoke-SecureFetch $pinned -OutFile $file -ErrorAction Stop)
            $written.Count | Should -Be 0
            (Get-Item -LiteralPath $file).Length | Should -Be 9494
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash | Should -Be $pinnedHash
            @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.securefetch-partial').Count | Should -Be 0
        }

        It 'writes the response as well under -PassThru, its Content and ContentBytes empty' {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            $file = Join-Path $TestDrive 'passed.png'
            $passed = Invoke-SecureFetch $pinned -OutFile $file -PassThru -ErrorAction Stop
            $passed.StatusCode | Should -Be 200
            $passed.Content | Should -BeExactly ''
            $passed.ContentBytes.Length | Should -Be 0
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash | Should -Be $pinnedHash
        }

        It 'resolves -OutFile through PowerShell, against the current location and on a drive of its own' {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            Push-Location -LiteralPath $TestDrive
            try {
                Invoke-SecureFetch $pinned -OutFile 'relative.png' -ErrorAction Stop
            } finally {
                Pop-Location
            }
            (Get-FileHash -LiteralPath (Join-Path $TestDrive 'relative.png') -Algorithm SHA256).Hash | Should -Be $pinnedHash
            Invoke-SecureFetch $pinned -OutFile 'TestDrive:\on-a-drive.png' -ErrorAction Stop
            (Get-FileHash -LiteralPath (Join-Path $TestDrive 'on-a-drive.png') -Algorithm SHA256).Hash | Should -Be $pinnedHash
        }

        It 'leaves the file as it was when a 4xx is raised, the body riding the error record' {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            $file = Join-Path $TestDrive 'kept.txt'
            Set-Content -LiteralPath $file -Value 'the file as it was'
            $missing = "https://$raw/PowerShell/PowerShell/v7.4.0/securefetch-no-such-file"
            Invoke-SecureFetch $missing -OutFile $file -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchHttpStatus,*'
            $failed[0].TargetObject.StatusCode | Should -Be 404
            $failed[0].TargetObject.ContentBytes.Length | Should -BeGreaterThan 0
            $failed[0].TargetObject.Content | Should -Not -BeNullOrEmpty
            (Get-Content -LiteralPath $file -Raw).Trim() | Should -BeExactly 'the file as it was'
            @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.securefetch-partial').Count | Should -Be 0
        }

        It 'reports a file it cannot replace as SecureFetchWriteFailed, deleting its temporary file' -Skip:(-not $onWindows) {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            $file = Join-Path $TestDrive 'held.png'
            Set-Content -LiteralPath $file -Value 'the file as it was'
            # Held open without delete sharing, as an editor might hold it,
            # so Windows refuses to rename the finished body over it.
            $held = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                Invoke-SecureFetch $pinned -OutFile $file -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            } finally {
                $held.Dispose()
            }
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchWriteFailed,*'
            $failed[0].CategoryInfo.Category | Should -Be 'WriteError'
            (Get-Content -LiteralPath $file -Raw).Trim() | Should -BeExactly 'the file as it was'
            @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.securefetch-partial').Count | Should -Be 0
        }

        It 'replaces a file another handle holds open, which goes on reading the file it opened' -Skip:$onWindows {
            if (-not $rawOnline) {
                Set-ItResult -Skipped -Because "$raw port 443 cannot be reached from here"
                return
            }
            $file = Join-Path $TestDrive 'open.png'
            Set-Content -LiteralPath $file -Value 'the file as it was'
            # Held open as the Windows test holds it; Linux, FreeBSD and
            # macOS rename over a file whatever holds it open.
            $held = [System.IO.File]::Open($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                Invoke-SecureFetch $pinned -OutFile $file -ErrorAction Stop | Should -BeNullOrEmpty
                ([System.IO.StreamReader]::new($held)).ReadToEnd().Trim() | Should -BeExactly 'the file as it was'
            } finally {
                $held.Dispose()
            }
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash | Should -Be $pinnedHash
            @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.securefetch-partial').Count | Should -Be 0
        }

        It 'refuses an -OutFile that is not a file it can write, before it connects' {
            foreach ($path in 'HKCU:\Software\SecureFetch-test', (Join-Path $TestDrive 'no-such-folder\body.bin'), $TestDrive) {
                Invoke-SecureFetch 'https://127.0.0.1:1/' -TimeoutSeconds 5 -OutFile $path -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
                $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchBadOutFile,*'
                $failed[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
            }
            Test-Path -LiteralPath 'HKCU:\Software\SecureFetch-test' | Should -BeFalse
        }
    }

    Context 'against a server whose answer to HEAD announces a length' {
        BeforeAll {
            $script:bin = 'httpbin.org'
            $script:binOnline = Test-Port443 $bin
        }

        It 'reads two HEAD responses, which carry no body whatever length they announce, over one kept connection' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            # A reader that waited for the 1024 bytes the fields announce
            # would run out the 20-second wait instead of returning.
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            $heads = @(@("https://$bin/bytes/1024", "https://$bin/bytes/1024") | Invoke-SecureFetch -Method HEAD -KeepAlive -TimeoutSeconds 20 -ErrorAction Stop)
            $clock.Stop()
            $heads.Count | Should -Be 2
            foreach ($head in $heads) {
                $head.StatusCode | Should -Be 200
                $head.Headers['Content-Length'] | Should -Be '1024'
                $head.ContentBytes.Length | Should -Be 0
                $head.Content | Should -BeExactly ''
            }
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 15
        }
    }

    Context 'against servers that send compressed bodies' {
        BeforeAll {
            $script:bin = 'httpbin.org'
            $script:binOnline = Test-Port443 $bin
            $script:meta = 'www.messenger.com'
            $script:metaOnline = Test-Port443 $meta
        }

        It 'asks for gzip, deflate, br and zstd, and decodes gzip, deflate and br bodies' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            foreach ($case in @(@('gzip', 'gzip', 'gzipped'), @('deflate', 'deflate', 'deflated'), @('brotli', 'br', 'brotli'))) {
                $r = Invoke-SecureFetch "https://$bin/$($case[0])" -ErrorAction Stop
                $r.Headers['Content-Encoding'] | Should -Be $case[1]
                $json = $r.Content | ConvertFrom-Json
                $json.($case[2]) | Should -BeTrue
                $json.headers.'Accept-Encoding' | Should -Be 'gzip, deflate, br, zstd'
            }
        }

        It 'asks for the identity encoding alone under -NoCompression' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$bin/headers" -NoCompression -ErrorAction Stop
            $r.Headers.Contains('Content-Encoding') | Should -BeFalse
            ($r.Content | ConvertFrom-Json).headers.'Accept-Encoding' | Should -Be 'identity'
        }

        It 'refuses a body that decodes to more than -MaximumDecodedBytes' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            Invoke-SecureFetch "https://$bin/gzip" -MaximumDecodedBytes 100 -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchTooLarge,*'
            $failed[0].CategoryInfo.Category | Should -Be 'LimitsExceeded'
        }

        It 'gives the bytes of a binary body in ContentBytes' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            $png = Invoke-SecureFetch "https://$bin/image/png" -ErrorAction Stop
            $png.Headers['Content-Type'] | Should -Be 'image/png'
            $png.ContentBytes.GetType().FullName | Should -Be 'System.Byte[]'
            (($png.ContentBytes[0..7] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') | Should -Be '89 50 4E 47 0D 0A 1A 0A'
        }

        It 'decodes a UTF-8 body into Content and keeps its bytes' {
            if (-not $binOnline) {
                Set-ItResult -Skipped -Because "$bin port 443 cannot be reached from here"
                return
            }
            $page = Invoke-SecureFetch "https://$bin/encoding/utf8" -ErrorAction Stop
            $page.Headers['Content-Type'] | Should -BeLike '*charset=utf-8*'
            $page.Content.Contains([string][char]0x222E) | Should -BeTrue
            [System.Text.Encoding]::UTF8.GetString($page.ContentBytes) | Should -Be $page.Content
        }

        It 'decodes a zstd body' {
            if (-not $metaOnline) {
                Set-ItResult -Skipped -Because "$meta port 443 cannot be reached from here"
                return
            }
            $r = Invoke-SecureFetch "https://$meta/" -ErrorAction Stop
            if ($r.Headers['Content-Encoding'] -ne 'zstd') {
                Set-ItResult -Skipped -Because "$meta answered with Content-Encoding '$($r.Headers['Content-Encoding'])' this time, not zstd"
                return
            }
            $r.Content | Should -Match '</html>'
        }
    }

    Context 'against a server that labels its page ISO-8859-1' {
        BeforeAll {
            $script:google = 'www.google.com'
            $script:googleOnline = Test-Port443 $google
        }

        It 'decodes the page one character per byte, by the label, with nothing unreadable' {
            if (-not $googleOnline) {
                Set-ItResult -Skipped -Because "$google port 443 cannot be reached from here"
                return
            }
            $page = Invoke-SecureFetch "https://$google/" -ErrorAction Stop
            if ($page.Headers['Content-Type'] -notlike '*charset=ISO-8859-1*') {
                Set-ItResult -Skipped -Because "$google sent Content-Type '$($page.Headers['Content-Type'])' this time"
                return
            }
            $page.Content.Length | Should -Be $page.ContentBytes.Length
            $page.Content.Contains([string][char]0xFFFD) | Should -BeFalse
        }
    }

    Context 'against servers that do not offer X25519MLKEM768' {
        BeforeAll {
            $script:classical = 'www.debian.org'
            $script:classicalOnline = Test-Port443 $classical
        }

        It 'refuses a TLS 1.3 server without X25519MLKEM768 under -RequirePostQuantum, and reports its group without it' {
            if (-not $classicalOnline) {
                Set-ItResult -Skipped -Because "$classical port 443 cannot be reached from here"
                return
            }
            $plain = Invoke-SecureFetch "https://$classical/" -ErrorAction Stop
            if ($plain.KeyExchange -eq 'X25519MLKEM768') {
                Set-ItResult -Skipped -Because "$classical negotiated X25519MLKEM768, so it cannot show a refusal"
                return
            }
            $plain.Protocol | Should -Be 'TLSv1_3'
            Invoke-SecureFetch "https://$classical/" -RequirePostQuantum -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchNotPostQuantum,*'
            $failed[0].CategoryInfo.Category | Should -Be 'SecurityError'
            $failed[0].Exception.Message | Should -BeLike '*the only key exchange -RequirePostQuantum offers*'
        }

        It 'refuses a TLS 1.2 server under -RequirePostQuantum' {
            if (-not $badssl) {
                Set-ItResult -Skipped -Because 'badssl.com port 443 cannot be reached from here'
                return
            }
            $plain = Invoke-BadSsl @{ Uri = 'https://badssl.com/' }
            if ($plain.Failed.Count) { throw $plain.Failed[0] }
            $protocol = $plain.Written[0].Protocol
            if ($protocol -ne 'TLSv1_2') {
                Set-ItResult -Skipped -Because "badssl.com negotiated $protocol, so it cannot show a TLS 1.2 refusal"
                return
            }
            $refused = Invoke-BadSsl @{ Uri = 'https://badssl.com/'; RequirePostQuantum = $true }
            $refused.Written | Should -BeNullOrEmpty
            $refused.Failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchNotPostQuantum,*'
        }
    }

    Context 'against a server that offers X25519MLKEM768' {
        BeforeAll {
            $script:trace = $null
            $script:plain = $null
            $script:missing = $null
            if ($online) {
                $script:trace = Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -ErrorAction Stop
                $script:plain = Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -NoCompression -ErrorAction Stop
                $script:missing = Invoke-SecureFetch "https://$endpoint/cdn-cgi/securefetch-no-such-page" -SkipHttpErrorCheck -ErrorAction Stop
            }
        }

        It 'negotiates TLS 1.3 with X25519MLKEM768' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $trace.Protocol | Should -Be 'TLSv1_3'
            $trace.KeyExchange | Should -Be 'X25519MLKEM768'
            $trace.CipherSuite | Should -BeLike 'TLS13_*'
            $trace.Content | Should -Match 'kex=X25519MLKEM768'
        }

        It 'completes the handshake under -RequirePostQuantum' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $required = Invoke-SecureFetch "https://$endpoint/cdn-cgi/trace" -RequirePostQuantum -ErrorAction Stop
            $required.Protocol | Should -Be 'TLSv1_3'
            $required.KeyExchange | Should -Be 'X25519MLKEM768'
            $required.Content | Should -Match 'kex=X25519MLKEM768'
        }

        It 'reads the status line, and writes a 404 as a response under -SkipHttpErrorCheck' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $trace.StatusCode | Should -Be 200
            $trace.StatusDescription | Should -Be 'OK'
            $missing.StatusCode | Should -Be 404
            $missing.StatusDescription | Should -Be 'Not Found'
        }

        It 'raises a 404 as an error record that carries the response' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $uri = "https://$endpoint/cdn-cgi/securefetch-no-such-page"
            Invoke-SecureFetch $uri -ErrorAction SilentlyContinue -ErrorVariable failed | Should -BeNullOrEmpty
            $failed.Count | Should -Be 1
            $failed[0].FullyQualifiedErrorId | Should -BeLike 'SecureFetchHttpStatus,*'
            $failed[0].CategoryInfo.Category | Should -Be 'InvalidResult'
            $failed[0].Exception.Message | Should -BeLike '*404 Not Found*'
            $failed[0].TargetObject.GetType().FullName | Should -Be 'SecureFetch.Response'
            $failed[0].TargetObject.Uri | Should -Be $uri
            $failed[0].TargetObject.StatusCode | Should -Be 404
            $failed[0].TargetObject.KeyExchange | Should -Be 'X25519MLKEM768'
            $failed[0].TargetObject.Headers['Server'] | Should -Be 'cloudflare'
            { Invoke-SecureFetch $uri -ErrorAction Stop } | Should -Throw '*404 Not Found*'
        }

        It 'reads the header fields into a table whose keys ignore case' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $trace.Headers.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
            $trace.Headers['Content-Type'].GetType().FullName | Should -Be 'System.String[]'
            $trace.Headers['Content-Type'] | Should -Be 'text/plain'
            $trace.Headers['content-type'] | Should -Be 'text/plain'
            $trace.Headers['Server'] | Should -Be 'cloudflare'
            $plain.Headers.Contains('Content-Encoding') | Should -BeFalse
            $plain.Headers['Content-Length'] | Should -Be ([string][System.Text.Encoding]::UTF8.GetByteCount($plain.Content))
        }

        It 'closes its connection by default, and keeps one for piped requests to the same host under -KeepAlive' -Skip:(-not $onWindows) {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $remote = @([System.Net.Dns]::GetHostAddresses($endpoint) | ForEach-Object { $_.ToString() })
            # The local ports of this process's established connections to
            # the endpoint that were not open before the test began, read
            # after each response has been written: an earlier test's web
            # cmdlet may keep a connection of its own. Get-NetTCPConnection
            # exists on Windows alone.
            $ports = {
                @(Get-NetTCPConnection -OwningProcess $PID -RemotePort 443 -State Established -ErrorAction SilentlyContinue |
                    Where-Object { $remote -contains $_.RemoteAddress } | ForEach-Object { $_.LocalPort })
            }
            $before = & $ports
            $held = { @(& $ports | Where-Object { $before -notcontains $_ }) -join ',' }
            $uris = @(1..3 | ForEach-Object { "https://$endpoint/cdn-cgi/trace" })
            $closed = @($uris | Invoke-SecureFetch -ErrorAction Stop | ForEach-Object { & $held })
            $kept = @($uris | Invoke-SecureFetch -KeepAlive -ErrorAction Stop | ForEach-Object { & $held })
            $ports = 'ports held after each response: by default [' + ($closed -join '; ') + '], under -KeepAlive [' + ($kept -join '; ') + ']'
            ($closed -join ';') | Should -Be ';;' -Because $ports
            $kept.Count | Should -Be 3 -Because $ports
            $kept[0] | Should -Match '^\d+$' -Because $ports
            $kept[1] | Should -Be $kept[0] -Because $ports
            $kept[2] | Should -Be $kept[0] -Because $ports
        }

        It 'sends HTTP/1.1 and answers each piped address with its own response' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $trace.Content | Should -Match 'http=http/1.1'
            $trace.Headers['Connection'] | Should -Be 'close'
            $uris = "https://$endpoint/cdn-cgi/trace", "https://$endpoint/cdn-cgi/securefetch-no-such-page"
            $both = @($uris | Invoke-SecureFetch -SkipHttpErrorCheck -ErrorAction Stop)
            $both.Count | Should -Be 2
            $both[0].Uri | Should -Be $uris[0]
            $both[0].StatusCode | Should -Be 200
            $both[1].Uri | Should -Be $uris[1]
            $both[1].StatusCode | Should -Be 404
        }

        It 'goes on to the next piped address after a 404 error record' {
            if (-not $online) {
                Set-ItResult -Skipped -Because "$endpoint port 443 cannot be reached from here"
                return
            }
            $uris = "https://$endpoint/cdn-cgi/securefetch-no-such-page", "https://$endpoint/cdn-cgi/trace"
            $written = @($uris | Invoke-SecureFetch -ErrorAction SilentlyContinue -ErrorVariable failed)
            $written.Count | Should -Be 1
            $written[0].Uri | Should -Be $uris[1]
            $written[0].StatusCode | Should -Be 200
            $failed.Count | Should -Be 1
            $failed[0].TargetObject.Uri | Should -Be $uris[0]
        }
    }
}
