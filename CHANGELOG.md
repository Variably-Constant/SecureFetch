# Changelog

What changed in each version of SecureFetch. Each release is one commit
in the repository's history, so the commit log names the versions and
this file says what changed in each.

## 0.2.0

### Added

- `Get-Help Invoke-SecureFetch -Online` opens the cmdlet's reference page
  in the wiki, which it declares as its `HelpUri`.
- `-ProxyCredential` takes a user name alone and prompts for the password
  through the host, as `Get-Credential -Credential` does: the parameter
  carries PowerShell's `[Credential()]`.

### Changed

- The module is built on PoWerRuSt 1.0.0 with cargo-pwrs 1.0.0, where
  0.1.0 was built on 0.3.0. In a session that shows as follows:
  - In Windows PowerShell 5.1 the module cannot share a session with a
    module built with PoWerRuSt 0.8.0 or earlier, in either order.
    SecureFetch 0.1.0 and Zstd 0.1.0 are two such modules. Imported after
    Zstd 0.1.0, SecureFetch 0.2.0 fails with
    `Could not load type 'Pwrs.RustJobSourceAdapter'`. When SecureFetch
    0.2.0 comes first, Zstd 0.1.0 fails instead, with
    `Method 'get_PwrsCmdletId' ... does not have an implementation`.
    PowerShell 7 imports them in either order. SecureFetch 0.2.0 and
    Zstd 0.2.0 import together in either order, in both hosts.
  - A SecureFetch of the same version already loaded from another
    folder, as when another module bundles it, makes a second import
    stand down and keep the loaded copy's commands. One of another
    version stops the import with `PwrsOtherVersionLoaded`.
  - Outside Windows the module stages its files in `pwrs-load-<uid>` in
    the temporary folder, a folder only its user can read, so every user
    of a machine imports it.
  - `-Debug` shows the verbose records and warnings, and asks after each
    whether to continue, as a compiled cmdlet does.
  - An exception that comes back through the cmdlet's output, such as a
    later command's throw, ends the command with that exception, whatever
    `-ErrorAction` says.
  - `-OutFile $null`, `-Proxy $null`, `-ContentType $null` and
    `-ProxyCredential $null` are each taken as the parameter not given.
    0.1.0 ended `-ProxyCredential $null` with `PwrsRuntimeError`.
  - The notices beside each native library give each crate's page on
    crates.io: `Source: https://crates.io/crates/<name>/<version>`.
- A stop wakes the wait for a request at once: the cmdlet registers a
  stop waker with PoWerRuSt, where it noticed a stop at its next check,
  up to 50 ms later.
- rustls 0.23.46, with aws-lc-rs 1.19.0 and aws-lc-sys 0.47.0;
  webpki-roots 1.0.11, the Mozilla roots the module bundles;
  brotli-decompressor 6.2.0, ruzstd 0.9.1, encoding_rs 0.8.44 and
  schannel 0.1.30.
- `.github/workflows/ci.yml` installs cargo-pwrs 1.0.0 and no longer
  saves Pester, since `cargo pwrs test` fetches Pester 6.2.0 into its
  toolchain.
- The Pester suite's two redirect tests that POST through httpbin.org's
  redirect-to endpoint lead to httpbin.org's own `/anything`, since
  httpbin.org redirects only to its own hosts and to example.com,
  example.net and example.org.
- Four wiki pages are renamed: Where It Has Been Run is now Tested
  Platforms, Why A Module Of Its Own is Why SecureFetch, How To Bound And
  Stop Requests is How To Set Timeouts And Stop Requests, and How To Pipe
  Addresses And Keep Connections is How To Pipe Addresses And Reuse
  Connections. Their old addresses redirect to the new ones.

### Fixed

- The cards on the wiki's section pages link to the lowercase paths Hugo
  publishes, so none answers 404 on GitHub Pages.

## 0.1.0

### Added

- `Invoke-SecureFetch`, which sends a request to an https:// address with
  TLS from rustls 0.23 inside the module. rustls runs over
  its aws-lc-rs provider, which offers the X25519MLKEM768 hybrid
  post-quantum key exchange first, and verifies server certificates
  against the Mozilla root certificates webpki-roots compiles into the
  module. `-Uri` takes the address by position or from the pipeline;
  `-TimeoutSeconds`, 1 to 300 and 30 when not given, bounds name
  resolution, the connection, and each read or write.
- A stop, such as Ctrl+C, ends a request at once, whatever it is
  waiting on. The request runs on a worker thread the stop does not wait
  for; on Windows that thread and its connection end when the server
  sends or closes, or when the step's own `-TimeoutSeconds` wait runs out.
- `SecureFetch.Response`, the object it writes for each address: `Uri`,
  `FinalUri` (the address the last request went to), `Redirects` (each
  address a redirect led to), `StatusCode`, `StatusDescription`,
  `Protocol`, `KeyExchange`, `CipherSuite`, `Headers` (an ordered
  dictionary whose keys ignore case, each holding a string array),
  `Trailers` (a chunked body's trailer fields, shaped like `Headers`),
  `Content` (the body as text, decoded by a byte order mark, else the
  Content-Type's charset label as the WHATWG Encoding Standard reads it
  through encoding_rs, else UTF-8) and `ContentBytes` (the body's bytes).
- HTTP/1.1 requests: a body ends where its Content-Length or chunked
  framing says, chunked bodies are decoded with their trailer fields,
  interim 1xx responses are skipped, and responses to HEAD and 204 and
  304 responses carry no body. Each request asks the server to close its
  connection; `-KeepAlive` keeps it instead for the next request to the
  same host and port, whether a redirect or the next piped address, and
  replaces a kept connection the server
  has closed, sending the request again when its method is GET, HEAD,
  OPTIONS, PUT or DELETE; a POST or PATCH on such a connection is
  `SecureFetchConnection` rather than being sent twice.
- Roots: by default rustls trusts the Mozilla roots compiled into the
  module and, on Windows, the roots of the Windows certificate store
  (`Cert:\CurrentUser\Root`, read through the schannel crate, keeping
  entries that allow server authentication and are valid now; an entry
  whose uses or validity cannot be read, or that rustls cannot take as a
  root, is skipped with a verbose message); on a system
  without that store the default is the bundled roots alone.
  `-TrustedRoots` (Bundled, Windows, None) chooses the sources and
  `-RootCertificate` adds `X509Certificate2` roots of the caller's own. A
  choice that trusts nothing, or None beside a source, is
  `SecureFetchRootStore` (InvalidArgument) before any connection; a store
  that cannot be opened, Windows named on a system without the store, or
  a `-RootCertificate` rustls cannot take as a root (named by its subject
  and thumbprint), is `SecureFetchRootStore` (SecurityError). The native
  library imports `crypt32.dll` to read the store on Windows. Each
  invocation reads its roots once and builds one TLS configuration, with
  session resumption off, so every connection makes a full handshake and
  reports its own key exchange.
- Proxies: `-Proxy http://host:port` tunnels each request with CONNECT,
  so TLS and its key exchange stay between the module and the server;
  `-ProxyCredential` sends Basic Proxy-Authorization. Without `-Proxy`,
  each request asks .NET for the proxy the system names for its address
  (`HttpClient.DefaultProxy` in PowerShell 7, which reads `HTTPS_PROXY`,
  `ALL_PROXY` and `NO_PROXY` and, when they are not set, the user's proxy
  settings on Windows and the system's on macOS;
  `WebRequest.GetSystemWebProxy()` in Windows PowerShell 5.1, which reads
  the Windows settings), unless `-NoProxy` is given, and `-ProxyCredential`
  goes to that proxy too. A kept connection is reused only through the
  same proxy. Failures are `SecureFetchProxy`: InvalidArgument before any
  connection for a `-Proxy` that is not an http:// address with a host
  and a port from 1 to 65535, that carries user information (which
  belongs in `-ProxyCredential`) or a path, or that comes with
  `-NoProxy`;
  AuthenticationError for a 407; ConnectionError otherwise.
- `-OutFile`, which writes the body to a file as it arrives, in pieces of
  up to 64 KiB, instead of holding it in memory: the path is resolved by
  PowerShell against the current location and must be a file system
  path; the body goes to a temporary file beside the target, renamed over
  it once the whole body has arrived and deleted on any failure or stop,
  leaving the target as it was. Nothing is written to the pipeline unless
  `-PassThru` is given, which writes the response with `Content` and
  `ContentBytes` empty. A redirect that is followed and a 4xx or 5xx
  raised as an error record write nothing to the file; the raised
  record's `TargetObject` carries the body in `Content` and
  `ContentBytes`. A path that cannot be resolved, is not a file system
  path, names a folder, or is in a folder that does not exist is
  `SecureFetchBadOutFile` (InvalidArgument) before any connection; a
  temporary file that cannot be created, written or renamed over the
  target is `SecureFetchWriteFailed` (WriteError).
- Redirects: a 301, 302, 303, 307 or 308 response with a Location is
  followed, the Location resolved against the address that answered
  (RFC 3986), up to `-MaximumRedirection` redirects (0 to 50, 5 when not
  given; 0 writes the redirect as the response it is). One more is
  `SecureFetchTooManyRedirects` (LimitsExceeded), a redirect to an
  address that is not https:// is `SecureFetchRedirectNotHttps`
  (SecurityError), and an https:// Location that cannot be sent is
  `SecureFetchBadResponse` (ProtocolError) naming it; each of these error
  records carries the redirect response. A redirect whose Location
  fields disagree is `SecureFetchBadResponse` too. A 303, and a 301 or
  302 answering a POST, is followed with a GET (a HEAD stays HEAD)
  without the body or the fields that describe it (Content-Type,
  Content-Encoding, Content-Language and Content-Location); any other
  redirect keeps the method and body. Authorization and Cookie are not
  sent on to
  another host or port.
- `-Method` (GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS, in any case,
  sent upper-cased; GET when not given), `-Headers` (a dictionary whose
  values are strings or arrays of strings, one field line each; an entry
  named User-Agent, Accept or Accept-Encoding replaces the one the cmdlet
  sends), `-Body` (a string, sent as UTF-8, or a byte array, framed by
  Content-Length) and `-ContentType` (sent as given; text/plain;
  charset=utf-8 or application/octet-stream when not given). A POST, PUT
  or PATCH without a body sends `Content-Length: 0`. A header field name
  that is not a token, one of the fields the cmdlet writes itself, a
  value that is neither a string nor an array of strings, a value
  carrying a control byte other than tab, a Content-Type given both in
  `-Headers` and by
  `-ContentType`, an Accept-Encoding entry beside `-NoCompression` (the
  message quotes both values), and a string body labeled with a charset
  other than UTF-8 are refused before any connection as
  `SecureFetchBadHeader`; a body of another type is `SecureFetchBadBody`.
- Content codings: requests ask for gzip, deflate, br and zstd, decoded
  as they arrive through flate2 on its zlib-rs backend, which picks its
  AVX2 and CLMUL paths at run time, brotli-decompressor and ruzstd;
  `-NoCompression` asks for identity alone; a body that decodes past
  `-MaximumDecodedBytes` (256 MiB when not given) is `SecureFetchTooLarge`
  (LimitsExceeded); a body that does not decode under its coding is
  `SecureFetchBadResponse`; other codings stay `SecureFetchEncoding`.
- An error record with its own id and category for each way a request
  can fail, from an address that is not https:// to a certificate that
  does not verify and a response that is not well-formed HTTP.
- A 4xx or 5xx status is an error record, `SecureFetchHttpStatus`
  (InvalidResult), whose `TargetObject` is the response;
  `-SkipHttpErrorCheck` writes such a response instead.
- `-RequirePostQuantum`, which offers only TLS 1.3 with X25519MLKEM768,
  so a server that cannot agree it fails the handshake, before the
  request is sent, as `SecureFetchNotPostQuantum` (SecurityError). The
  handshake always finishes before the request is written.
- Rust unit tests for taking addresses and responses apart and for
  stopping and bounding requests, and a Pester suite that runs in
  PowerShell 7 and in Windows PowerShell 5.1.
- The README, this changelog, and the MIT license.
- The wiki, published as a Hugo site on the Hextra theme at
  variably-constant.github.io/SecureFetch by
  `.github/workflows/wiki-deploy.yml` at every push to main, from
  `wiki/content/docs`. It is organized by the Diataxis framework: a
  Getting Started tutorial that installs the module from the PowerShell
  Gallery, ten how-to guides, two explanations, reference pages for
  every parameter, every `SecureFetch.Response` property with its type,
  every error id and where the module has been run, and a section on
  building from source and running the tests. Every example carries its
  output from runs in both hosts on Windows 11, and the page on where
  the module has been run gives the build and the test suite on Windows
  11, Windows 10, Windows Server 2019, AlmaLinux 8.10, Ubuntu 24.04 and
  FreeBSD 15.0.
- The module manifest's author (Mark Newton), company (Variably
  Constant), copyright ((c) 2026 Mark Newton), description, project and
  license links, icon, release notes and tags, taken from Cargo.toml.
  The description says what the cmdlet does, that the module is bound
  to Rust with PoWerRuSt, and which platforms and hosts it runs on, and
  links this repository, PWRS and PoWerRuSt on crates.io.
- Cargo.lock, so every build compiles the same crate versions.
- Rust edition 2024, with `rust-version = "1.98"` in Cargo.toml.
- `.cargo/config.toml`, which links the C runtime into the native library
  (`-C target-feature=+crt-static`), so the module does not need the
  Visual C++ Redistributable.
- PoWerRuSt 0.3.0 comes from crates.io, and the module is built with
  cargo-pwrs 0.3.0, which writes `THIRD-PARTY-NOTICES.txt` into the
  module folder: at its root for the assemblies PWRS compiles, and under
  `runtimes/win-x64` with the license and license files of each crate
  compiled into the native library. alloc-stdlib 0.3.0 packages no
  license file, so `licenses/alloc-stdlib-0.3.0/LICENSE`, its
  repository's LICENSE at the commit it was packaged from, is supplied
  for it through `[package.metadata.pwrs.license-files]`.
- The package carries a native library for Windows x64, Linux x64 (built
  against glibc 2.28, so it loads on 2.28 and newer), macOS arm64 and
  FreeBSD x64, each with its own `THIRD-PARTY-NOTICES.txt`.
- A refusal that quotes an address given to `-Uri` or `-Proxy`, or a
  proxy the system names, writes the user information in it as `***`
  (`https://***@host/`, `http://***@proxy:3128`), so a password given
  there does not reach the error record: `SecureFetchUserInfo`,
  `SecureFetchNotHttps` and `SecureFetchProxy`.
- `.github/workflows/ci.yml`, a GitHub Actions workflow that installs
  cargo-pwrs 0.3.0 and Pester 6.2.0 and builds, lints and tests the
  module at every push: on windows-latest in both hosts, with NASM 3.02,
  and on ubuntu-latest and macos-latest in PowerShell 7. Each job uploads
  the module folder it built as an artifact.
- `.github/workflows/verify-gallery.yml`, started by hand after a
  publish, which installs the published version from the PowerShell
  Gallery on windows-latest, ubuntu-latest and macos-latest and runs the
  Pester suite against it, on Windows in both hosts.
- The Pester suite runs on Windows, Linux, FreeBSD and macOS. The tests
  that read the Windows certificate store, the one that reads this
  process's connections through `Get-NetTCPConnection`, and the one that
  needs Windows to refuse a rename over a file held open run on Windows
  alone; on the other systems the suite checks that `-TrustedRoots
  Windows` is refused and that a held-open target is replaced. A test
  counts the connections a local TLS server accepts, so closing by
  default and keeping one under `-KeepAlive` are checked on every system
  without the network.
