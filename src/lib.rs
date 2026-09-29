//! `Invoke-SecureFetch`: a request to an https:// address that the module
//! makes itself, with TLS from rustls inside the module rather than from
//! the host's TLS stack (SChannel on Windows). rustls runs over its
//! aws-lc-rs provider, whose default key exchange groups offer the
//! X25519MLKEM768 hybrid post-quantum group first, so a server that
//! supports it negotiates it. Only this module's own connections use this
//! stack; the host's web cmdlets and every other module keep the host's.
//!
//! Each request runs on a worker thread of its own while the pipeline
//! thread waits for it, so a stop (Ctrl+C or a runspace stop) ends the
//! cmdlet within one polling interval whatever the request is blocked on,
//! and name resolution, which the system resolver cannot interrupt, runs
//! on a thread of its own that is waited on for at most `-TimeoutSeconds`.
//! A stopped worker is not waited for: it ends on its own when the step
//! it is blocked in returns, which on Windows is when the server acts or
//! the step's own wait of `-TimeoutSeconds` runs out, since shutting a
//! socket down there does not end a receive already blocked on it.

use pwrs::prelude::*;
use rustls::pki_types::ServerName;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a waiting thread sleeps between checks of a stop or a
/// deadline when nothing wakes it sooner.
const POLL: Duration = Duration::from_millis(50);

/// One response, with what the TLS handshake that carried it negotiated.
#[psclass(name = "SecureFetch.Response")]
#[derive(Default, Clone)]
pub struct Response {
    /// The address requested, as it was given.
    pub uri: String,
    /// The address the last request was sent to, written out whole: when
    /// no redirect was followed, Uri as it was sent (https:// in lower
    /// case, no port when it is 443, / when no path was given, bytes a
    /// request target cannot carry escaped as %XX, no fragment); else the
    /// last address redirected to.
    pub final_uri: String,
    /// Each address a redirect led to, in the order they were followed;
    /// empty when none was.
    pub redirects: Vec<String>,
    /// The status code, such as 200.
    pub status_code: i32,
    /// The reason phrase of the status line, such as OK; empty when the server sent none.
    pub status_description: String,
    /// The TLS protocol version, such as TLSv1_3.
    pub protocol: String,
    /// The key exchange group, such as X25519MLKEM768.
    pub key_exchange: String,
    /// The cipher suite, such as TLS13_AES_256_GCM_SHA384.
    pub cipher_suite: String,
    /// The header fields: an OrderedDictionary whose keys match without
    /// regard to case, in the order each name first arrived, each holding
    /// a string array of every value sent under that name.
    pub headers: PsObject,
    /// The trailer fields a chunked body ended with, shaped like Headers;
    /// empty when there were none.
    pub trailers: PsObject,
    /// The body as text, decoded from ContentBytes the way a browser
    /// decodes it: by a byte order mark when the body starts with one, else
    /// by the charset the Content-Type names, else as UTF-8; a byte
    /// sequence the encoding cannot read becomes U+FFFD. Empty when
    /// -OutFile took the body.
    pub content: String,
    /// The body's bytes as received, its content codings undone: the bytes
    /// Content was decoded from. Empty when -OutFile took the body.
    pub content_bytes: Vec<u8>,
}

/// Sends a request to an https:// address with TLS from rustls inside the
/// module and writes the response with what the handshake negotiated.
///
/// The request is a GET unless -Method names another method. -Headers adds
/// header fields and may replace the User-Agent, Accept and Accept-Encoding
/// fields the cmdlet sends; -Body sends a string, as UTF-8, or a byte
/// array, as it is, framed by Content-Length, with -ContentType saying what
/// it is. A header or body that cannot be sent is refused before any
/// connection is made.
///
/// The TLS stack is the module's own, not the host's, and offers the
/// X25519MLKEM768 hybrid post-quantum key exchange first; with
/// -RequirePostQuantum it offers that and TLS 1.3 alone, so a server
/// without them is refused during the handshake. The request is
/// HTTP/1.1 and asks the server to close the connection after the
/// response; with -KeepAlive the connection is kept instead and reused for
/// the next request to the same host and port through the same proxy,
/// whether a redirect or the next piped address. The body is read to
/// the end its Content-Length or chunked framing gives, and chunked bodies
/// are decoded, trailer fields included. It asks for gzip, deflate, br and
/// zstd bodies and decodes them, up to -MaximumDecodedBytes of decoded
/// bytes; -NoCompression asks for the identity encoding alone. A response
/// to HEAD carries no body. A response whose status is 4xx or 5xx is an
/// error record that carries the response, unless -SkipHttpErrorCheck is
/// given; an address that cannot be sent, a connection or handshake that
/// fails, and a response that cannot be read are error records too. A
/// stop, such as Ctrl+C, ends a request at once, whatever it is waiting on.
///
/// A 301, 302, 303, 307 or 308 response with a Location is followed, up
/// to -MaximumRedirection redirects, to https:// addresses only; a 303,
/// and a 301 or 302 answering a POST, is followed with a GET without the
/// body. Authorization and Cookie fields are not sent on to another host
/// or port. The response written names the address it came from in
/// FinalUri and each address followed in Redirects.
///
/// With -OutFile the body is written to that file as it arrives instead
/// of being held in memory, through a temporary file that replaces it
/// only once the whole body has arrived, and nothing is written to the
/// pipeline unless -PassThru is given.
///
/// With -Proxy the request goes through that HTTP proxy, tunneled with
/// CONNECT so TLS still runs between this module and the server; without
/// it, the proxy the system names for the address is used, unless
/// -NoProxy is given.
///
/// Server certificates are verified by rustls against the bundled Mozilla
/// roots and, on Windows, the roots in the Windows certificate store,
/// unless -TrustedRoots names others; -RootCertificate adds roots of the
/// caller's own.
///
/// # Examples
/// Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace
/// 'https://pq.cloudflareresearch.com/cdn-cgi/trace' | Invoke-SecureFetch -TimeoutSeconds 10 | Select-Object StatusCode, Protocol, KeyExchange, CipherSuite
/// Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/no-such-page -SkipHttpErrorCheck
/// Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace -RequirePostQuantum
/// Invoke-SecureFetch https://postman-echo.com/post -Method POST -Body '{"name":"value"}' -ContentType 'application/json' -Headers @{ 'X-Example' = '42' }
/// (Invoke-SecureFetch https://github.com/PowerShell/PowerShell/releases/latest).FinalUri
/// Invoke-SecureFetch https://speed.cloudflare.com/__down?bytes=1048576 -OutFile .\down.bin -PassThru
#[cmdlet(verb = "Invoke", noun = "SecureFetch", output = ["SecureFetch.Response"])]
pub struct InvokeSecureFetch {
    /// An https:// address.
    #[param(mandatory, position = 0, value_from_pipeline)]
    pub uri: String,
    /// The request method: GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS, in any case, sent upper-cased; GET when not given.
    #[param(validate_set = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])]
    pub method: String,
    /// Header fields to send, as a dictionary of names and values; a value is a string, or an array of strings sent as one field line each. An entry named User-Agent, Accept or Accept-Encoding replaces the one the cmdlet sends.
    #[param]
    pub headers: HeaderTable,
    /// The request body: a string, sent as UTF-8, or a byte array, sent as it is. Sent with every method that is given it, framed by Content-Length.
    #[param]
    pub body: PsObject,
    /// The body's Content-Type, sent as given. Without it a string body is sent as text/plain; charset=utf-8 and a byte array as application/octet-stream.
    #[param]
    pub content_type: Option<String>,
    /// Seconds to wait for name resolution, for the connection and for each read or write; 30 when not given.
    #[param(validate_range(1, 300))]
    pub timeout_seconds: u64,
    /// Writes a response whose status is 4xx or 5xx as a response rather than raising it as an error record.
    #[param]
    pub skip_http_error_check: bool,
    /// Offers only TLS 1.3 with the X25519MLKEM768 key exchange, so a server that cannot negotiate it fails the handshake, before any request is sent, as SecureFetchNotPostQuantum.
    #[param]
    pub require_post_quantum: bool,
    /// Keeps each connection open after its response and reuses it for the next request to the same host and port through the same proxy, whether a redirect or the next piped address. When the server has closed the kept connection, a GET, HEAD, OPTIONS, PUT or DELETE is sent once more on a new connection, and a POST or PATCH fails as SecureFetchConnection rather than being sent twice.
    #[param]
    pub keep_alive: bool,
    /// Asks for the body in the identity encoding only, instead of gzip, deflate, br or zstd.
    #[param]
    pub no_compression: bool,
    /// The most bytes a body sent with a content coding may decode to; past it the request fails as SecureFetchTooLarge. 256 MiB when not given.
    #[param]
    pub maximum_decoded_bytes: u64,
    /// The most redirects to follow, 0 to 50; past it the request fails as SecureFetchTooManyRedirects. 0 writes a redirect as the response it is. 5 when not given.
    #[param(validate_range(0, 50))]
    pub maximum_redirection: i32,
    /// A file to write the body to as it arrives, instead of holding it in memory; a relative path is relative to the current location. The body goes to a temporary file beside it, which replaces the file only once the whole body has arrived. Nothing is written to the pipeline unless -PassThru is given.
    #[param]
    pub out_file: Option<String>,
    /// With -OutFile, also writes the response, its Content and ContentBytes empty.
    #[param]
    pub pass_thru: bool,
    /// An HTTP proxy to reach the server through, as http://host:port. The request is tunneled with CONNECT, so TLS and its key exchange run between this module and the server. Without it, the proxy the system names for the address is used, unless -NoProxy is given.
    #[param]
    pub proxy: Option<String>,
    /// The user name and password for the proxy, sent as Basic Proxy-Authorization.
    #[param]
    pub proxy_credential: Option<PsCredential>,
    /// Connects to the server directly rather than through the proxy the system names for it.
    #[param]
    pub no_proxy: bool,
    /// Where the roots a server's certificate must chain to come from: Bundled, the Mozilla roots compiled into the module; Windows, the roots in the current user's Root store (Cert:\CurrentUser\Root), which also shows the machine's; None, neither. When not given: Bundled and Windows on Windows, Bundled on a system without a Windows certificate store.
    #[param(validate_set = ["Bundled", "Windows", "None"])]
    pub trusted_roots: Vec<String>,
    /// Certificates to trust as roots besides those -TrustedRoots names, as X509Certificate2 objects, such as those in the Cert: drive or one read with [X509Certificate2]::new('ca.cer').
    #[param]
    pub root_certificate: Vec<RootCertificate>,
    /// The connections -KeepAlive keeps between requests, one per host,
    /// port, proxy and TLS requirement; they close when the invocation
    /// ends.
    idle: Vec<Idle>,
    /// The method, header fields and body every record of the invocation
    /// sends, read from the parameters and checked on the first record.
    outgoing: Option<Arc<Outgoing>>,
    /// The TLS client configuration every request of the invocation uses,
    /// its roots read on the first record.
    tls: Option<Arc<rustls::ClientConfig>>,
}

/// An unbound parameter keeps its field's value, so these are the default
/// method, timeout, decoded-size bound, redirect limit and root sources.
impl Default for InvokeSecureFetch {
    fn default() -> Self {
        InvokeSecureFetch {
            uri: String::new(),
            method: "GET".to_string(),
            headers: HeaderTable::default(),
            body: PsObject::null(),
            content_type: None,
            timeout_seconds: 30,
            skip_http_error_check: false,
            require_post_quantum: false,
            keep_alive: false,
            no_compression: false,
            maximum_decoded_bytes: 256 << 20,
            maximum_redirection: 5,
            out_file: None,
            pass_thru: false,
            proxy: None,
            proxy_credential: None,
            no_proxy: false,
            trusted_roots: default_trusted_roots(),
            root_certificate: Vec::new(),
            idle: Vec::new(),
            outgoing: None,
            tls: None,
        }
    }
}

/// The -Headers dictionary: any System.Collections.IDictionary, such as a
/// hashtable or an [ordered] one, held as the caller passed it; null when
/// the parameter is not given or is given $null.
#[derive(Default)]
pub struct HeaderTable(PsObject);

impl PsTyped for HeaderTable {
    const CLR_NAME: &'static str = "System.Collections.IDictionary";
    const VALUE_TYPE: bool = false;
}

impl FromPs for HeaderTable {
    fn from_ps(obj: &PsObject) -> PsResult<Self> {
        Ok(HeaderTable(obj.clone()))
    }
}

/// One -RootCertificate entry: a
/// System.Security.Cryptography.X509Certificates.X509Certificate2, held as
/// the caller passed it.
#[derive(Default)]
pub struct RootCertificate(PsObject);

impl PsTyped for RootCertificate {
    const CLR_NAME: &'static str = "System.Security.Cryptography.X509Certificates.X509Certificate2";
    const VALUE_TYPE: bool = false;
}

impl FromPs for RootCertificate {
    fn from_ps(obj: &PsObject) -> PsResult<Self> {
        Ok(RootCertificate(obj.clone()))
    }
}

impl Cmdlet for InvokeSecureFetch {
    /// Makes the request, then each request a redirect it may follow leads
    /// to, and writes the last response. A redirect past
    /// -MaximumRedirection, or to an address that is not https://, is an
    /// error record carrying the redirect response instead.
    fn process(&mut self, ps: &Pipeline<'_>) -> PsResult<()> {
        let mut target = Target::parse(&self.uri)?;
        let mut outgoing = self.outgoing()?;
        let out_file = match &self.out_file {
            Some(path) => Some(out_file_path(ps, path)?),
            None => None,
        };
        let mut redirects: Vec<String> = Vec::new();
        loop {
            let fetched = self.fetch(ps, &target, &outgoing, out_file.as_deref())?;
            let status_code = fetched.message.status_code;
            let location = match self.maximum_redirection {
                0 => None,
                _ => redirect_location(&fetched.message, &target)?,
            };
            let Some(location) = location else {
                let failed = is_http_error(status_code) && !self.skip_http_error_check;
                let status = status_text(status_code, &fetched.message.reason);
                let to_file = fetched.to_file;
                let response = self.response(fetched, &target, redirects)?;
                if failed {
                    return Err(PsError::new(ErrorCategory::InvalidResult, "SecureFetchHttpStatus", format!("{} answered {status}", self.uri)).with_target(response));
                }
                if to_file && !self.pass_thru {
                    return Ok(());
                }
                return ps.write_object(&response);
            };
            if redirects.len() >= self.maximum_redirection.max(0) as usize {
                let limit = self.maximum_redirection;
                let noun = if limit == 1 { "redirect" } else { "redirects" };
                let message = format!(
                    "{} kept redirecting past -MaximumRedirection {limit}: after {limit} {noun}, a {status_code} from {} led to {location}",
                    self.uri,
                    target.address()
                );
                let response = self.response(fetched, &target, redirects)?;
                return Err(PsError::new(ErrorCategory::LimitsExceeded, "SecureFetchTooManyRedirects", message).with_target(response));
            }
            let next = match redirected_target(&target, &location) {
                Ok(next) => next,
                Err(refused) => {
                    let response = self.response(fetched, &target, redirects)?;
                    return Err(refused.with_target(response));
                }
            };
            let crossed = !next.host.eq_ignore_ascii_case(&target.host) || next.port != target.port;
            outgoing = Arc::new(outgoing.redirected(status_code, crossed));
            redirects.push(next.address());
            target = next;
        }
    }
}

impl InvokeSecureFetch {
    /// Makes one request to `target` on a worker thread and waits for it
    /// here, on the pipeline thread, which alone may write to the
    /// pipeline. A connection kept for the target is used first, and the
    /// connection comes back to the kept ones when the response leaves it
    /// fit for another request. When the pipeline stops first, the request
    /// is marked stopped, its connection is shut down, and the phase ends
    /// at once with SecureFetchStopped; the worker ends on its own when the
    /// step it is blocked in returns.
    fn fetch(&mut self, ps: &Pipeline<'_>, target: &Target, outgoing: &Arc<Outgoing>, out_file: Option<&Path>) -> PsResult<Exchange> {
        let post_quantum_only = self.require_post_quantum;
        let proxy = self.proxy_for(ps, target)?;
        let idle = match self.keep_alive {
            true => take_idle(&mut self.idle, target, post_quantum_only, proxy.as_ref()),
            false => None,
        };
        let host = target.host.clone();
        let job = Job {
            config: self.tls_config(ps)?,
            post_quantum_only,
            wait: Duration::from_secs(self.timeout_seconds),
            keep_alive: self.keep_alive,
            outgoing: Arc::clone(outgoing),
            max_decoded: self.maximum_decoded_bytes,
            out_file: out_file.map(Path::to_path_buf),
            http_errors_to_file: self.skip_http_error_check,
            redirects_followed: self.maximum_redirection > 0,
            proxy,
            idle,
            target: target.clone(),
        };
        let cancel = Arc::new(Cancel::default());
        let worker = {
            let cancel = Arc::clone(&cancel);
            start("securefetch-request", move || exchange(job, &cancel)).map_err(|e| no_thread(&host, &e))?
        };
        let mut fetched = match wait_on(worker, || ps.stopping().then_some(Halt::Stopped)) {
            Ok(result) => result?,
            Err((_, worker)) => {
                let unshut = cancel.stop();
                // Dropping the handle detaches the worker, which ends by
                // itself when the step it is blocked in returns.
                drop(worker);
                return Err(stopped(&host, unshut));
            }
        };
        // The worker has finished, so this is the last hold on the second
        // handle to its connection; dropping it closes a connection that
        // was not kept before the response is written.
        drop(cancel);
        if let Some(idle) = fetched.idle.take() {
            self.idle.push(idle);
        }
        Ok(fetched)
    }

    /// The TLS client configuration this invocation's requests use, built
    /// on the first record and kept: -RequirePostQuantum's version and
    /// group, and the roots -TrustedRoots and -RootCertificate name.
    fn tls_config(&mut self, ps: &Pipeline<'_>) -> PsResult<Arc<rustls::ClientConfig>> {
        if let Some(ready) = &self.tls {
            return Ok(Arc::clone(ready));
        }
        let roots = trusted_roots(ps, &self.trusted_roots, &self.root_certificate)?;
        let ready = client_config(self.require_post_quantum, roots)?;
        self.tls = Some(Arc::clone(&ready));
        Ok(ready)
    }

    /// The proxy a request to `target` goes through: -Proxy when given;
    /// none under -NoProxy; otherwise the one the system names for the
    /// address, asked for each request. -ProxyCredential goes with
    /// whichever it is.
    fn proxy_for(&self, ps: &Pipeline<'_>, target: &Target) -> PsResult<Option<Proxy>> {
        let address = match (&self.proxy, self.no_proxy) {
            (Some(given), true) => {
                return Err(proxy_refused(given, "is given together with -NoProxy, which asks for no proxy".to_string()));
            }
            (Some(given), false) => ProxyAddress::parse(given).map_err(|why| proxy_refused(given, why))?,
            (None, true) => return Ok(None),
            (None, false) => match system_proxy(ps, target)? {
                None => return Ok(None),
                Some(named) => ProxyAddress::parse(&named).map_err(|why| {
                    proxy_error(ErrorCategory::ConnectionError, &named, format!("is the proxy the system names for {}, and it {why}", target.address()))
                })?,
            },
        };
        let authorization = match &self.proxy_credential {
            Some(credential) => Some(format!("Basic {}", base64(format!("{}:{}", credential.user_name, credential.password.reveal()?).as_bytes()))),
            None => None,
        };
        Ok(Some(Proxy { address, authorization }))
    }

    /// The SecureFetch.Response for `fetched`, the answer from `target`
    /// after the redirects in `redirects` were followed.
    fn response(&self, fetched: Exchange, target: &Target, redirects: Vec<String>) -> PsResult<PsObject> {
        let message = fetched.message;
        Response {
            uri: self.uri.clone(),
            final_uri: target.address(),
            redirects,
            status_code: i32::from(message.status_code),
            status_description: message.reason,
            protocol: fetched.protocol,
            key_exchange: fetched.key_exchange,
            cipher_suite: fetched.cipher_suite,
            headers: header_table(&message.fields)?,
            trailers: header_table(&message.trailers)?,
            content: text_of(&message.body, &message.fields),
            content_bytes: message.body,
        }
        .into_ps()
    }

    /// The method, header fields and body this invocation sends, read from
    /// the parameters and checked on the first record and kept for the
    /// records after it. A parameter that cannot be sent is refused on
    /// every record, before any connection is made.
    fn outgoing(&mut self) -> PsResult<Arc<Outgoing>> {
        if let Some(ready) = &self.outgoing {
            return Ok(Arc::clone(ready));
        }
        let entries = header_entries(&self.headers.0)?;
        let payload = payload_of(&self.body)?;
        let ready = Arc::new(Outgoing::new(&self.method, !self.no_compression, entries, payload, self.content_type.as_deref())?);
        self.outgoing = Some(Arc::clone(&ready));
        Ok(ready)
    }
}

/// Whether a response with `status_code` is raised as SecureFetchHttpStatus
/// unless -SkipHttpErrorCheck is given: a 4xx or a 5xx.
fn is_http_error(status_code: u16) -> bool {
    (400..=599).contains(&status_code)
}

/// A status as a caller reads it: the code, then the reason phrase when
/// the server sent one.
fn status_text(status_code: u16, reason: &str) -> String {
    match reason {
        "" => status_code.to_string(),
        _ => format!("{status_code} {reason}"),
    }
}

/// One request as the worker thread makes it: where it goes and how.
struct Job {
    target: Target,
    config: Arc<rustls::ClientConfig>,
    post_quantum_only: bool,
    /// The bound on name resolution, the connection and each read or write.
    wait: Duration,
    /// Whether the connection is to be kept for the next request.
    keep_alive: bool,
    /// The method, header fields and body to send.
    outgoing: Arc<Outgoing>,
    /// The most bytes a body sent with a content coding may decode to.
    max_decoded: u64,
    /// The file -OutFile names, resolved; the body of a response that is
    /// written rather than followed or raised goes there instead of into
    /// memory.
    out_file: Option<PathBuf>,
    /// Whether a 4xx or 5xx response is written, under
    /// -SkipHttpErrorCheck, so its body goes to the file too.
    http_errors_to_file: bool,
    /// Whether redirects are followed, so a redirect's body stays in
    /// memory.
    redirects_followed: bool,
    /// The HTTP proxy to tunnel through, if any.
    proxy: Option<Proxy>,
    /// A connection kept from an earlier request to the same place, tried
    /// before a new one is opened.
    idle: Option<Idle>,
}

impl Job {
    /// Whether the body of the response `head` begins goes to the
    /// -OutFile file: when there is one, unless the response is a redirect
    /// that is followed or refused, or a 4xx or 5xx raised as an error
    /// record, whose body stays in memory for the record.
    fn to_file(&self, head: &Head) -> bool {
        let redirect = self.redirects_followed
            && matches!(head.status_code, 301 | 302 | 303 | 307 | 308)
            && head.fields.iter().any(|(name, _)| name.eq_ignore_ascii_case("Location"));
        let raised = is_http_error(head.status_code) && !self.http_errors_to_file;
        self.out_file.is_some() && !redirect && !raised
    }
}

/// A connection kept open after a response, for the next request to the
/// same host and port under the same TLS requirement, through the same
/// proxy or none.
struct Idle {
    host: String,
    port: u16,
    post_quantum_only: bool,
    proxy: Option<ProxyAddress>,
    sock: TcpStream,
    conn: rustls::ClientConnection,
}

/// Takes from `idle` the connection kept for `target` under
/// `post_quantum_only` through `proxy`, if there is one.
fn take_idle(idle: &mut Vec<Idle>, target: &Target, post_quantum_only: bool, proxy: Option<&Proxy>) -> Option<Idle> {
    let through = proxy.map(|proxy| &proxy.address);
    let found = idle.iter().position(|kept| {
        kept.host.eq_ignore_ascii_case(&target.host) && kept.port == target.port && kept.post_quantum_only == post_quantum_only && kept.proxy.as_ref() == through
    })?;
    Some(idle.swap_remove(found))
}

/// What the worker thread brings back from one request.
struct Exchange {
    message: Message,
    /// What the TLS handshake that carried the response agreed.
    protocol: String,
    key_exchange: String,
    cipher_suite: String,
    /// The connection, when the job keeps connections and the response
    /// left this one fit for another request.
    idle: Option<Idle>,
    /// Whether the body went to the -OutFile file, which now holds it,
    /// rather than into the message.
    to_file: bool,
}

/// One request, as the worker thread makes it. A connection kept from an
/// earlier request is tried first; when the server has closed it before
/// answering, which a server may do to an idle connection, an idempotent
/// request (GET, HEAD, OPTIONS, PUT or DELETE) is made once more on a new
/// connection, and any other request fails as SecureFetchConnection rather
/// than being sent twice. Once `cancel` is stopped, whatever step is under
/// way returns SecureFetchStopped and no later step starts.
fn exchange(mut job: Job, cancel: &Cancel) -> PsResult<Exchange> {
    if let Some(idle) = job.idle.take() {
        if let Some(done) = send(&job, idle.sock, idle.conn, true, cancel)? {
            return Ok(done);
        }
        let method = job.outgoing.method.as_str();
        if !idempotent(method) {
            return Err(PsError::new(
                ErrorCategory::ConnectionError,
                "SecureFetchConnection",
                format!(
                    "{} closed the connection kept from an earlier request before answering this {method}; a {method} is not idempotent, so it is not sent again on a new connection",
                    job.target.host
                ),
            ));
        }
    }
    let (sock, conn) = open(&job, cancel)?;
    send(&job, sock, conn, false, cancel)?
        .ok_or_else(|| malformed(&job.target.host, "closed the connection before answering".to_string()))
}

/// Whether a request with `method` may be sent again after a connection
/// closed before its answer (RFC 9110 section 9.2.2): GET, HEAD, OPTIONS,
/// PUT and DELETE.
fn idempotent(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE")
}

/// A new connection to the job's target with its TLS handshake done:
/// resolves the host, connects, or tunnels through the job's proxy, and
/// completes the handshake, each wait bounded by the job's wait. The
/// handshake finishes before anything else is written, so under
/// `post_quantum_only` a server that cannot agree TLS 1.3 with
/// X25519MLKEM768 is refused, as SecureFetchNotPostQuantum, having been
/// sent nothing but the handshake.
fn open(job: &Job, cancel: &Cancel) -> PsResult<(TcpStream, rustls::ClientConnection)> {
    let host = job.target.host.as_str();
    let wait = job.wait;
    let mut sock = match &job.proxy {
        Some(proxy) => tunnel(job, proxy, cancel)?,
        None => {
            let addrs = resolve(host, wait, cancel, system_lookup(host, job.target.port))?;
            let sock = connect(host, &addrs, wait, cancel)?;
            watch(cancel, &sock, host)?;
            sock
        }
    };
    let mut conn = rustls::ClientConnection::new(Arc::clone(&job.config), job.target.server.clone())
        .map_err(|e| PsError::new(ErrorCategory::SecurityError, "SecureFetchTls", format!("cannot start a TLS session with {host}: {e}")))?;
    conn.complete_io(&mut sock).map_err(|e| {
        if job.post_quantum_only && !cancel.is_stopped() && refused_post_quantum(&e) {
            not_post_quantum(host, &e.to_string())
        } else if cancel.is_stopped() {
            stopped(host, None)
        } else {
            exchange_error(e, host, wait)
        }
    })?;
    if conn.is_handshaking() {
        return Err(PsError::new(ErrorCategory::SecurityError, "SecureFetchTls", format!("the handshake with {host} did not finish")));
    }
    if job.post_quantum_only {
        let agreed = (conn.protocol_version(), conn.negotiated_key_exchange_group().map(|group| group.name()));
        if agreed != (Some(rustls::ProtocolVersion::TLSv1_3), Some(rustls::NamedGroup::X25519MLKEM768)) {
            return Err(not_post_quantum(host, &format!("the handshake agreed {agreed:?}")));
        }
    }
    Ok((sock, conn))
}

/// Registers `sock` with `cancel`, then gives up with SecureFetchStopped
/// when a stop has already come.
fn watch(cancel: &Cancel, sock: &TcpStream, host: &str) -> PsResult<()> {
    cancel.watch(sock).map_err(|e| {
        PsError::new(ErrorCategory::ConnectionError, "SecureFetchConnection", format!("cannot keep a handle to the connection to {host} for a stop: {e}"))
    })?;
    match cancel.is_stopped() {
        true => Err(stopped(host, None)),
        false => Ok(()),
    }
}

/// Sends the job's request on `sock` and `conn`, a connection whose
/// handshake is done, and reads the response. When `kept` is set the
/// connection is one kept from an earlier request, and if the server closed
/// it before answering anything this returns Ok(None), so the request can
/// be made again on a new connection. The connection comes back with the
/// response when the job keeps connections and the response leaves it fit
/// for another request.
fn send(job: &Job, mut sock: TcpStream, mut conn: rustls::ClientConnection, kept: bool, cancel: &Cancel) -> PsResult<Option<Exchange>> {
    let host = job.target.host.as_str();
    let wait = job.wait;
    if kept {
        watch(cancel, &sock, host)?;
    }
    let (protocol, key_exchange, cipher_suite) = negotiated(&conn, host)?;
    let failed = |e: std::io::Error| if cancel.is_stopped() { stopped(host, None) } else { exchange_error(e, host, wait) };
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let head = job.outgoing.head(&job.target, job.keep_alive);
    let written = write_request(&mut tls, head.as_bytes(), job.outgoing.body.as_ref().map(|body| body.as_slice()), cancel);
    match written {
        Ok(()) => {}
        Err(e) if kept && !cancel.is_stopped() && closed_under_us(&e) => return Ok(None),
        Err(e) => return Err(failed(e)),
    }
    let mut input = Input::new(&mut tls, cancel, host, wait);
    if kept {
        match input.fill_raw() {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(e) if !cancel.is_stopped() && closed_under_us(&e) => return Ok(None),
            Err(e) => return Err(failed(e)),
        }
    }
    let bodiless = job.outgoing.method == "HEAD";
    let head = read_final_head(&mut input)?;
    let to_file = job.to_file(&head);
    let (trailers, framing, body) = match (&job.out_file, to_file) {
        (Some(path), true) => {
            let mut file = FileSink::create(path)?;
            match read_body(&mut input, &head, &mut file, job.max_decoded, bodiless) {
                Ok((trailers, framing)) => {
                    file.commit()?;
                    (trailers, framing, Vec::new())
                }
                Err(e) => return Err(file.discard(e)),
            }
        }
        _ => {
            let mut kept_body = Kept { host, body: Vec::new() };
            let (trailers, framing) = read_body(&mut input, &head, &mut kept_body, job.max_decoded, bodiless)?;
            (trailers, framing, kept_body.body)
        }
    };
    drop(input);
    let reusable = job.keep_alive && persistent(&head, framing);
    let message = Message { status_code: head.status_code, reason: head.reason, fields: head.fields, body, trailers };
    let idle = reusable.then(|| Idle {
        host: host.to_string(),
        port: job.target.port,
        post_quantum_only: job.post_quantum_only,
        proxy: job.proxy.as_ref().map(|proxy| proxy.address.clone()),
        sock,
        conn,
    });
    Ok(Some(Exchange { message, protocol, key_exchange, cipher_suite, idle, to_file }))
}

/// Writes a request's head to `out`, then its body in pieces of up to 64
/// KiB, checking `cancel` before each piece, so a stop during a long
/// upload ends it at the next piece rather than at the end of the body.
fn write_request<W: Write>(out: &mut W, head: &[u8], body: Option<&[u8]>, cancel: &Cancel) -> std::io::Result<()> {
    out.write_all(head)?;
    for piece in body.into_iter().flat_map(|bytes| bytes.chunks(64 * 1024)) {
        if cancel.is_stopped() {
            return Err(std::io::Error::other("the request was stopped while its body was being sent"));
        }
        out.write_all(piece)?;
    }
    out.flush()
}

/// Whether `e` is the server having closed or reset the connection, which
/// on a kept connection means it closed the idle connection before this
/// request reached it.
fn closed_under_us(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)
}

/// Whether the connection that carried the response `head`, delimited by
/// `framing`, can carry another request (RFC 9112 section 9.3): an
/// HTTP/1.1 or later response without `Connection: close`, whose body
/// ended where its framing said rather than at the connection's close.
fn persistent(head: &Head, framing: Framing) -> bool {
    let closes = head
        .fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Connection"))
        .flat_map(|(_, value)| value.split(','))
        .any(|option| option.trim_matches([' ', '\t']).eq_ignore_ascii_case("close"));
    head.version >= (1, 1) && !closes && framing != Framing::UntilClose
}

/// Whether `e`, a handshake that failed while only TLS 1.3 with
/// X25519MLKEM768 was offered, is the server turning that offer down: an
/// alert saying it shares no group or version with it (handshake_failure,
/// insufficient_security or protocol_version, which RFC 8446 sections
/// 4.1.1 and 4.2.1 name for those cases); rustls finding that the server
/// chose a version other than TLS 1.3 or shares no key exchange group;
/// the server asking to retry with a group that was not offered; or the
/// server closing or resetting the connection mid-handshake, which some
/// servers do instead of sending an alert. A wait that runs out is not a
/// refusal.
fn refused_post_quantum(e: &std::io::Error) -> bool {
    use rustls::AlertDescription::{HandshakeFailure, InsufficientSecurity, ProtocolVersion};
    use rustls::PeerIncompatible::{NoKxGroupsInCommon, ServerDoesNotSupportTls12Or13, ServerTlsVersionIsDisabledByOurConfig};
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::AlertReceived(alert)) => matches!(alert, HandshakeFailure | InsufficientSecurity | ProtocolVersion),
        Some(rustls::Error::PeerIncompatible(why)) => {
            matches!(why, NoKxGroupsInCommon | ServerDoesNotSupportTls12Or13 | ServerTlsVersionIsDisabledByOurConfig)
        }
        Some(rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup)) => true,
        Some(_) => false,
        None => matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted),
    }
}

/// SecureFetchNotPostQuantum for `host`, with `why` the handshake failed.
fn not_post_quantum(host: &str, why: &str) -> PsError {
    PsError::new(
        ErrorCategory::SecurityError,
        "SecureFetchNotPostQuantum",
        format!("{host} did not complete a TLS 1.3 handshake with X25519MLKEM768, the only key exchange -RequirePostQuantum offers: {why}"),
    )
}

/// The pipeline thread's hold on a request its worker thread is making:
/// a flag the worker checks after each step, and a second handle to the
/// worker's connection, so a stop can shut the connection down and the
/// server learns at once that the client has gone.
#[derive(Default)]
struct Cancel {
    stopped: AtomicBool,
    socket: Mutex<Option<TcpStream>>,
}

impl Cancel {
    /// Whether [`Cancel::stop`] has been called.
    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Keeps a second handle to `sock` for [`Cancel::stop`] to shut down.
    /// A stop that came before this call finds no connection to shut down,
    /// so the caller checks [`Cancel::is_stopped`] after it: the lock the
    /// two calls share orders them, so one of the two always sees the
    /// other.
    fn watch(&self, sock: &TcpStream) -> std::io::Result<()> {
        let second = sock.try_clone()?;
        *lock(&self.socket) = Some(second);
        Ok(())
    }

    /// Marks the request stopped and shuts its connection down, both
    /// directions. On Windows the shutdown does not end a receive already
    /// blocked on the connection (measured on Windows 11 build 26200); that
    /// receive returns when the server sends or closes, or when its own
    /// wait runs out. Returns the shutdown's failure, if any; a connection
    /// already closed is not one.
    fn stop(&self) -> Option<std::io::Error> {
        self.stopped.store(true, Ordering::SeqCst);
        let watched = lock(&self.socket).take();
        match watched.map(|sock| sock.shutdown(Shutdown::Both)) {
            None | Some(Ok(())) => None,
            Some(Err(e)) if e.kind() == ErrorKind::NotConnected => None,
            Some(Err(e)) => Some(e),
        }
    }
}

/// `mutex` locked. A panic on another thread while it was held leaves the
/// value whole, since every write to it is a single assignment, so a
/// poisoned lock is taken as it is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Why a wait on a helper thread ended before the thread did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Halt {
    /// The request was stopped.
    Stopped,
    /// The wait ran past its deadline.
    TimedOut,
}

/// Starts `work` on a new thread named `name`. The thread unparks the
/// thread that started it when `work` returns, so a [`wait_on`] there
/// wakes at once rather than at its next poll.
fn start<T, F>(name: &str, work: F) -> std::io::Result<JoinHandle<T>>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let waiter = std::thread::current();
    std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let value = work();
        waiter.unpark();
        value
    })
}

/// Waits for `worker` to finish, asking `halt` every [`POLL`] whether to
/// stop waiting, and returns what the worker returned. When `halt`
/// answers first, returns why, with the worker still running; dropping
/// that handle leaves the worker to finish on its own. A panic on the
/// worker resumes on this thread, so it reaches PWRS's boundary as a
/// panic in the cmdlet body would.
fn wait_on<T>(worker: JoinHandle<T>, mut halt: impl FnMut() -> Option<Halt>) -> Result<T, (Halt, JoinHandle<T>)> {
    loop {
        if worker.is_finished() {
            return match worker.join() {
                Ok(value) => Ok(value),
                Err(panic) => std::panic::resume_unwind(panic),
            };
        }
        if let Some(why) = halt() {
            return Err((why, worker));
        }
        std::thread::park_timeout(POLL);
    }
}

/// SecureFetchStopped for the request to `host`, naming the failure to
/// shut its connection down when there was one.
fn stopped(host: &str, unshut: Option<std::io::Error>) -> PsError {
    let message = match unshut {
        None => format!("the request to {host} was stopped"),
        Some(e) => format!("the request to {host} was stopped, and shutting its connection down failed: {e}"),
    };
    PsError::new(ErrorCategory::OperationStopped, "SecureFetchStopped", message)
}

/// The error for a thread the request to `host` needed and the system
/// would not start.
fn no_thread(host: &str, e: &std::io::Error) -> PsError {
    PsError::new(ErrorCategory::ResourceUnavailable, "SecureFetchOutOfMemory", format!("cannot start a thread for the request to {host}: {e}"))
}

/// `address` as an error record quotes it: the user information in its
/// authority, everything before the last `@` there, written as `***`, so
/// a password given in the address stays out of the record, `$Error` and
/// any transcript. The authority starts after the `://` of a scheme, or
/// at the start of an address without one, and ends at the first `/`,
/// `?` or `#`; an address with no `@` in it is quoted as it is.
fn masked(address: &str) -> String {
    let start = address.find("://").map_or(0, |i| i + 3);
    let end = address[start..].find(['/', '?', '#']).map_or(address.len(), |i| start + i);
    match address[start..end].rfind('@') {
        Some(at) => format!("{}***{}", &address[..start], &address[start + at..]),
        None => address.to_string(),
    }
}

/// Where one request goes, taken apart from an https:// address.
#[derive(Clone)]
struct Target {
    /// The host name or address, without the brackets an IPv6 address is written in.
    host: String,
    /// The host as TLS checks the server's certificate against it.
    server: ServerName<'static>,
    port: u16,
    /// The Host header: the host as the address wrote it, and the port unless it is 443.
    host_header: String,
    /// The path and query as a request target; see [`request_target`].
    request_target: String,
}

impl Target {
    /// Takes `https://host[:port][/path][?query][#fragment]` apart. The
    /// scheme matches without regard to case, and the fragment is dropped,
    /// since it is never sent. An address with another scheme, with user
    /// information, with no host, with a host that is neither a DNS name
    /// nor an IP address, or with a port outside 1 to 65535 is refused.
    fn parse(uri: &str) -> PsResult<Target> {
        let refuse = |id: &str, message: String| PsError::new(ErrorCategory::InvalidArgument, id, message);
        let rest = match uri.split_at_checked(8) {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https://") => rest,
            _ => return Err(refuse("SecureFetchNotHttps", format!("{} is not an https:// address", masked(uri)))),
        };
        let rest = match rest.split_once('#') {
            Some((before, _fragment)) => before,
            None => rest,
        };
        let (authority, path_and_query) = match rest.find(['/', '?']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(refuse("SecureFetchUserInfo", format!("{} carries user information, which this cmdlet does not send", masked(uri))));
        }
        let (host, port, bracketed) = match authority.strip_prefix('[') {
            Some(inner) => {
                let (host, after) = inner
                    .split_once(']')
                    .ok_or_else(|| refuse("SecureFetchBadHost", format!("{uri} opens an IPv6 address with [ and does not close it")))?;
                let port = match after {
                    "" => None,
                    _ => Some(after.strip_prefix(':').ok_or_else(|| refuse("SecureFetchBadHost", format!("{uri} has {after} after its IPv6 address")))?),
                };
                (host, port, true)
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port), false),
                None => (authority, None, false),
            },
        };
        if host.is_empty() {
            return Err(refuse("SecureFetchBadHost", format!("{uri} names no host")));
        }
        let port = match port {
            None | Some("") => 443,
            Some(text) => match text.parse::<u16>() {
                Ok(0) => return Err(refuse("SecureFetchBadPort", "0 is not a port: ports run from 1 to 65535".to_string())),
                Ok(port) => port,
                Err(e) => return Err(refuse("SecureFetchBadPort", format!("{text} is not a port: {e}"))),
            },
        };
        let server = ServerName::try_from(host.to_string())
            .map_err(|e| refuse("SecureFetchBadHost", format!("{host} is neither a DNS name nor an IP address: {e}")))?;
        let host_header = match (bracketed, port) {
            (true, 443) => format!("[{host}]"),
            (true, _) => format!("[{host}]:{port}"),
            (false, 443) => host.to_string(),
            (false, _) => format!("{host}:{port}"),
        };
        Ok(Target { host: host.to_string(), server, port, host_header, request_target: request_target(path_and_query) })
    }

    /// The address a request to this target is sent to, written out whole:
    /// `https://`, the host and any port as the Host field carries them,
    /// and the request target.
    fn address(&self) -> String {
        format!("https://{}{}", self.host_header, self.request_target)
    }

    /// The host and port as CONNECT names them (RFC 9110 section 9.3.6):
    /// `host:port`, an IPv6 address in brackets.
    fn authority(&self) -> String {
        match self.host.contains(':') {
            true => format!("[{}]:{}", self.host, self.port),
            false => format!("{}:{}", self.host, self.port),
        }
    }
}

/// The Location of `message` when it is a redirect to follow: a 301, 302,
/// 303, 307 or 308 with a Location field. None for any other response,
/// which is written as it is. Location carries one value, so a response
/// that repeats the field with different values, from `target`, is
/// SecureFetchBadResponse; the same value repeated is that value.
fn redirect_location(message: &Message, target: &Target) -> PsResult<Option<String>> {
    if !matches!(message.status_code, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let mut values = message.fields.iter().filter(|(name, _)| name.eq_ignore_ascii_case("Location")).map(|(_, value)| value.as_str());
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.any(|other| other != first) {
        return Err(malformed(&target.host, format!("redirected with a {} carrying Location fields that disagree", message.status_code)));
    }
    Ok(Some(first.to_string()))
}

/// Where a redirect from `base` with Location `location` leads: the
/// Location resolved against `base` as RFC 3986 section 5.2 resolves a
/// reference, which must be an https:// address. Another scheme is
/// SecureFetchRedirectNotHttps; an https:// address that cannot be sent,
/// such as one with no host or with user information, is
/// SecureFetchBadResponse, since the fault is the server's.
fn redirected_target(base: &Target, location: &str) -> PsResult<Target> {
    let (scheme, address) = resolve_reference(base, location);
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(PsError::new(
            ErrorCategory::SecurityError,
            "SecureFetchRedirectNotHttps",
            format!("{} redirected to {location}, which is not an https:// address, so it is not followed", base.address()),
        ));
    }
    Target::parse(&address).map_err(|e| malformed(&base.host, format!("redirected to {location}, which cannot be sent: {}", e.message)))
}

/// The parts of a URI reference (RFC 3986 appendix B) this module reads:
/// scheme, authority, path and query. The fragment is left out, since it
/// is never sent.
struct Reference<'a> {
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
}

/// `reference` taken apart as RFC 3986 appendix B's expression does: a
/// scheme is whatever comes before a colon that no `/` or `?` precedes.
fn split_reference(reference: &str) -> Reference<'_> {
    let rest = match reference.split_once('#') {
        Some((before, _fragment)) => before,
        None => reference,
    };
    let (scheme, rest) = match rest.find([':', '/', '?']) {
        Some(i) if rest.as_bytes()[i] == b':' => (Some(&rest[..i]), &rest[i + 1..]),
        _ => (None, rest),
    };
    let (authority, rest) = match rest.strip_prefix("//") {
        Some(after) => match after.find(['/', '?']) {
            Some(end) => (Some(&after[..end]), &after[end..]),
            None => (Some(after), ""),
        },
        None => (None, rest),
    };
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (rest, None),
    };
    Reference { scheme, authority, path, query }
}

/// `reference` resolved against `base` (RFC 3986 section 5.2.2, strict),
/// as its scheme and the absolute address, without a fragment. A
/// reference with a scheme and no authority, such as `https:path`, stays
/// without one, so its address is not an https:// address.
fn resolve_reference(base: &Target, reference: &str) -> (String, String) {
    let r = split_reference(reference);
    let (base_path, base_query) = match base.request_target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (base.request_target.as_str(), None),
    };
    let here = Some(base.host_header.as_str());
    let (scheme, authority, path, query) = match (r.scheme, r.authority) {
        (Some(scheme), authority) => (scheme, authority, remove_dot_segments(r.path), r.query),
        (None, Some(authority)) => ("https", Some(authority), remove_dot_segments(r.path), r.query),
        (None, None) if r.path.is_empty() => ("https", here, base_path.to_string(), r.query.or(base_query)),
        (None, None) if r.path.starts_with('/') => ("https", here, remove_dot_segments(r.path), r.query),
        (None, None) => ("https", here, remove_dot_segments(&merge_paths(base_path, r.path)), r.query),
    };
    let mut address = match authority {
        Some(authority) => format!("{scheme}://{authority}{path}"),
        None => format!("{scheme}:{path}"),
    };
    if let Some(query) = query {
        address.push('?');
        address.push_str(query);
    }
    (scheme.to_string(), address)
}

/// A relative path `path` joined to the base path `base` (RFC 3986 section
/// 5.2.3): everything in `base` up to and including its last `/`, then
/// `path`; `/` then `path` when `base` has no `/`.
fn merge_paths(base: &str, path: &str) -> String {
    match base.rfind('/') {
        Some(last) => format!("{}{path}", &base[..=last]),
        None => format!("/{path}"),
    }
}

/// `path` with its `.` and `..` segments applied and removed (RFC 3986
/// section 5.2.4).
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut output = String::new();
    let drop_last = |output: &mut String| match output.rfind('/') {
        Some(last) => output.truncate(last),
        None => output.clear(),
    };
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../").or_else(|| input.strip_prefix("./")) {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            drop_last(&mut output);
        } else if input == "/.." {
            input = "/";
            drop_last(&mut output);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = match input[start..].find('/') {
                Some(next) => start + next,
                None => input.len(),
            };
            output.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

/// `path_and_query` as a request target: a `/` first when it does not
/// start with one, and every byte other than the visible ASCII a request
/// target may carry written as %XX. A space, a control character or a
/// non-ASCII letter therefore reaches the server escaped and can never
/// end the request line early. A `%` is kept as it is, so an address that
/// is already escaped is sent unchanged.
fn request_target(path_and_query: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    if !path_and_query.starts_with('/') {
        out.push('/');
    }
    for &b in path_and_query.as_bytes() {
        if b.is_ascii_graphic() && !b"\"<>\\^`{|}".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
    }
    out
}

/// Header fields SecureFetch writes itself, which -Headers may not carry:
/// the host, the body's framing, and the connection's own management.
const OWNED_FIELDS: [&str; 9] = ["Host", "Content-Length", "Transfer-Encoding", "Connection", "TE", "Trailer", "Upgrade", "Keep-Alive", "Proxy-Connection"];

/// Header fields that describe a request's content, which RFC 9110 section
/// 15.4 has a client stop sending when a redirect turns the request into a
/// GET without its body.
const CONTENT_FIELDS: [&str; 4] = ["Content-Type", "Content-Encoding", "Content-Language", "Content-Location"];

/// Header fields that carry credentials, which are not sent on when a
/// redirect leads to another host or port.
const CREDENTIAL_FIELDS: [&str; 2] = ["Authorization", "Cookie"];

/// What a request sends besides its target and its Connection field.
struct Outgoing {
    /// The method, upper-cased.
    method: String,
    /// The header field lines sent after Host, in order: the defaults no
    /// -Headers entry replaced, then the -Headers entries.
    fields: Fields,
    /// The Content-Type sent after `fields`: -ContentType, or the body's
    /// default when neither -ContentType nor -Headers gives one.
    content_type: Option<String>,
    /// The body, shared with the requests redirects lead to; None sends
    /// none.
    body: Option<Arc<Vec<u8>>>,
}

/// One -Headers value, as the dictionary held it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Given {
    /// A string: one field line.
    One(String),
    /// An array whose elements are all strings: one field line each.
    Many(Vec<String>),
    /// Any other value, described by its type, such as `a System.Int32`.
    Other(String),
}

/// The -Body value, as the caller passed it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Payload {
    /// A string, sent as UTF-8.
    Text(String),
    /// A byte array, sent as it is.
    Bytes(Vec<u8>),
}

/// SecureFetchBadHeader: a -Headers entry or -ContentType that cannot be
/// sent, for the reason `message` gives.
fn bad_header(message: String) -> PsError {
    PsError::new(ErrorCategory::InvalidArgument, "SecureFetchBadHeader", message)
}

/// SecureFetchBadHeader for the -Headers entry `name`, whose value is
/// `described`, neither a string nor an array of strings.
fn unsendable_value(name: &str, described: &str) -> PsError {
    bad_header(format!("the {name} value is {described}; a -Headers value is a string or an array of strings"))
}

/// SecureFetchBadHeader for `field` given both as a -Headers entry, whose
/// value lines are `lines`, and by the parameter `by` describes with its
/// value, which would send the field twice. The message quotes both
/// values.
fn both_given(field: &str, lines: &[&str], by: &str) -> PsError {
    let entry = match lines {
        [] => "an empty array".to_string(),
        _ => lines.iter().map(|line| format!("{line:?}")).collect::<Vec<_>>().join(" and "),
    };
    bad_header(format!("{field} is given both in -Headers, as {entry}, and by {by}; give one of them"))
}

/// The first byte of `text` a field value cannot carry: a control byte,
/// 0x00 to 0x1F or 0x7F, other than a tab.
fn control_byte(text: &str) -> Option<u8> {
    text.bytes().find(|&b| (b < 0x20 && b != b'\t') || b == 0x7F)
}

/// Refuses `content_type` as the Content-Type of a string body, which is
/// sent as UTF-8, when it names a charset other than UTF-8 by any of the
/// WHATWG Encoding Standard's labels for it.
fn utf8_only(content_type: &str) -> PsResult<()> {
    match charset_label(content_type) {
        Some(label) if encoding_rs::Encoding::for_label(label.as_bytes()) != Some(encoding_rs::UTF_8) => {
            Err(bad_header(format!("a string -Body is sent as UTF-8, so its Content-Type cannot name the charset {label:?}: {content_type}")))
        }
        _ => Ok(()),
    }
}

impl Outgoing {
    /// The request an invocation sends, checked before any connection is
    /// made. `method` is sent upper-cased. `entries` are the -Headers
    /// entries in order: a name must be a token and not one of
    /// [`OWNED_FIELDS`], each value line must be free of control bytes
    /// other than tab, and an entry named User-Agent, Accept or
    /// Accept-Encoding replaces that default, an empty array dropping it.
    /// `compression` off asks for the identity encoding alone. The body,
    /// when there is one, goes with `content_type`, or else with a
    /// Content-Type from `entries`, or else with text/plain;
    /// charset=utf-8 for a string and application/octet-stream for bytes.
    /// A string body goes as UTF-8, so a Content-Type naming another
    /// charset is refused. Each refusal is SecureFetchBadHeader.
    fn new(method: &str, compression: bool, entries: Vec<(String, Given)>, payload: Option<Payload>, content_type: Option<&str>) -> PsResult<Outgoing> {
        let mut named: Vec<String> = Vec::new();
        let mut given: Fields = Vec::new();
        for (name, value) in entries {
            if !is_token(&name) {
                return Err(bad_header(format!(
                    "{name:?} is not a header field name, which is one or more letters, digits and the marks ! # $ % & ' * + - . ^ _ ` | ~"
                )));
            }
            if let Some(owned) = OWNED_FIELDS.iter().find(|owned| owned.eq_ignore_ascii_case(&name)) {
                return Err(bad_header(format!("{name} cannot be set through -Headers: SecureFetch writes the {owned} field itself")));
            }
            let lines = match value {
                Given::One(line) => vec![line],
                Given::Many(lines) => lines,
                Given::Other(described) => return Err(unsendable_value(&name, &described)),
            };
            for line in lines {
                if let Some(byte) = control_byte(&line) {
                    return Err(bad_header(format!("the {name} value carries the control byte 0x{byte:02X}, which a field value cannot carry")));
                }
                given.push((name.clone(), line));
            }
            named.push(name);
        }
        let names = |field: &str| named.iter().any(|name| name.eq_ignore_ascii_case(field));
        let lines_of = |field: &str| given.iter().filter(|(name, _)| name.eq_ignore_ascii_case(field)).map(|(_, line)| line.as_str()).collect::<Vec<_>>();
        if !compression && names("Accept-Encoding") {
            let by = format!("-NoCompression, which sends {:?}", accept_encoding(false));
            return Err(both_given("Accept-Encoding", &lines_of("Accept-Encoding"), &by));
        }
        if let Some(byte) = content_type.and_then(control_byte) {
            return Err(bad_header(format!("the -ContentType value carries the control byte 0x{byte:02X}, which a field value cannot carry")));
        }
        if let Some(verbatim) = content_type.filter(|_| names("Content-Type")) {
            let by = format!("-ContentType, as {verbatim:?}");
            return Err(both_given("Content-Type", &lines_of("Content-Type"), &by));
        }
        let appended = match (content_type, &payload) {
            (Some(verbatim), _) => Some(verbatim.to_string()),
            (None, _) if names("Content-Type") => None,
            (None, Some(Payload::Text(_))) => Some("text/plain; charset=utf-8".to_string()),
            (None, Some(Payload::Bytes(_))) => Some("application/octet-stream".to_string()),
            (None, None) => None,
        };
        if matches!(payload, Some(Payload::Text(_))) {
            let from_entries = given.iter().filter(|(name, _)| name.eq_ignore_ascii_case("Content-Type")).map(|(_, value)| value.as_str());
            for sent in appended.as_deref().into_iter().chain(from_entries) {
                utf8_only(sent)?;
            }
        }
        let user_agent = format!("SecureFetch/{}", env!("CARGO_PKG_VERSION"));
        let defaults = [("User-Agent", user_agent.as_str()), ("Accept", "*/*"), ("Accept-Encoding", accept_encoding(compression))];
        let mut fields: Fields = Vec::new();
        for (field, value) in defaults {
            if !names(field) {
                fields.push((field.to_string(), value.to_string()));
            }
        }
        fields.extend(given);
        let body = payload.map(|payload| {
            Arc::new(match payload {
                Payload::Text(text) => text.into_bytes(),
                Payload::Bytes(bytes) => bytes,
            })
        });
        Ok(Outgoing { method: method.to_ascii_uppercase(), fields, content_type: appended, body })
    }

    /// The request a redirect with `status` leads to (RFC 9110 section
    /// 15.4). A 303, and a 301 or 302 answering a POST, is followed with a
    /// GET, or with a HEAD when this is one, without the body, its
    /// Content-Type, or the -Headers fields in [`CONTENT_FIELDS`]; any
    /// other redirect keeps the method and the body. When `crossed`, the
    /// redirect leads to another host or port, and the fields in
    /// [`CREDENTIAL_FIELDS`] are not sent on.
    fn redirected(&self, status: u16, crossed: bool) -> Outgoing {
        let retrieval = status == 303 || (matches!(status, 301 | 302) && self.method == "POST");
        let dropped = |name: &str| {
            (crossed && CREDENTIAL_FIELDS.iter().any(|field| field.eq_ignore_ascii_case(name)))
                || (retrieval && CONTENT_FIELDS.iter().any(|field| field.eq_ignore_ascii_case(name)))
        };
        let method = match (retrieval, self.method.as_str()) {
            (true, "HEAD") | (false, _) => self.method.clone(),
            (true, _) => "GET".to_string(),
        };
        Outgoing {
            method,
            fields: self.fields.iter().filter(|(name, _)| !dropped(name)).cloned().collect(),
            content_type: if retrieval { None } else { self.content_type.clone() },
            body: if retrieval { None } else { self.body.clone() },
        }
    }

    /// The request's head for `target`: the request line, Host, the header
    /// fields, the body's Content-Type, a Connection field that states the
    /// policy (`close`, so the server closes the connection after the
    /// response, or `keep-alive` when `keep_alive` asks to keep it for the
    /// next request), and the body's Content-Length. A POST, PUT or PATCH
    /// without a body says Content-Length: 0, as RFC 9110 section 8.6 asks
    /// of a method that gives a body a meaning; any other method without
    /// one sends no Content-Length.
    fn head(&self, target: &Target, keep_alive: bool) -> String {
        let mut head = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", self.method, target.request_target, target.host_header);
        for (name, value) in &self.fields {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(content_type) = &self.content_type {
            head.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        head.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
        match &self.body {
            Some(body) => head.push_str(&format!("Content-Length: {}\r\n", body.len())),
            None if matches!(self.method.as_str(), "POST" | "PUT" | "PATCH") => head.push_str("Content-Length: 0\r\n"),
            None => {}
        }
        head.push_str("\r\n");
        head
    }
}

/// The entries of the -Headers dictionary `table`, in the order it gives
/// them, each key read as its text; none when it is null.
fn header_entries(table: &PsObject) -> PsResult<Vec<(String, Given)>> {
    if table.is_null() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in Vec::<PsObject>::from_ps(table)? {
        let name = String::from_ps(&entry.get("Key")?)?;
        let value = given(&entry.get("Value")?)?;
        entries.push((name, value));
    }
    Ok(entries)
}

/// What the -Headers value `value` asks for: one line for a string, one
/// line per element for an array whose elements are all strings (as
/// PowerShell's `'a', 'b'` makes), and otherwise a description of what it
/// is.
fn given(value: &PsObject) -> PsResult<Given> {
    if value.is_null() {
        return Ok(Given::Other("$null".to_string()));
    }
    if value.type_tag()? == pwrs::sys::PS_TYPE_STRING {
        return Ok(Given::One(String::from_ps(value)?));
    }
    let type_name = value.type_name()?;
    if !type_name.ends_with("[]") {
        return Ok(Given::Other(format!("a {type_name}")));
    }
    let mut lines = Vec::new();
    for element in Vec::<PsObject>::from_ps(value)? {
        if element.is_null() || element.type_tag()? != pwrs::sys::PS_TYPE_STRING {
            return Ok(Given::Other(format!("a {type_name} holding a value that is not a string")));
        }
        lines.push(String::from_ps(&element)?);
    }
    Ok(Given::Many(lines))
}

/// The -Body value `body`: None when it is null, the text of a string, or
/// a copy of the bytes of a byte array; any other type is
/// SecureFetchBadBody. The bytes are copied because the request is sent
/// from a worker thread that may outlive this phase, and the array is
/// only held for the phase.
fn payload_of(body: &PsObject) -> PsResult<Option<Payload>> {
    if body.is_null() {
        return Ok(None);
    }
    if body.type_tag()? == pwrs::sys::PS_TYPE_STRING {
        return Ok(Some(Payload::Text(String::from_ps(body)?)));
    }
    let type_name = body.type_name()?;
    if type_name != "System.Byte[]" {
        return Err(PsError::new(ErrorCategory::InvalidArgument, "SecureFetchBadBody", format!("-Body takes a string or a byte array, not a {type_name}")));
    }
    let pinned = body.pin::<u8>()?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(pinned.len()).map_err(|e| {
        PsError::new(ErrorCategory::ResourceUnavailable, "SecureFetchOutOfMemory", format!("cannot hold a copy of the {}-byte -Body: {e}", pinned.len()))
    })?;
    bytes.extend_from_slice(&pinned);
    Ok(Some(Payload::Bytes(bytes)))
}

/// The TLS client configuration: rustls over its aws-lc-rs provider,
/// verifying server certificates against `roots`. By default it enables
/// TLS 1.3 and 1.2 and the provider's default key exchange groups, which
/// put X25519MLKEM768 first. With `post_quantum_only` it enables TLS 1.3
/// alone and X25519MLKEM768 alone, so a server that lacks either cannot
/// complete the handshake. Session resumption is off, so every new
/// connection makes a full handshake with a key exchange of its own,
/// which is what its response reports.
fn client_config(post_quantum_only: bool, roots: rustls::RootCertStore) -> PsResult<Arc<rustls::ClientConfig>> {
    let unconfigured = |e: rustls::Error| PsError::new(ErrorCategory::SecurityError, "SecureFetchTls", format!("cannot configure TLS: {e}"));
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let builder = if post_quantum_only {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        rustls::ClientConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        rustls::ClientConfig::builder_with_provider(Arc::new(provider)).with_safe_default_protocol_versions()
    }
    .map_err(unconfigured)?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// The roots server certificates are verified against: those of the
/// sources `sources` names (-TrustedRoots, matched without regard to case)
/// and the certificates in `extra` (-RootCertificate). None beside another
/// source, or no root at all, is refused before any connection as
/// SecureFetchRootStore (InvalidArgument); so is a -RootCertificate rustls
/// cannot take as a root (SecurityError).
fn trusted_roots(ps: &Pipeline<'_>, sources: &[String], extra: &[RootCertificate]) -> PsResult<rustls::RootCertStore> {
    let (bundled, windows) = root_sources(sources, extra.len())?;
    let mut roots = rustls::RootCertStore::empty();
    if bundled {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if windows {
        for skipped in windows_roots(&mut roots)? {
            ps.verbose(&skipped)?;
        }
    }
    for certificate in extra {
        let der = Vec::<u8>::from_ps(&certificate.0.get("RawData")?)?;
        match roots.add(rustls::pki_types::CertificateDer::from(der)) {
            Ok(()) => {}
            Err(e) => {
                let subject = String::from_ps(&certificate.0.get("Subject")?)?;
                let thumbprint = String::from_ps(&certificate.0.get("Thumbprint")?)?;
                return Err(PsError::new(
                    ErrorCategory::SecurityError,
                    "SecureFetchRootStore",
                    format!("the -RootCertificate {subject} (thumbprint {thumbprint}) cannot be used as a root: {e}"),
                ));
            }
        }
    }
    Ok(roots)
}

/// Whether the -TrustedRoots values `sources`, matched without regard to
/// case, name the bundled roots and the Windows roots. None beside another
/// source, and sources that name no roots when `extra`, the number of
/// -RootCertificate entries, is 0, are SecureFetchRootStore
/// (InvalidArgument).
fn root_sources(sources: &[String], extra: usize) -> PsResult<(bool, bool)> {
    let named = |source: &str| sources.iter().any(|given| given.eq_ignore_ascii_case(source));
    let refused = |why: String| PsError::new(ErrorCategory::InvalidArgument, "SecureFetchRootStore", why);
    let (bundled, windows) = (named("Bundled"), named("Windows"));
    if named("None") && (bundled || windows) {
        return Err(refused(format!("-TrustedRoots {} names None beside a source of roots", sources.join(", "))));
    }
    if !bundled && !windows && extra == 0 {
        return Err(refused("no root is trusted: -TrustedRoots names no source of roots and no -RootCertificate is given, so no server could be verified".to_string()));
    }
    Ok((bundled, windows))
}

/// The object identifier of server authentication, the extended key usage
/// a root must allow to be kept from the Windows store.
#[cfg(windows)]
const SERVER_AUTHENTICATION: &str = "1.3.6.1.5.5.7.3.1";

/// Adds to `roots` the certificates of the current user's Root store
/// (Cert:\CurrentUser\Root, which also shows the machine's and Group
/// Policy's roots) that Windows lets authenticate servers and that are
/// valid now, read through the schannel crate. A store that cannot be
/// opened is SecureFetchRootStore (SecurityError). An entry whose uses or
/// validity cannot be read, or that rustls cannot take as a root, is
/// skipped; the notes returned name each one by its thumbprint, for the
/// verbose stream.
#[cfg(windows)]
fn windows_roots(roots: &mut rustls::RootCertStore) -> PsResult<Vec<String>> {
    use schannel::cert_context::ValidUses;
    let store = schannel::cert_store::CertStore::open_current_user("ROOT").map_err(|e| {
        PsError::new(ErrorCategory::SecurityError, "SecureFetchRootStore", format!("cannot open the current user's Root certificate store: {e}"))
    })?;
    let mut skipped = Vec::new();
    for certificate in store.certs() {
        let name = match certificate.fingerprint(schannel::cert_context::HashAlgorithm::sha1()) {
            Ok(sha1) => format!("with SHA-1 thumbprint {}", sha1.iter().map(|b| format!("{b:02X}")).collect::<String>()),
            Err(e) => format!("whose thumbprint cannot be read ({e})"),
        };
        let uses = match certificate.valid_uses() {
            Ok(uses) => uses,
            Err(e) => {
                skipped.push(format!("skipped the Windows root {name}: its uses cannot be read: {e}"));
                continue;
            }
        };
        let current = match certificate.is_time_valid() {
            Ok(current) => current,
            Err(e) => {
                skipped.push(format!("skipped the Windows root {name}: its validity cannot be read: {e}"));
                continue;
            }
        };
        let serves = match uses {
            ValidUses::All => true,
            ValidUses::Oids(oids) => oids.iter().any(|oid| oid == SERVER_AUTHENTICATION),
        };
        if !(current && serves) {
            continue;
        }
        match roots.add(rustls::pki_types::CertificateDer::from(certificate.to_der().to_vec())) {
            Ok(()) => {}
            Err(e) => skipped.push(format!("skipped the Windows root {name}: rustls cannot take it as a root: {e}")),
        }
    }
    Ok(skipped)
}

/// Windows roots on a system without a Windows certificate store: refused
/// as SecureFetchRootStore.
#[cfg(not(windows))]
fn windows_roots(_roots: &mut rustls::RootCertStore) -> PsResult<Vec<String>> {
    Err(PsError::new(ErrorCategory::SecurityError, "SecureFetchRootStore", "-TrustedRoots Windows names the Windows certificate store, and this system has none"))
}

/// The -TrustedRoots sources when the parameter is not given: the bundled
/// roots and the Windows certificate store.
#[cfg(windows)]
fn default_trusted_roots() -> Vec<String> {
    vec!["Bundled".to_string(), "Windows".to_string()]
}

/// The -TrustedRoots sources when the parameter is not given on a system
/// without a Windows certificate store: the bundled roots.
#[cfg(not(windows))]
fn default_trusted_roots() -> Vec<String> {
    vec!["Bundled".to_string()]
}

/// The system resolver's lookup of `host` and `port`, as work for the
/// resolver thread [`resolve`] starts.
fn system_lookup(host: &str, port: u16) -> impl FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static + use<> {
    let host = host.to_string();
    move || (host.as_str(), port).to_socket_addrs().map(Iterator::collect)
}

/// The addresses `lookup` finds for `host`. The lookup runs on a thread
/// of its own so that the wait for it ends when `wait` runs out, as
/// SecureFetchTimeout, or when `cancel` is stopped, as SecureFetchStopped.
/// The system resolver cannot be interrupted, so a lookup still running
/// then is left to finish on its own and its answer is dropped.
fn resolve<L>(host: &str, wait: Duration, cancel: &Cancel, lookup: L) -> PsResult<Vec<SocketAddr>>
where
    L: FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let unresolved = |what: String| PsError::new(ErrorCategory::ConnectionError, "SecureFetchResolve", what);
    let resolver = start("securefetch-resolve", lookup).map_err(|e| no_thread(host, &e))?;
    let deadline = Instant::now() + wait;
    let halt = || {
        if cancel.is_stopped() {
            Some(Halt::Stopped)
        } else if Instant::now() >= deadline {
            Some(Halt::TimedOut)
        } else {
            None
        }
    };
    match wait_on(resolver, halt) {
        Ok(Ok(addrs)) if addrs.is_empty() => Err(unresolved(format!("{host} resolved to no address"))),
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(unresolved(format!("cannot resolve {host}: {e}"))),
        Err((Halt::TimedOut, _still_running)) => Err(PsError::new(
            ErrorCategory::OperationTimeout,
            "SecureFetchTimeout",
            format!("resolving {host} took longer than {} s", wait.as_secs()),
        )),
        Err((Halt::Stopped, _still_running)) => Err(stopped(host, None)),
    }
}

/// A TCP connection to the first of `addrs` that accepts within `wait`,
/// with every later read and write on it bounded by `wait` as well. An
/// attempt in progress cannot be interrupted, so `cancel` is checked
/// before each one. When no address accepts, the error names every
/// address tried and why each one failed.
fn connect(host: &str, addrs: &[SocketAddr], wait: Duration, cancel: &Cancel) -> PsResult<TcpStream> {
    let mut failures: Vec<(SocketAddr, std::io::Error)> = Vec::new();
    for &addr in addrs {
        if cancel.is_stopped() {
            return Err(stopped(host, None));
        }
        match TcpStream::connect_timeout(&addr, wait) {
            Ok(sock) => {
                sock.set_read_timeout(Some(wait)).and_then(|()| sock.set_write_timeout(Some(wait))).map_err(|e| {
                    PsError::new(ErrorCategory::ConnectionError, "SecureFetchConnect", format!("cannot bound the waits on the connection to {addr}: {e}"))
                })?;
                return Ok(sock);
            }
            Err(e) => failures.push((addr, e)),
        }
    }
    if failures.is_empty() {
        return Err(PsError::new(ErrorCategory::ConnectionError, "SecureFetchResolve", format!("{host} resolved to no address")));
    }
    let tried = failures.iter().map(|(addr, e)| format!("{addr}: {e}")).collect::<Vec<_>>().join("; ");
    if failures.iter().all(|(_, e)| is_timeout(e)) {
        return Err(PsError::new(
            ErrorCategory::OperationTimeout,
            "SecureFetchTimeout",
            format!("no address of {host} accepted a connection within {} s ({tried})", wait.as_secs()),
        ));
    }
    Err(PsError::new(ErrorCategory::ConnectionError, "SecureFetchConnect", format!("cannot connect to {host} ({tried})")))
}

/// Where an HTTP proxy listens, taken apart from an http:// address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProxyAddress {
    /// The host name or address, without the brackets an IPv6 address is
    /// written in.
    host: String,
    port: u16,
}

impl ProxyAddress {
    /// Takes `http://host[:port][/]` apart, the scheme matched without
    /// regard to case; the port is 80, http's own, when not given. An
    /// https:// proxy, another scheme, user information, a path, no host,
    /// or a port outside 1 to 65535 is refused with the reason.
    fn parse(text: &str) -> Result<ProxyAddress, String> {
        let rest = match text.split_at_checked(7) {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http://") => rest,
            _ => {
                return Err(match text.split_at_checked(8) {
                    Some((scheme, _)) if scheme.eq_ignore_ascii_case("https://") => "is an https:// proxy, which this version does not support".to_string(),
                    _ => "is not an http:// proxy address".to_string(),
                });
            }
        };
        let authority = match rest.strip_suffix('/') {
            Some(before) => before,
            None => rest,
        };
        if authority.contains(['/', '?', '#']) {
            return Err("carries a path, which a proxy address does not".to_string());
        }
        if authority.contains('@') {
            return Err("carries user information; give the proxy's user name and password with -ProxyCredential".to_string());
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(inner) => {
                let Some((host, after)) = inner.split_once(']') else {
                    return Err("opens an IPv6 address with [ and does not close it".to_string());
                };
                match after {
                    "" => (host, None),
                    _ => match after.strip_prefix(':') {
                        Some(port) => (host, Some(port)),
                        None => return Err(format!("has {after} after its IPv6 address")),
                    },
                }
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        if host.is_empty() {
            return Err("names no host".to_string());
        }
        let port = match port {
            None | Some("") => 80,
            Some(text) => match text.parse::<u16>() {
                Ok(0) => return Err("names port 0, and ports run from 1 to 65535".to_string()),
                Ok(port) => port,
                Err(e) => return Err(format!("has a port that is not a port, {text}: {e}")),
            },
        };
        Ok(ProxyAddress { host: host.to_string(), port })
    }

    /// The address written out, as `http://host:port`.
    fn display(&self) -> String {
        match self.host.contains(':') {
            true => format!("http://[{}]:{}", self.host, self.port),
            false => format!("http://{}:{}", self.host, self.port),
        }
    }
}

/// A proxy a request goes through.
#[derive(Clone)]
struct Proxy {
    address: ProxyAddress,
    /// The Proxy-Authorization value, Basic, from -ProxyCredential.
    authorization: Option<String>,
}

/// SecureFetchProxy for a -Proxy value `given` that cannot be used, for
/// the reason `why` gives, refused before any connection. The value is
/// quoted with its user information masked.
fn proxy_refused(given: &str, why: String) -> PsError {
    PsError::new(ErrorCategory::InvalidArgument, "SecureFetchProxy", format!("-Proxy {} {why}", masked(given)))
}

/// SecureFetchProxy in `category` for the proxy `address`, which `why`.
/// The address is quoted with its user information masked.
fn proxy_error(category: ErrorCategory, address: &str, why: String) -> PsError {
    PsError::new(category, "SecureFetchProxy", format!("the proxy {} {why}", masked(address)))
}

/// The proxy the system names for `target`, asked of .NET the way the
/// host's own web cmdlets ask it: HttpClient.DefaultProxy in PowerShell 7,
/// which reads HTTPS_PROXY, ALL_PROXY and NO_PROXY and, when they are not
/// set, the user's proxy settings on Windows and the system's on macOS,
/// and WebRequest.GetSystemWebProxy() in Windows PowerShell 5.1. None when
/// it says to go direct, which GetProxy says by answering nothing or the
/// address itself.
fn system_proxy(ps: &Pipeline<'_>, target: &Target) -> PsResult<Option<String>> {
    let edition = String::from_ps(&ps.variable("PSVersionTable")?.call("get_Item", &["PSEdition".into_ps()?])?)?;
    let proxy = match edition.as_str() {
        "Core" => PsType::from_name("System.Net.Http.HttpClient").call_static("get_DefaultProxy", &[])?,
        _ => PsType::from_name("System.Net.WebRequest").call_static("GetSystemWebProxy", &[])?,
    };
    if proxy.is_null() {
        return Ok(None);
    }
    let address = PsType::from_name("System.Uri").new(&[target.address().into_ps()?])?;
    if bool::from_ps(&proxy.call("IsBypassed", std::slice::from_ref(&address))?)? {
        return Ok(None);
    }
    let through = proxy.call("GetProxy", std::slice::from_ref(&address))?;
    if through.is_null() {
        return Ok(None);
    }
    let through = String::from_ps(&through.get("AbsoluteUri")?)?;
    match through == String::from_ps(&address.get("AbsoluteUri")?)? {
        true => Ok(None),
        false => Ok(Some(through)),
    }
}

/// `bytes` in base64 (RFC 4648), with padding.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut three = [0u8; 3];
        three[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(three[0]) << 16) | (u32::from(three[1]) << 8) | u32::from(three[2]);
        let digit = |shift: u32| char::from(TABLE[((n >> shift) & 63) as usize]);
        out.push(digit(18));
        out.push(digit(12));
        out.push(if chunk.len() > 1 { digit(6) } else { '=' });
        out.push(if chunk.len() > 2 { digit(0) } else { '=' });
    }
    out
}

/// A connection to the job's target through `proxy`: the proxy's host is
/// resolved and connected to, the connection is registered with `cancel`,
/// and CONNECT asks the proxy for a tunnel to the target's host and port,
/// which the proxy resolves. A 2xx answer leaves the tunnel for TLS to run
/// through, end to end. Every failure before the tunnel is up is
/// SecureFetchProxy: AuthenticationError for a 407, ConnectionError for
/// anything else; a stop stays SecureFetchStopped.
fn tunnel(job: &Job, proxy: &Proxy, cancel: &Cancel) -> PsResult<TcpStream> {
    let shown = proxy.address.display();
    let at_proxy = |e: PsError| match e.error_id.as_str() {
        "SecureFetchStopped" => e,
        _ => proxy_error(ErrorCategory::ConnectionError, &shown, format!("could not be used: {}", e.message)),
    };
    let proxy_host = proxy.address.host.as_str();
    let addrs = resolve(proxy_host, job.wait, cancel, system_lookup(proxy_host, proxy.address.port)).map_err(at_proxy)?;
    let mut sock = connect(proxy_host, &addrs, job.wait, cancel).map_err(at_proxy)?;
    watch(cancel, &sock, &job.target.host)?;
    let authority = job.target.authority();
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(authorization) = &proxy.authorization {
        request.push_str(&format!("Proxy-Authorization: {authorization}\r\n"));
    }
    request.push_str("\r\n");
    let written = sock.write_all(request.as_bytes()).and_then(|()| sock.flush());
    if let Err(e) = written {
        return Err(match cancel.is_stopped() {
            true => stopped(&job.target.host, None),
            false => at_proxy(exchange_error(e, proxy_host, job.wait)),
        });
    }
    let mut input = Input::new(&mut sock, cancel, proxy_host, job.wait);
    let head = read_final_head(&mut input).map_err(at_proxy)?;
    let leftover = input.waiting().len();
    drop(input);
    match head.status_code {
        200..=299 if leftover == 0 => Ok(sock),
        200..=299 => Err(proxy_error(ErrorCategory::ConnectionError, &shown, format!("sent {leftover} bytes after its answer to CONNECT"))),
        407 => Err(proxy_error(
            ErrorCategory::AuthenticationError,
            &shown,
            match proxy.authorization {
                Some(_) => "refused the -ProxyCredential given (407 Proxy Authentication Required)".to_string(),
                None => "asks for credentials (407 Proxy Authentication Required); give them with -ProxyCredential".to_string(),
            },
        )),
        _ => Err(proxy_error(ErrorCategory::ConnectionError, &shown, format!("answered CONNECT {authority} with {}", status_text(head.status_code, &head.reason)))),
    }
}

/// Whether `e` is a socket wait that ran out, which Windows reports as
/// TimedOut and Unix as WouldBlock.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

/// What a failed read or write on the TLS stream to `host` becomes. A TLS
/// failure, such as a certificate that does not verify or an alert from
/// the server, is a security error; a wait longer than `wait` is a
/// timeout; anything else is a connection error.
fn exchange_error(e: std::io::Error, host: &str, wait: Duration) -> PsError {
    if let Some(tls) = e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        return PsError::new(ErrorCategory::SecurityError, "SecureFetchTls", format!("the TLS exchange with {host} failed: {tls}"));
    }
    if is_timeout(&e) {
        return PsError::new(
            ErrorCategory::OperationTimeout,
            "SecureFetchTimeout",
            format!("{host} kept the connection waiting longer than {} s", wait.as_secs()),
        );
    }
    PsError::new(ErrorCategory::ConnectionError, "SecureFetchConnection", format!("the connection to {host} failed: {e}"))
}

/// The bytes one connection delivers, read as they arrive and held until
/// they are taken. Each read is bounded by the socket's own wait, is
/// followed by a check of `cancel`, since a read that returns after a stop
/// may have been ended by the stop's shutdown rather than by the server,
/// and is reserved before it is kept, so a response too large for the
/// allocator is an error record rather than the end of the session.
struct Input<'a, R: Read> {
    stream: &'a mut R,
    cancel: &'a Cancel,
    host: &'a str,
    wait: Duration,
    /// Bytes read so far; those before `start` have been taken.
    held: Vec<u8>,
    start: usize,
    /// Whether the server has closed the connection. A close without
    /// TLS's close_notify alert counts, since many servers never send the
    /// alert; a response such a close cuts short is caught by its framing.
    closed: bool,
}

impl<'a, R: Read> Input<'a, R> {
    fn new(stream: &'a mut R, cancel: &'a Cancel, host: &'a str, wait: Duration) -> Self {
        Input { stream, cancel, host, wait, held: Vec::new(), start: 0, closed: false }
    }

    /// The bytes read and not yet taken.
    fn waiting(&self) -> &[u8] {
        &self.held[self.start..]
    }

    /// Reads once more from the connection, adding what arrives to the
    /// bytes held, and returns the connection's own error when it fails;
    /// memory refused for the bytes is an error of kind OutOfMemory.
    /// Returns false, having read nothing, once the server has closed the
    /// connection.
    fn fill_raw(&mut self) -> std::io::Result<bool> {
        if self.closed {
            return Ok(false);
        }
        if self.start > 0 {
            self.held.drain(..self.start);
            self.start = 0;
        }
        let mut chunk = [0u8; 16384];
        loop {
            let n = match self.stream.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => 0,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.closed = true;
                return Ok(false);
            }
            self.held.try_reserve(n).map_err(|e| std::io::Error::new(ErrorKind::OutOfMemory, e))?;
            self.held.extend_from_slice(&chunk[..n]);
            return Ok(true);
        }
    }

    /// [`Input::fill_raw`] with its error made an error record, and
    /// SecureFetchStopped when the request was stopped while it read.
    fn fill(&mut self) -> PsResult<bool> {
        let filled = self.fill_raw();
        if self.cancel.is_stopped() {
            return Err(stopped(self.host, None));
        }
        filled.map_err(|e| match e.kind() {
            ErrorKind::OutOfMemory => out_of_memory(self.host, &e),
            _ => exchange_error(e, self.host, self.wait),
        })
    }

    /// The next line, without its line ending: CRLF, or a bare LF, which
    /// RFC 9112 lets a recipient accept. None when the server closed the
    /// connection before the line ended.
    fn line(&mut self) -> PsResult<Option<Vec<u8>>> {
        let mut scanned = 0;
        loop {
            if let Some(offset) = self.waiting()[scanned..].iter().position(|&b| b == b'\n') {
                let end = self.start + scanned + offset;
                let mut content = &self.held[self.start..end];
                if let Some(without_cr) = content.strip_suffix(b"\r") {
                    content = without_cr;
                }
                let mut line = Vec::new();
                line.try_reserve(content.len()).map_err(|e| out_of_memory(self.host, &e))?;
                line.extend_from_slice(content);
                self.start = end + 1;
                return Ok(Some(line));
            }
            scanned = self.waiting().len();
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    /// Moves into `buf` as many of the bytes held as fit, but no more than
    /// `limit`, reading once from the connection first when none are held.
    /// Returns how many it moved, which is 0 only when the server has
    /// closed the connection (or `buf` or `limit` is empty).
    fn take(&mut self, buf: &mut [u8], limit: u64) -> PsResult<usize> {
        if self.waiting().is_empty() && !self.fill()? {
            return Ok(0);
        }
        let n = (self.waiting().len().min(buf.len()) as u64).min(limit) as usize;
        buf[..n].copy_from_slice(&self.waiting()[..n]);
        self.start += n;
        Ok(n)
    }
}

/// Where a response's body goes as it arrives.
trait Sink {
    /// Takes the next bytes of the body.
    fn put(&mut self, bytes: &[u8]) -> PsResult<()>;
}

/// A body kept in memory, each piece reserved before it is kept.
struct Kept<'a> {
    host: &'a str,
    body: Vec<u8>,
}

impl Sink for Kept<'_> {
    fn put(&mut self, bytes: &[u8]) -> PsResult<()> {
        self.body.try_reserve(bytes.len()).map_err(|e| out_of_memory(self.host, &e))?;
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

/// A body written to a temporary file in the folder of `target`, the file
/// -OutFile names, which replaces `target` only once the whole body has
/// arrived. The request's own thread writes it; the body never has to fit
/// in memory.
struct FileSink {
    target: PathBuf,
    temp: PathBuf,
    file: std::fs::File,
}

impl FileSink {
    /// A new temporary file beside `target`, named after it with 16 random
    /// hexadecimal digits and `.securefetch-partial` added, created only
    /// when no file of that name exists.
    fn create(target: &Path) -> PsResult<FileSink> {
        let mut random = [0u8; 8];
        rustls::crypto::aws_lc_rs::default_provider()
            .secure_random
            .fill(&mut random)
            .map_err(|e| write_failed(target, format!("cannot draw a random name for its temporary file: {e:?}")))?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let Some(name) = target.file_name() else {
            return Err(write_failed(target, "it names no file".to_string()));
        };
        let temp = target.with_file_name(format!("{}.{suffix}.securefetch-partial", name.to_string_lossy()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| write_failed(target, format!("cannot create the temporary file {}: {e}", temp.display())))?;
        Ok(FileSink { target: target.to_path_buf(), temp, file })
    }

    /// Makes the temporary file durable, closes it, and renames it over
    /// the target, replacing the target when it exists. When any step
    /// fails the temporary file is deleted and the target is left as it
    /// was.
    fn commit(self) -> PsResult<()> {
        let FileSink { target, temp, file } = self;
        let synced = file.sync_all();
        drop(file);
        if let Err(e) = synced {
            return Err(remove_temp(&temp, write_failed(&target, format!("cannot finish writing {}: {e}", temp.display()))));
        }
        std::fs::rename(&temp, &target).map_err(|e| remove_temp(&temp, write_failed(&target, format!("cannot replace it with {}: {e}", temp.display()))))
    }

    /// `e`, the error that ended the body, after the temporary file is
    /// closed and deleted, leaving the target as it was.
    fn discard(self, e: PsError) -> PsError {
        let FileSink { temp, file, .. } = self;
        drop(file);
        remove_temp(&temp, e)
    }
}

impl Sink for FileSink {
    fn put(&mut self, bytes: &[u8]) -> PsResult<()> {
        self.file.write_all(bytes).map_err(|e| write_failed(&self.target, format!("cannot write to {}: {e}", self.temp.display())))
    }
}

/// `e` after deleting the temporary file `temp`; a failure to delete it is
/// added to the message, naming the file left behind.
fn remove_temp(temp: &Path, mut e: PsError) -> PsError {
    if let Err(removal) = std::fs::remove_file(temp) {
        e.message = format!("{}; the temporary file {} could not be deleted: {removal}", e.message, temp.display());
    }
    e
}

/// SecureFetchWriteFailed: the body could not be written to `target`, the
/// file -OutFile names, for the reason `why` gives.
fn write_failed(target: &Path, why: String) -> PsError {
    PsError::new(ErrorCategory::WriteError, "SecureFetchWriteFailed", format!("cannot write the body to {}: {why}", target.display()))
}

/// The file -OutFile `path` names, resolved against the current location
/// by PowerShell's own path resolution, as Invoke-WebRequest resolves it.
/// It must be in the FileSystem provider, in a folder that exists, and not
/// itself a folder; anything else is SecureFetchBadOutFile, before any
/// connection is made.
fn out_file_path(ps: &Pipeline<'_>, path: &str) -> PsResult<PathBuf> {
    let refused = |why: String| PsError::new(ErrorCategory::InvalidArgument, "SecureFetchBadOutFile", format!("-OutFile {path} {why}"));
    let paths = ps.variable("ExecutionContext")?.get("SessionState")?.get("Path")?;
    let reference = || PsType::from_name("System.Management.Automation.PSReference").new(&[PsObject::null()]);
    let (provider, drive) = (reference()?, reference()?);
    let resolved = paths
        .call("GetUnresolvedProviderPathFromPSPath", &[path.into_ps()?, provider.clone(), drive])
        .map_err(|e| refused(format!("cannot be resolved: {}", e.message)))?;
    let resolved = PathBuf::from(String::from_ps(&resolved)?);
    let provider = String::from_ps(&provider.get("Value")?.get("Name")?)?;
    if provider != "FileSystem" {
        return Err(refused(format!("is a path of the {provider} provider, not a file system path")));
    }
    if resolved.is_dir() {
        return Err(refused(format!("names the folder {}, not a file", resolved.display())));
    }
    match resolved.parent() {
        Some(folder) if folder.is_dir() => Ok(resolved),
        _ => Err(refused(format!("is in a folder that does not exist: {}", resolved.display()))),
    }
}

/// SecureFetchOutOfMemory for a response from `host` the allocator would
/// not make room for.
fn out_of_memory(host: &str, e: &impl std::fmt::Display) -> PsError {
    PsError::new(ErrorCategory::ResourceUnavailable, "SecureFetchOutOfMemory", format!("cannot hold the response from {host}: {e}"))
}

/// The protocol version, key exchange group and cipher suite a finished
/// handshake agreed, in rustls' names for them.
fn negotiated(conn: &rustls::ClientConnection, host: &str) -> PsResult<(String, String, String)> {
    let missing = |what: &str| {
        PsError::new(ErrorCategory::SecurityError, "SecureFetchTls", format!("the handshake with {host} finished without a {what}"))
    };
    let protocol = conn.protocol_version().ok_or_else(|| missing("protocol version"))?;
    let group = conn.negotiated_key_exchange_group().ok_or_else(|| missing("key exchange group"))?;
    let suite = conn.negotiated_cipher_suite().ok_or_else(|| missing("cipher suite"))?;
    Ok((format!("{protocol:?}"), format!("{:?}", group.name()), format!("{:?}", suite.suite())))
}

/// Field lines as names and values, in arrival order.
type Fields = Vec<(String, String)>;

/// A response as it arrived, taken apart.
struct Message {
    status_code: u16,
    /// The reason phrase; empty when the status line has none.
    reason: String,
    /// Each header field line's name and value, in arrival order.
    fields: Fields,
    body: Vec<u8>,
    /// Each field line of a chunked body's trailer section, in arrival
    /// order; empty for any other body.
    trailers: Fields,
}

/// A response's status line and header section, taken apart.
struct Head {
    /// The major and minor version of the status line's `HTTP/x.y`.
    version: (u8, u8),
    status_code: u16,
    /// The reason phrase; empty when the status line has none.
    reason: String,
    /// Each header field line's name and value, in arrival order.
    fields: Fields,
}

/// How a response's body is delimited (RFC 9112 section 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    /// No body at all: a 204 or 304 response, or a response to HEAD,
    /// whatever its fields say.
    Empty,
    /// Exactly this many bytes, as Content-Length announced.
    Length(u64),
    /// The chunked transfer coding, which ends with its trailer section.
    Chunked,
    /// Everything until the server closes the connection.
    UntilClose,
}

/// SecureFetchBadResponse for a response from `host` that `what`.
fn malformed(host: &str, what: String) -> PsError {
    PsError::new(ErrorCategory::ProtocolError, "SecureFetchBadResponse", format!("the response from {host} {what}"))
}

/// Reads the status line and header section of the final response from
/// `input`, on which the request has been sent. Interim 1xx responses
/// before it are read and dropped; a 101 is refused, since no upgrade is
/// asked for.
fn read_final_head<R: Read>(input: &mut Input<'_, R>) -> PsResult<Head> {
    let host = input.host;
    loop {
        let head = read_head(input)?;
        match head.status_code {
            101 => return Err(malformed(host, "switched protocols (101) though no upgrade was asked for".to_string())),
            100..=199 => continue,
            _ => return Ok(head),
        }
    }
}

/// Reads from `input` the body of the response whose status line and
/// header section are `head`, decoded from its content codings, into
/// `sink` as it arrives; it ends where its framing says, so a server that
/// keeps the connection open after it is not waited for. A decoded body
/// larger than `limit` bytes is SecureFetchTooLarge; a body sent without a
/// content coding is not bounded this way. When `bodiless` is set, as it
/// is for the response to a HEAD, there is no body whatever the fields say
/// (RFC 9112 section 6.3), since they describe the body a GET would have
/// had. Returns the trailer fields of a chunked body and the framing the
/// body had.
fn read_body<R: Read, S: Sink>(input: &mut Input<'_, R>, head: &Head, sink: &mut S, limit: u64, bodiless: bool) -> PsResult<(Fields, Framing)> {
    let host = input.host;
    let framed = match bodiless {
        true => Framing::Empty,
        false => framing(head, host)?,
    };
    let codings = match framed {
        Framing::Empty => Vec::new(),
        _ => content_codings(head, host)?,
    };
    let mut trailers = Fields::new();
    let body = Body::new(input, framed, &mut trailers);
    decode(body, &codings, limit, sink, host)?;
    Ok((trailers, framed))
}

/// A content coding this version decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Coding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    /// The coding's name in Content-Encoding.
    fn name(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
        }
    }
}

/// What a request's Accept-Encoding asks for: every coding [`Coding`]
/// decodes, or only identity when `compression` is off.
fn accept_encoding(compression: bool) -> &'static str {
    match compression {
        true => "gzip, deflate, br, zstd",
        false => "identity",
    }
}

/// The content codings the response `head` was sent with, in the order
/// the server applied them, identity left out. A coding this version does
/// not decode is SecureFetchEncoding.
fn content_codings(head: &Head, host: &str) -> PsResult<Vec<Coding>> {
    let mut codings = Vec::new();
    let named = head.fields.iter().filter(|(name, _)| name.eq_ignore_ascii_case("Content-Encoding")).flat_map(|(_, value)| value.split(','));
    for name in named.map(|c| c.trim_matches([' ', '\t'])).filter(|c| !c.is_empty()) {
        let coding = match name.to_ascii_lowercase().as_str() {
            "identity" => continue,
            "gzip" | "x-gzip" => Coding::Gzip,
            "deflate" => Coding::Deflate,
            "br" => Coding::Brotli,
            "zstd" => Coding::Zstd,
            _ => {
                return Err(PsError::new(
                    ErrorCategory::NotImplemented,
                    "SecureFetchEncoding",
                    format!("the response from {host} is sent with Content-Encoding: {name}, which this version does not decode"),
                ))
            }
        };
        codings.push(coding);
    }
    Ok(codings)
}

/// Reads `body` through a decoder for each of `codings`, the last applied
/// first, and passes what comes out to `sink` in pieces of up to 64 KiB.
/// With any coding, more than `limit` decoded bytes is SecureFetchTooLarge.
/// A failure the body reader reports comes back as the error record it
/// carries; a failure of a decoder itself is SecureFetchBadResponse.
fn decode<R: Read, S: Sink>(body: Body<'_, '_, R>, codings: &[Coding], limit: u64, sink: &mut S, host: &str) -> PsResult<()> {
    let described = codings.iter().map(|c| c.name()).collect::<Vec<_>>().join(", ");
    let failed = |e: std::io::Error| body_error(e, host, &described);
    let mut reader: Box<dyn Read + '_> = Box::new(body);
    for &coding in codings.iter().rev() {
        reader = match coding {
            Coding::Gzip => Box::new(flate2::read::MultiGzDecoder::new(reader)),
            Coding::Deflate => deflate_reader(reader).map_err(failed)?,
            Coding::Brotli => Box::new(brotli_decompressor::Decompressor::new(reader, 64 * 1024)),
            Coding::Zstd => Box::new(ruzstd::decoding::StreamingDecoder::new(reader).map_err(|e| {
                PsError::new(ErrorCategory::ProtocolError, "SecureFetchBadResponse", format!("the response from {host} has a zstd body that does not decode: {e}"))
            })?),
        };
    }
    let bounded = !codings.is_empty();
    let mut buf = vec![0u8; 64 * 1024];
    let mut decoded = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(failed(e)),
        };
        decoded = decoded.saturating_add(n as u64);
        if bounded && decoded > limit {
            return Err(PsError::new(
                ErrorCategory::LimitsExceeded,
                "SecureFetchTooLarge",
                format!("the {described} body from {host} decodes to more than {limit} bytes, the -MaximumDecodedBytes bound"),
            ));
        }
        sink.put(&buf[..n])?;
    }
}

/// A reader of the deflate coding over `reader`. RFC 9110 defines deflate
/// as the zlib format, and some servers send the raw deflate format
/// instead, so the first two bytes decide: a valid zlib header (method 8,
/// and the header a multiple of 31) is read as zlib, anything else as raw
/// deflate.
fn deflate_reader<'r>(mut reader: Box<dyn Read + 'r>) -> std::io::Result<Box<dyn Read + 'r>> {
    let mut first = [0u8; 2];
    let mut got = 0;
    while got < first.len() {
        match reader.read(&mut first[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let zlib = got == 2 && first[0] & 0x0F == 8 && (u16::from(first[0]) << 8 | u16::from(first[1])) % 31 == 0;
    let whole = std::io::Cursor::new(first[..got].to_vec()).chain(reader);
    Ok(match zlib {
        true => Box::new(flate2::read::ZlibDecoder::new(whole)),
        false => Box::new(flate2::read::DeflateDecoder::new(whole)),
    })
}

/// The error record for `e`, a failed read of a body sent with the content
/// codings `described`: the record the body reader wrapped in it, or
/// SecureFetchBadResponse when a decoder found the bytes do not decode.
fn body_error(e: std::io::Error, host: &str, described: &str) -> PsError {
    let message = e.to_string();
    match e.into_inner().map(|inner| inner.downcast::<PsError>()) {
        Some(Ok(record)) => *record,
        Some(Err(other)) => malformed(host, format!("has a {described} body that does not decode: {other}")),
        None => malformed(host, format!("has a {described} body that does not decode: {message}")),
    }
}

/// Where a framed body stands between reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// A Content-Length body with this many bytes left of `total`.
    Length { left: u64, total: u64 },
    /// A chunked body, at the start of a chunk size line.
    ChunkSize,
    /// A chunked body, with this many bytes left of the current chunk.
    Chunk(u64),
    /// A chunked body, after a chunk's data and before the line end that
    /// closes it.
    ChunkEnd,
    /// A body that ends when the server closes the connection.
    UntilClose,
    /// The body has ended.
    Done,
}

/// The body of one response as a reader: the bytes its framing delimits,
/// with chunk size lines and the trailer section taken out, which reads
/// as ended where the framing says. A failure reads as an io::Error that
/// wraps the error record saying what failed; [`body_error`] takes it back
/// out. The trailer fields of a chunked body land in `trailers`.
struct Body<'i, 'a, R: Read> {
    input: &'i mut Input<'a, R>,
    stage: Stage,
    /// The body bytes read so far, for the message of a body cut short.
    passed: u64,
    trailers: &'i mut Fields,
}

impl<'i, 'a, R: Read> Body<'i, 'a, R> {
    fn new(input: &'i mut Input<'a, R>, framing: Framing, trailers: &'i mut Fields) -> Self {
        let stage = match framing {
            Framing::Empty | Framing::Length(0) => Stage::Done,
            Framing::Length(total) => Stage::Length { left: total, total },
            Framing::Chunked => Stage::ChunkSize,
            Framing::UntilClose => Stage::UntilClose,
        };
        Body { input, stage, passed: 0, trailers }
    }

    /// SecureFetchTruncated for a chunked body the connection closed inside.
    fn cut_short(&self) -> PsError {
        PsError::new(
            ErrorCategory::ProtocolError,
            "SecureFetchTruncated",
            format!("the response from {} ended inside its chunked body, after {} body bytes", self.input.host, self.passed),
        )
    }

    /// Moves the next body bytes into `buf`, which is not empty, and
    /// returns how many; 0 once the body has ended.
    fn next(&mut self, buf: &mut [u8]) -> PsResult<usize> {
        let host = self.input.host;
        loop {
            match self.stage {
                Stage::Done => return Ok(0),
                Stage::UntilClose => {
                    let n = self.input.take(buf, u64::MAX)?;
                    if n == 0 {
                        self.stage = Stage::Done;
                    }
                    self.passed += n as u64;
                    return Ok(n);
                }
                Stage::Length { left, total } => {
                    let n = self.input.take(buf, left)?;
                    if n == 0 {
                        return Err(PsError::new(
                            ErrorCategory::ProtocolError,
                            "SecureFetchTruncated",
                            format!("the response from {host} ended after {} of the {total} body bytes its Content-Length announced", self.passed),
                        ));
                    }
                    self.passed += n as u64;
                    self.stage = match left - n as u64 {
                        0 => Stage::Done,
                        rest => Stage::Length { left: rest, total },
                    };
                    return Ok(n);
                }
                Stage::ChunkSize => {
                    let Some(line) = self.input.line()? else {
                        return Err(self.cut_short());
                    };
                    let size = chunk_size(&line)
                        .ok_or_else(|| malformed(host, format!("has a chunk size line that is not a chunk size: {}", String::from_utf8_lossy(&line))))?;
                    if size == 0 {
                        *self.trailers = self.read_trailers()?;
                        self.stage = Stage::Done;
                    } else {
                        self.stage = Stage::Chunk(size);
                    }
                }
                Stage::Chunk(left) => {
                    let n = self.input.take(buf, left)?;
                    if n == 0 {
                        return Err(self.cut_short());
                    }
                    self.passed += n as u64;
                    self.stage = match left - n as u64 {
                        0 => Stage::ChunkEnd,
                        rest => Stage::Chunk(rest),
                    };
                    return Ok(n);
                }
                Stage::ChunkEnd => match self.input.line()? {
                    Some(after) if after.is_empty() => self.stage = Stage::ChunkSize,
                    Some(_) => return Err(malformed(host, "has a chunk longer than its chunk size".to_string())),
                    None => return Err(self.cut_short()),
                },
            }
        }
    }

    /// The fields of the trailer section after the last chunk, which ends at
    /// the first empty line.
    fn read_trailers(&mut self) -> PsResult<Fields> {
        let mut lines = Vec::new();
        loop {
            match self.input.line()? {
                None => return Err(self.cut_short()),
                Some(line) if line.is_empty() => break,
                Some(line) => lines.push(line),
            }
        }
        field_lines(&lines, self.input.host, "trailer")
    }
}

impl<R: Read> Read for Body<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.next(buf).map_err(std::io::Error::other)
    }
}

/// Reads a status line and the header section after it, which ends at the
/// first empty line.
///
/// The status line reads `HTTP/`, a digit, a dot and a digit, a space and
/// a three-digit code from 100 up, then a space and the reason phrase when
/// there is one. Lines end in CRLF or in a bare LF.
fn read_head<R: Read>(input: &mut Input<'_, R>) -> PsResult<Head> {
    let host = input.host;
    let unfinished = || malformed(host, "has no end to its header section".to_string());
    let Some(status_line) = input.line()? else {
        return Err(unfinished());
    };
    let status_line = String::from_utf8_lossy(&status_line).into_owned();
    let (version, status_code, reason) =
        status_parts(&status_line).ok_or_else(|| malformed(host, format!("starts with a line that is not an HTTP status line: {status_line}")))?;
    let reason = reason.to_string();
    let mut lines = Vec::new();
    loop {
        match input.line()? {
            None => return Err(unfinished()),
            Some(line) if line.is_empty() => break,
            Some(line) => lines.push(line),
        }
    }
    let fields = field_lines(&lines, host, "header")?;
    Ok(Head { version, status_code, reason, fields })
}

/// The field lines of a header or trailer section, `section` naming which
/// in an error, as names and values. A line starting with a space or a tab
/// continues the field line before it (obsolete line folding) and is
/// joined to it with one space. A field name must be an RFC 9110 token.
fn field_lines(lines: &[Vec<u8>], host: &str, section: &str) -> PsResult<Vec<(String, String)>> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = String::from_utf8_lossy(line);
        if line.starts_with([' ', '\t']) {
            let Some((_, value)) = fields.last_mut() else {
                return Err(malformed(host, format!("continues a {section} field before sending one: {line}")));
            };
            let more = line.trim_matches([' ', '\t']);
            if !more.is_empty() {
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(more);
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(malformed(host, format!("has a {section} line with no colon: {line}")));
        };
        if !is_token(name) {
            return Err(malformed(host, format!("has a {section} field name that is not a token: {name}")));
        }
        fields.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    Ok(fields)
}

/// The version, status code and reason phrase of `line` when it is a
/// status line: `HTTP/`, a digit, a dot and a digit, a space, three digits
/// making a code from 100 to 999, then a space and the reason phrase,
/// which may be empty or absent.
fn status_parts(line: &str) -> Option<((u8, u8), u16, &str)> {
    let rest = line.strip_prefix("HTTP/")?;
    let (version, rest) = rest.split_once(' ')?;
    let version = match *version.as_bytes() {
        [major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => (major - b'0', minor - b'0'),
        _ => return None,
    };
    let (code, reason) = match rest.split_once(' ') {
        Some(parts) => parts,
        None => (rest, ""),
    };
    match *code.as_bytes() {
        [a @ b'1'..=b'9', b @ b'0'..=b'9', c @ b'0'..=b'9'] => {
            Some((version, u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0'), reason))
        }
        _ => None,
    }
}

/// Whether `s` is an RFC 9110 token: one or more letters, digits and the
/// marks ! # $ % & ' * + - . ^ _ ` | ~.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// How the body of the response `head` describes is delimited, after
/// refusing framing this version cannot hand on right. A 204 or 304 has
/// no body. Otherwise a transfer coding other than chunked is
/// SecureFetchEncoding; Transfer-Encoding beside Content-Length, and
/// Transfer-Encoding in an HTTP/1.0 response, are SecureFetchBadResponse,
/// since RFC 9112 section 6.1 has a recipient treat such framing as
/// faulty; Content-Length values must be decimal numbers and, when
/// repeated, the same number.
fn framing(head: &Head, host: &str) -> PsResult<Framing> {
    if matches!(head.status_code, 204 | 304) {
        return Ok(Framing::Empty);
    }
    let values = |name: &'static str| head.fields.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    let undecoded = |field: &str, value: &str| {
        PsError::new(
            ErrorCategory::NotImplemented,
            "SecureFetchEncoding",
            format!("the response from {host} is sent with {field}: {value}, which this version does not decode"),
        )
    };
    let mut announced: Option<u64> = None;
    for item in values("Content-Length").flat_map(|v| v.split(',')) {
        let item = item.trim_matches([' ', '\t']);
        let n = decimal(item).ok_or_else(|| malformed(host, format!("has a Content-Length that is not a length: {item}")))?;
        if announced.is_some_and(|a| a != n) {
            return Err(malformed(host, "has Content-Length values that disagree".to_string()));
        }
        announced = Some(n);
    }
    let codings: Vec<&str> = values("Transfer-Encoding").flat_map(|v| v.split(',')).map(|c| c.trim_matches([' ', '\t'])).filter(|c| !c.is_empty()).collect();
    if values("Transfer-Encoding").next().is_some() {
        if head.version < (1, 1) {
            return Err(malformed(host, "is HTTP/1.0 and sent Transfer-Encoding, so its framing cannot be trusted".to_string()));
        }
        if announced.is_some() {
            return Err(malformed(host, "sent both Transfer-Encoding and Content-Length".to_string()));
        }
        return match codings.as_slice() {
            [only] if only.eq_ignore_ascii_case("chunked") => Ok(Framing::Chunked),
            _ => Err(undecoded("Transfer-Encoding", &codings.join(", "))),
        };
    }
    Ok(match announced {
        Some(n) => Framing::Length(n),
        None => Framing::UntilClose,
    })
}

/// The size a chunk size line announces: the hexadecimal number before any
/// `;` that starts a chunk extension, with the spaces and tabs around it
/// that RFC 9112 allows. None when it is not one, or does not fit a u64.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let size = match line.iter().position(|&b| b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    let size = size.trim_ascii();
    if size.is_empty() {
        return None;
    }
    size.iter().try_fold(0u64, |n, &b| n.checked_mul(16)?.checked_add(u64::from(char::from(b).to_digit(16)?)))
}

/// `s` as a decimal number: one or more ASCII digits and nothing else,
/// no larger than a u64 holds.
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    s.bytes().try_fold(0u64, |n, b| if b.is_ascii_digit() { n.checked_mul(10)?.checked_add(u64::from(b - b'0')) } else { None })
}

/// `fields` grouped by name without regard to ASCII case, in the order
/// each name first arrived. Each group keeps the spelling its first line
/// used and the values of all its lines in arrival order.
fn group_fields(fields: &[(String, String)]) -> Vec<(String, Vec<String>)> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for (name, value) in fields {
        match groups.iter_mut().find(|(seen, _)| seen.eq_ignore_ascii_case(name)) {
            Some((_, values)) => values.push(value.clone()),
            None => groups.push((name.clone(), vec![value.clone()])),
        }
    }
    groups
}

/// The header fields as a System.Collections.Specialized.OrderedDictionary
/// keyed through StringComparer.OrdinalIgnoreCase: one key per field name
/// as [`group_fields`] groups them, each holding a string[] of the values.
fn header_table(fields: &[(String, String)]) -> PsResult<PsObject> {
    let comparer = PsType::from_name("System.StringComparer").call_static("get_OrdinalIgnoreCase", &[])?;
    let table = PsType::from_name("System.Collections.Specialized.OrderedDictionary").new(&[comparer])?;
    for (name, values) in group_fields(fields) {
        table.call("Add", &[name.into_ps()?, PsArray(values).into_ps()?])?;
    }
    Ok(table)
}

/// The body as text, decoded the way the WHATWG Encoding Standard has a
/// browser decode it, through encoding_rs: a byte order mark at the start
/// picks UTF-8, UTF-16LE or UTF-16BE and is dropped; otherwise the charset
/// label of the first Content-Type field, looked up in the standard's
/// table of labels (so `iso-8859-1` and `latin1` read as windows-1252, and
/// `utf-16` as UTF-16LE); otherwise UTF-8. A sequence the encoding cannot
/// read becomes U+FFFD.
fn text_of(body: &[u8], fields: &Fields) -> String {
    let content_type = fields.iter().find(|(name, _)| name.eq_ignore_ascii_case("Content-Type")).map(|(_, value)| value.as_str());
    let named = content_type.and_then(charset_label).and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()));
    let encoding = match named {
        Some(encoding) => encoding,
        None => encoding_rs::UTF_8,
    };
    let (text, _, _) = encoding.decode(body);
    text.into_owned()
}

/// The charset label a Content-Type value names: its `charset` parameter's
/// value, without the quotes a quoted-string value carries.
fn charset_label(content_type: &str) -> Option<&str> {
    content_type.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        let value = value.trim_matches([' ', '\t']);
        let value = match value.strip_prefix('"').and_then(|quoted| quoted.strip_suffix('"')) {
            Some(unquoted) => unquoted,
            None => value,
        };
        name.trim_matches([' ', '\t']).eq_ignore_ascii_case("charset").then_some(value)
    })
}

pwrs::export_module! {
    name: "SecureFetch",
    cmdlets: [InvokeSecureFetch],
    classes: [Response],
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error id `result` carries, or `accepted` when it succeeded.
    fn error_id<T>(result: PsResult<T>) -> String {
        match result {
            Ok(_) => "accepted".to_string(),
            Err(e) => e.error_id,
        }
    }

    /// One response read from `input` as the worker reads one: its final
    /// header section, then its body into `sink`.
    fn read_response<R: Read, S: Sink>(input: &mut Input<'_, R>, sink: &mut S, limit: u64, bodiless: bool) -> PsResult<(Head, Fields, Framing)> {
        let head = read_final_head(input)?;
        let (trailers, framing) = read_body(input, &head, sink, limit, bodiless)?;
        Ok((head, trailers, framing))
    }

    /// `raw` read as one response the way a connection's bytes are read,
    /// its decoded body bounded by `limit`, with the framing it had.
    fn framed_within(raw: &[u8], limit: u64) -> PsResult<(Message, Framing)> {
        let cancel = Cancel::default();
        let mut stream = raw;
        let mut input = Input::new(&mut stream, &cancel, "test.invalid", Duration::from_secs(5));
        let mut kept = Kept { host: "test.invalid", body: Vec::new() };
        let (head, trailers, framing) = read_response(&mut input, &mut kept, limit, false)?;
        let message = Message { status_code: head.status_code, reason: head.reason, fields: head.fields, body: kept.body, trailers };
        Ok((message, framing))
    }

    fn framed(raw: &[u8]) -> PsResult<(Message, Framing)> {
        framed_within(raw, u64::MAX)
    }

    /// A response carrying `body` with Content-Encoding `coding`, framed by
    /// Content-Length.
    fn encoded(coding: &str, body: &[u8]) -> Vec<u8> {
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        raw.extend_from_slice(body);
        raw
    }

    /// `data` compressed by a flate2 encoder that writes into a Vec.
    fn compressed<W: Write>(mut encoder: W, data: &[u8], finish: impl FnOnce(W) -> std::io::Result<Vec<u8>>) -> std::io::Result<Vec<u8>> {
        encoder.write_all(data)?;
        finish(encoder)
    }

    fn message(raw: &str) -> PsResult<Message> {
        framed(raw.as_bytes()).map(|(message, _)| message)
    }

    /// A connection's bytes that end with the response: a read after them
    /// is an error, as if the server were still holding the connection
    /// open, so a reader that reads past the response fails.
    struct Held<'a>(&'a [u8]);

    impl Read for Held<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return Err(std::io::Error::other("read past the end of the response"));
            }
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn parts(t: &Target) -> (&str, u16, &str, &str) {
        (t.host.as_str(), t.port, t.host_header.as_str(), t.request_target.as_str())
    }

    #[test]
    fn an_https_address_is_taken_apart() -> PsResult<()> {
        assert_eq!(parts(&Target::parse("https://example.com")?), ("example.com", 443, "example.com", "/"));
        assert_eq!(parts(&Target::parse("HTTPS://Example.com:8443/a/b?c=d#section")?), ("Example.com", 8443, "Example.com:8443", "/a/b?c=d"));
        assert_eq!(parts(&Target::parse("https://[::1]:4433/x")?), ("::1", 4433, "[::1]:4433", "/x"));
        assert_eq!(parts(&Target::parse("https://[::1]/")?), ("::1", 443, "[::1]", "/"));
        assert_eq!(parts(&Target::parse("https://127.0.0.1?q=1")?), ("127.0.0.1", 443, "127.0.0.1", "/?q=1"));
        Ok(())
    }

    #[test]
    fn an_address_it_cannot_send_is_refused() {
        assert_eq!(error_id(Target::parse("http://example.com/")), "SecureFetchNotHttps");
        assert_eq!(error_id(Target::parse("https:")), "SecureFetchNotHttps");
        assert_eq!(error_id(Target::parse("https://example.com:tls/")), "SecureFetchBadPort");
        assert_eq!(error_id(Target::parse("https://example.com:0/")), "SecureFetchBadPort");
        assert_eq!(error_id(Target::parse("https://example.com:65536/")), "SecureFetchBadPort");
        assert_eq!(error_id(Target::parse("https:///index.html")), "SecureFetchBadHost");
        assert_eq!(error_id(Target::parse("https://exa mple.com/")), "SecureFetchBadHost");
        assert_eq!(error_id(Target::parse("https://[::1/")), "SecureFetchBadHost");
        assert_eq!(error_id(Target::parse("https://[::1]x/")), "SecureFetchBadHost");
        assert_eq!(error_id(Target::parse("https://user:secret@example.com/")), "SecureFetchUserInfo");
    }

    #[test]
    fn a_request_target_escapes_what_http_cannot_carry() {
        assert_eq!(request_target(""), "/");
        assert_eq!(request_target("?q=1"), "/?q=1");
        assert_eq!(request_target("/a b/\u{fc}?x=\r\n"), "/a%20b/%C3%BC?x=%0D%0A");
        assert_eq!(request_target("/already%20escaped/{x}"), "/already%20escaped/%7Bx%7D");
    }

    /// The Mozilla roots webpki-roots compiles in, as -TrustedRoots Bundled
    /// gives them.
    fn bundled_roots() -> rustls::RootCertStore {
        rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
    }

    /// The request an invocation sends with these parameters, asking for
    /// compressed bodies.
    fn outgoing(method: &str, entries: Vec<(&str, Given)>, payload: Option<Payload>, content_type: Option<&str>) -> PsResult<Outgoing> {
        let entries = entries.into_iter().map(|(name, value)| (name.to_string(), value)).collect();
        Outgoing::new(method, true, entries, payload, content_type)
    }

    fn one(value: &str) -> Given {
        Given::One(value.to_string())
    }

    fn text_body() -> Option<Payload> {
        Some(Payload::Text("SecureFetch test".to_string()))
    }

    /// The Content-Type values `o` sends, in order.
    fn content_types(o: &Outgoing) -> Vec<String> {
        let from_fields = o.fields.iter().filter(|(name, _)| name.eq_ignore_ascii_case("Content-Type")).map(|(_, value)| value.clone());
        from_fields.chain(o.content_type.clone()).collect()
    }

    /// The body `o` sends, as bytes.
    fn body_of(o: &Outgoing) -> Option<&[u8]> {
        o.body.as_ref().map(|body| body.as_slice())
    }

    #[test]
    fn the_request_is_http_1_1_and_says_its_codings_and_whether_the_connection_is_kept() -> PsResult<()> {
        let target = Target::parse("https://example.com:8443/p?q")?;
        let expected = |accept: &str, connection: &str| {
            format!(
                "GET /p?q HTTP/1.1\r\nHost: example.com:8443\r\nUser-Agent: SecureFetch/{}\r\nAccept: */*\r\nAccept-Encoding: {accept}\r\nConnection: {connection}\r\n\r\n",
                env!("CARGO_PKG_VERSION")
            )
        };
        assert_eq!(Outgoing::new("GET", true, Vec::new(), None, None)?.head(&target, false), expected("gzip, deflate, br, zstd", "close"));
        assert_eq!(Outgoing::new("GET", false, Vec::new(), None, None)?.head(&target, true), expected("identity", "keep-alive"));
        Ok(())
    }

    #[test]
    fn the_method_is_sent_upper_cased_and_a_body_is_framed_by_its_length() -> PsResult<()> {
        let target = Target::parse("https://example.com/p")?;
        let request_line = |o: &Outgoing| o.head(&target, false).lines().next().map(str::to_string);
        let length = |o: &Outgoing| o.head(&target, false).lines().find_map(|line| line.strip_prefix("Content-Length: ").map(str::to_string));
        for method in ["get", "Head", "POST", "put", "patch", "delete", "options"] {
            let o = outgoing(method, Vec::new(), None, None)?;
            assert_eq!(request_line(&o), Some(format!("{} /p HTTP/1.1", method.to_ascii_uppercase())));
            let expected = matches!(o.method.as_str(), "POST" | "PUT" | "PATCH").then(|| "0".to_string());
            assert_eq!(length(&o), expected, "{method}");
        }
        let o = outgoing("DELETE", Vec::new(), Some(Payload::Text("caf\u{e9}".to_string())), None)?;
        assert_eq!((length(&o), body_of(&o)), (Some("5".to_string()), Some("caf\u{e9}".as_bytes())));
        let o = outgoing("POST", Vec::new(), Some(Payload::Bytes(vec![0, 1, 2])), None)?;
        assert_eq!((length(&o), body_of(&o)), (Some("3".to_string()), Some([0u8, 1, 2].as_slice())));
        let o = outgoing("PUT", Vec::new(), Some(Payload::Text(String::new())), None)?;
        assert_eq!((length(&o), content_types(&o)), (Some("0".to_string()), vec!["text/plain; charset=utf-8".to_string()]));
        Ok(())
    }

    #[test]
    fn header_entries_follow_the_defaults_they_do_not_replace() -> PsResult<()> {
        let entries = vec![
            ("X-One", one("1")),
            ("user-agent", one("Custom/1.0")),
            ("X-Many", Given::Many(vec!["a".to_string(), "b".to_string()])),
            ("Accept", Given::Many(Vec::new())),
            ("X-Tab", one("a\tb caf\u{e9}")),
        ];
        let o = outgoing("GET", entries, None, None)?;
        let owned = |name: &str, value: &str| (name.to_string(), value.to_string());
        assert_eq!(
            o.fields,
            [
                owned("Accept-Encoding", "gzip, deflate, br, zstd"),
                owned("X-One", "1"),
                owned("user-agent", "Custom/1.0"),
                owned("X-Many", "a"),
                owned("X-Many", "b"),
                owned("X-Tab", "a\tb caf\u{e9}"),
            ]
        );
        let o = outgoing("GET", vec![("ACCEPT-ENCODING", one("br"))], None, None)?;
        assert_eq!(o.fields.iter().filter(|(name, _)| name.eq_ignore_ascii_case("Accept-Encoding")).count(), 1);
        Ok(())
    }

    #[test]
    fn a_body_goes_with_the_content_type_given_or_its_default() -> PsResult<()> {
        let bytes = || Some(Payload::Bytes(vec![1]));
        assert_eq!(content_types(&outgoing("POST", Vec::new(), text_body(), None)?), ["text/plain; charset=utf-8"]);
        assert_eq!(content_types(&outgoing("POST", Vec::new(), bytes(), None)?), ["application/octet-stream"]);
        assert!(content_types(&outgoing("POST", Vec::new(), None, None)?).is_empty());
        assert_eq!(content_types(&outgoing("POST", Vec::new(), text_body(), Some("application/json"))?), ["application/json"]);
        assert_eq!(content_types(&outgoing("GET", Vec::new(), None, Some("application/json"))?), ["application/json"]);
        assert_eq!(content_types(&outgoing("PUT", vec![("content-type", one("application/xml"))], text_body(), None)?), ["application/xml"]);
        assert_eq!(content_types(&outgoing("PUT", Vec::new(), text_body(), Some("text/plain; charset=UTF8"))?), ["text/plain; charset=UTF8"]);
        assert_eq!(content_types(&outgoing("PUT", Vec::new(), bytes(), Some("text/plain; charset=iso-8859-1"))?), ["text/plain; charset=iso-8859-1"]);
        Ok(())
    }

    #[test]
    fn a_header_that_would_break_the_request_is_refused() {
        let refused = |entries: Vec<(&str, Given)>| error_id(outgoing("GET", entries, None, None));
        for name in ["Bad Name", "", "X:Y", "X\r\nInjected", "caf\u{e9}"] {
            assert_eq!(refused(vec![(name, one("v"))]), "SecureFetchBadHeader", "{name:?}");
        }
        for name in ["Host", "content-length", "Transfer-Encoding", "CONNECTION", "TE", "Trailer", "Upgrade", "Keep-Alive", "Proxy-Connection"] {
            assert_eq!(refused(vec![(name, one("v"))]), "SecureFetchBadHeader", "{name}");
        }
        for value in ["a\r\nInjected: yes", "a\nb", "a\rb", "nul\0", "bell\u{7}", "del\u{7f}"] {
            assert_eq!(refused(vec![("X-Test", one(value))]), "SecureFetchBadHeader", "{value:?}");
            assert_eq!(refused(vec![("X-Test", Given::Many(vec!["fine".to_string(), value.to_string()]))]), "SecureFetchBadHeader", "{value:?}");
            assert_eq!(error_id(outgoing("GET", Vec::new(), None, Some(value))), "SecureFetchBadHeader", "{value:?}");
        }
        assert_eq!(refused(vec![("X-Retry", Given::Other("a System.Int32".to_string()))]), "SecureFetchBadHeader");
        assert_eq!(refused(vec![("X-Fine", one("")), ("X-Also", one("  spaced  "))]), "accepted");
    }

    #[test]
    fn a_string_body_refuses_a_content_type_naming_another_charset() {
        assert_eq!(error_id(outgoing("POST", Vec::new(), text_body(), Some("text/plain; charset=iso-8859-1"))), "SecureFetchBadHeader");
        assert_eq!(error_id(outgoing("POST", Vec::new(), text_body(), Some("text/plain; charset=\"utf-16\""))), "SecureFetchBadHeader");
        assert_eq!(error_id(outgoing("POST", vec![("Content-Type", one("text/html; charset=windows-1252"))], text_body(), None)), "SecureFetchBadHeader");
        assert_eq!(error_id(outgoing("POST", Vec::new(), text_body(), Some("application/json; charset=utf-8"))), "accepted");
    }

    #[test]
    fn a_field_given_both_in_headers_and_by_its_parameter_is_refused_naming_both_values() {
        let refusal = |result: PsResult<Outgoing>| match result {
            Ok(_) => "accepted".to_string(),
            Err(e) => format!("{}: {}", e.error_id, e.message),
        };
        assert_eq!(
            refusal(outgoing("POST", vec![("Content-Type", one("text/csv"))], text_body(), Some("text/plain"))),
            "SecureFetchBadHeader: Content-Type is given both in -Headers, as \"text/csv\", and by -ContentType, as \"text/plain\"; give one of them"
        );
        let accept_encoding = |value: Given| vec![("Accept-Encoding".to_string(), value)];
        assert_eq!(
            refusal(Outgoing::new("GET", false, accept_encoding(one("gzip")), None, None)),
            "SecureFetchBadHeader: Accept-Encoding is given both in -Headers, as \"gzip\", and by -NoCompression, which sends \"identity\"; give one of them"
        );
        assert_eq!(
            refusal(Outgoing::new("GET", false, accept_encoding(Given::Many(vec!["br".to_string(), "zstd".to_string()])), None, None)),
            "SecureFetchBadHeader: Accept-Encoding is given both in -Headers, as \"br\" and \"zstd\", and by -NoCompression, which sends \"identity\"; give one of them"
        );
        assert_eq!(
            refusal(Outgoing::new("GET", false, accept_encoding(Given::Many(Vec::new())), None, None)),
            "SecureFetchBadHeader: Accept-Encoding is given both in -Headers, as an empty array, and by -NoCompression, which sends \"identity\"; give one of them"
        );
        assert_eq!(error_id(Outgoing::new("GET", true, accept_encoding(one("gzip")), None, None)), "accepted");
    }

    #[test]
    fn a_header_value_of_another_type_is_refused_naming_the_field_and_the_type() {
        match outgoing("GET", vec![("X-Retry", Given::Other("a System.Int32".to_string()))], None, None) {
            Ok(_) => panic!("a System.Int32 value was accepted"),
            Err(e) => assert_eq!(
                (e.error_id.as_str(), e.message.as_str()),
                ("SecureFetchBadHeader", "the X-Retry value is a System.Int32; a -Headers value is a string or an array of strings")
            ),
        }
    }

    #[test]
    fn only_idempotent_methods_are_sent_again() {
        for method in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE"] {
            assert!(idempotent(method), "{method}");
        }
        for method in ["POST", "PATCH"] {
            assert!(!idempotent(method), "{method}");
        }
    }

    #[test]
    fn a_request_body_follows_its_head_and_a_stop_ends_the_upload() -> PsResult<()> {
        let body = vec![7u8; 200 * 1024];
        let mut sent = Vec::new();
        write_request(&mut sent, b"PUT / HTTP/1.1\r\n\r\n", Some(&body), &Cancel::default())?;
        assert_eq!((sent.len(), &sent[18..], sent.starts_with(b"PUT / HTTP/1.1\r\n\r\n")), (18 + body.len(), body.as_slice(), true));
        let stopped = Cancel::default();
        assert!(stopped.stop().is_none());
        let mut cut = Vec::new();
        assert!(write_request(&mut cut, b"PUT / HTTP/1.1\r\n\r\n", Some(&body), &stopped).is_err());
        assert_eq!(cut, b"PUT / HTTP/1.1\r\n\r\n");
        Ok(())
    }

    #[test]
    fn a_response_to_head_ends_with_its_header_section() -> PsResult<()> {
        for raw in ["HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nContent-Encoding: gzip\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"] {
            let cancel = Cancel::default();
            let mut open = Held(raw.as_bytes());
            let mut input = Input::new(&mut open, &cancel, "test.invalid", Duration::from_secs(5));
            let mut kept = Kept { host: "test.invalid", body: Vec::new() };
            let (head, _, framing) = read_response(&mut input, &mut kept, u64::MAX, true)?;
            assert_eq!((head.status_code, kept.body.len(), framing), (200, 0, Framing::Empty), "{raw:?}");
        }
        Ok(())
    }

    /// A folder of its own under the system's temporary folder for one
    /// test, emptied first.
    fn scratch_folder(name: &str) -> std::io::Result<PathBuf> {
        let folder = std::env::temp_dir().join(format!("securefetch-test-{name}-{}", std::process::id()));
        if folder.exists() {
            std::fs::remove_dir_all(&folder)?;
        }
        std::fs::create_dir_all(&folder)?;
        Ok(folder)
    }

    /// The names of the files in `folder`, sorted.
    fn names_in(folder: &Path) -> std::io::Result<Vec<String>> {
        let mut names = std::fs::read_dir(folder)?.map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned())).collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn a_body_written_to_a_file_replaces_it_only_once_it_is_whole() -> PsResult<()> {
        let folder = scratch_folder("outfile")?;
        let target = folder.join("body.bin");
        std::fs::write(&target, b"the file as it was")?;
        let gzip = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()), b"a body that arrived whole", |e| e.finish())?;
        let raw = encoded("gzip", &gzip);
        let cancel = Cancel::default();
        let mut whole = raw.as_slice();
        let mut input = Input::new(&mut whole, &cancel, "test.invalid", Duration::from_secs(5));
        let head = read_final_head(&mut input)?;
        let mut file = FileSink::create(&target)?;
        let during = names_in(&folder)?;
        assert_eq!(during.len(), 2, "{during:?}");
        assert!(during.iter().any(|name| name.starts_with("body.bin.") && name.ends_with(".securefetch-partial")), "{during:?}");
        assert_eq!(std::fs::read(&target)?, b"the file as it was");
        read_body(&mut input, &head, &mut file, u64::MAX, false)?;
        file.commit()?;
        assert_eq!((std::fs::read(&target)?, names_in(&folder)?), (b"a body that arrived whole".to_vec(), vec!["body.bin".to_string()]));
        let mut cut = &raw[..raw.len() - 5];
        let mut input = Input::new(&mut cut, &cancel, "test.invalid", Duration::from_secs(5));
        let head = read_final_head(&mut input)?;
        let mut file = FileSink::create(&target)?;
        let ended = match read_body(&mut input, &head, &mut file, u64::MAX, false) {
            Ok(_) => PsError::new(ErrorCategory::NotSpecified, "TestReadWhole", "a body cut short was read as whole"),
            Err(e) => file.discard(e),
        };
        assert_eq!(ended.error_id, "SecureFetchTruncated");
        assert_eq!((std::fs::read(&target)?, names_in(&folder)?), (b"a body that arrived whole".to_vec(), vec!["body.bin".to_string()]));
        assert_eq!(error_id(FileSink::create(&folder.join("no-such-folder").join("body.bin"))), "SecureFetchWriteFailed");
        std::fs::remove_dir_all(&folder)?;
        Ok(())
    }

    #[test]
    fn only_a_body_that_is_written_rather_than_followed_or_raised_goes_to_the_file() -> PsResult<()> {
        let mut job = Job {
            target: Target::parse("https://example.com/")?,
            config: client_config(false, bundled_roots())?,
            post_quantum_only: false,
            wait: Duration::from_secs(5),
            keep_alive: false,
            outgoing: Arc::new(Outgoing::new("GET", true, Vec::new(), None, None)?),
            max_decoded: 1 << 20,
            out_file: Some(PathBuf::from("body.bin")),
            http_errors_to_file: false,
            redirects_followed: true,
            proxy: None,
            idle: None,
        };
        let head = |raw: &str| framed(raw.as_bytes()).map(|(m, _)| Head { version: (1, 1), status_code: m.status_code, reason: m.reason, fields: m.fields });
        let ok = head("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        let moved = head("HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")?;
        let unlocated = head("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")?;
        let missing = head("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")?;
        assert_eq!((job.to_file(&ok), job.to_file(&moved), job.to_file(&unlocated), job.to_file(&missing)), (true, false, true, false));
        job.redirects_followed = false;
        job.http_errors_to_file = true;
        assert_eq!((job.to_file(&moved), job.to_file(&missing)), (true, true));
        job.out_file = None;
        assert!(!job.to_file(&ok));
        Ok(())
    }

    #[test]
    fn a_proxy_address_is_taken_apart_or_refused() {
        let address = |host: &str, port: u16| -> Result<ProxyAddress, String> { Ok(ProxyAddress { host: host.to_string(), port }) };
        assert_eq!(ProxyAddress::parse("http://proxy.example:3128"), address("proxy.example", 3128));
        assert_eq!(ProxyAddress::parse("HTTP://proxy.example/"), address("proxy.example", 80));
        assert_eq!(ProxyAddress::parse("http://[::1]:8080"), address("::1", 8080));
        assert_eq!(ProxyAddress::parse("http://127.0.0.1"), address("127.0.0.1", 80));
        for (text, reason) in [
            ("https://proxy.example:3128", "https:// proxy"),
            ("socks5://proxy.example:1080", "not an http:// proxy"),
            ("proxy.example:3128", "not an http:// proxy"),
            ("http://user:secret@proxy.example:3128", "user information"),
            ("http://proxy.example:3128/path", "path"),
            ("http://:3128", "no host"),
            ("http://proxy.example:0", "port 0"),
            ("http://proxy.example:65536", "not a port"),
            ("http://[::1:8080", "does not close it"),
        ] {
            let refused = ProxyAddress::parse(text);
            assert!(matches!(&refused, Err(why) if why.contains(reason)), "{text}: {refused:?}");
        }
        assert_eq!(ProxyAddress { host: "::1".to_string(), port: 8080 }.display(), "http://[::1]:8080");
        assert_eq!(ProxyAddress { host: "proxy.example".to_string(), port: 80 }.display(), "http://proxy.example:80");
    }

    #[test]
    fn a_refusal_quotes_an_address_with_its_user_information_masked() {
        for (given, id, quoted) in [
            ("https://user:secret@example.com/", "SecureFetchUserInfo", "https://***@example.com/ carries user information"),
            ("HTTPS://user:secret@example.com:8443/a?b#c", "SecureFetchUserInfo", "HTTPS://***@example.com:8443/a?b#c carries user information"),
            ("http://user:secret@example.com/", "SecureFetchNotHttps", "http://***@example.com/ is not an https:// address"),
            ("user:secret@example.com", "SecureFetchNotHttps", "***@example.com is not an https:// address"),
        ] {
            match Target::parse(given) {
                Ok(_) => panic!("{given} was accepted"),
                Err(e) => {
                    assert_eq!(e.error_id, id, "{given}");
                    assert!(e.message.starts_with(quoted), "{given}: {}", e.message);
                    assert!(!e.message.contains("secret"), "{given}: {}", e.message);
                }
            }
        }
        for (given, quoted) in [
            ("http://user:secret@proxy.example:3128", "-Proxy http://***@proxy.example:3128 carries user information"),
            ("https://user:secret@proxy.example:3128", "-Proxy https://***@proxy.example:3128 is an https:// proxy"),
        ] {
            match ProxyAddress::parse(given) {
                Ok(address) => panic!("{given} was accepted as {address:?}"),
                Err(why) => {
                    let e = proxy_refused(given, why);
                    assert_eq!((e.error_id.as_str(), e.message.starts_with(quoted)), ("SecureFetchProxy", true), "{given}: {}", e.message);
                    assert!(!e.message.contains("secret"), "{given}: {}", e.message);
                }
            }
        }
        let system = proxy_error(ErrorCategory::ConnectionError, "http://user:secret@proxy.example:8080/", "is the proxy the system names".to_string());
        assert_eq!(system.message, "the proxy http://***@proxy.example:8080/ is the proxy the system names");
        for unchanged in ["https://example.com/a@b", "https://example.com/?to=a@b", "http://proxy.example:3128", "example.com"] {
            assert_eq!(masked(unchanged), unchanged);
        }
    }

    #[test]
    fn trusted_roots_name_their_sources_and_must_trust_something() -> PsResult<()> {
        let named = |sources: &[&str], extra: usize| root_sources(&sources.iter().map(|s| s.to_string()).collect::<Vec<_>>(), extra);
        assert_eq!(named(&["Bundled", "Windows"], 0)?, (true, true));
        assert_eq!(named(&["bundled"], 0)?, (true, false));
        assert_eq!(named(&["WINDOWS"], 0)?, (false, true));
        assert_eq!(named(&["None"], 1)?, (false, false));
        assert_eq!(named(&[], 2)?, (false, false));
        for (sources, extra) in [(vec!["None"], 0), (vec![], 0), (vec!["None", "Bundled"], 1), (vec!["Windows", "none"], 0)] {
            assert_eq!(error_id(named(&sources, extra)), "SecureFetchRootStore", "{sources:?} with {extra}");
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_root_store_gives_roots_that_authenticate_servers() -> PsResult<()> {
        let mut roots = rustls::RootCertStore::empty();
        let skipped = windows_roots(&mut roots)?;
        assert!(roots.len() >= 10, "{} roots taken, skipped: {skipped:?}", roots.len());
        Ok(())
    }

    #[test]
    fn connect_names_the_host_and_port_and_basic_credentials_are_base64() -> PsResult<()> {
        assert_eq!(Target::parse("https://example.com/")?.authority(), "example.com:443");
        assert_eq!(Target::parse("https://[::1]:4433/x")?.authority(), "[::1]:4433");
        for (text, encoded) in [("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(text.as_bytes()), encoded, "{text}");
        }
        assert!(base64(b"").is_empty());
        assert_eq!(base64("Aladdin:open sesame".as_bytes()), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        Ok(())
    }

    #[test]
    fn a_location_resolves_against_the_address_that_answered_as_rfc_3986_says() -> PsResult<()> {
        let base = Target::parse("https://a/b/c/d;p?q")?;
        let resolved = |reference: &str| resolve_reference(&base, reference).1;
        for (reference, expected) in [
            ("g", "https://a/b/c/g"),
            ("./g", "https://a/b/c/g"),
            ("g/", "https://a/b/c/g/"),
            ("/g", "https://a/g"),
            ("//g", "https://g"),
            ("?y", "https://a/b/c/d;p?y"),
            ("g?y", "https://a/b/c/g?y"),
            ("#s", "https://a/b/c/d;p?q"),
            ("g#s", "https://a/b/c/g"),
            ("g?y#s", "https://a/b/c/g?y"),
            (";x", "https://a/b/c/;x"),
            ("g;x", "https://a/b/c/g;x"),
            ("g;x?y#s", "https://a/b/c/g;x?y"),
            ("", "https://a/b/c/d;p?q"),
            (".", "https://a/b/c/"),
            ("./", "https://a/b/c/"),
            ("..", "https://a/b/"),
            ("../", "https://a/b/"),
            ("../g", "https://a/b/g"),
            ("../..", "https://a/"),
            ("../../", "https://a/"),
            ("../../g", "https://a/g"),
            ("../../../g", "https://a/g"),
            ("../../../../g", "https://a/g"),
            ("/./g", "https://a/g"),
            ("/../g", "https://a/g"),
            ("g.", "https://a/b/c/g."),
            (".g", "https://a/b/c/.g"),
            ("g..", "https://a/b/c/g.."),
            ("..g", "https://a/b/c/..g"),
            ("./../g", "https://a/b/g"),
            ("./g/.", "https://a/b/c/g/"),
            ("g/./h", "https://a/b/c/g/h"),
            ("g/../h", "https://a/b/c/h"),
            ("g;x=1/./y", "https://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "https://a/b/c/y"),
            ("g?y/./x", "https://a/b/c/g?y/./x"),
            ("g?y/../x", "https://a/b/c/g?y/../x"),
            ("g#s/./x", "https://a/b/c/g"),
            ("g#s/../x", "https://a/b/c/g"),
            ("HTTPS://Other.example:8443/x/../y?z#f", "HTTPS://Other.example:8443/y?z"),
            ("https:relative", "https:relative"),
        ] {
            assert_eq!(resolved(reference), expected, "{reference:?}");
        }
        assert_eq!(resolve_reference(&base, "g:h").0, "g");
        assert_eq!(resolve_reference(&base, "http:g").0, "http");
        Ok(())
    }

    #[test]
    fn a_redirect_is_followed_only_to_an_https_address_that_can_be_sent() -> PsResult<()> {
        let base = Target::parse("https://example.com/a/b")?;
        assert_eq!(redirected_target(&base, "c?d")?.address(), "https://example.com/a/c?d");
        assert_eq!(redirected_target(&base, "HTTPS://Other.example:8443")?.address(), "https://Other.example:8443/");
        assert_eq!(redirected_target(&base, "/caf\u{e9} x")?.address(), "https://example.com/caf%C3%A9%20x");
        for location in ["http://example.com/", "ftp://example.com/", "javascript:alert(1)", "g:h", "//example.com:80/x"] {
            let expected = if location.starts_with("//") { "accepted" } else { "SecureFetchRedirectNotHttps" };
            assert_eq!(error_id(redirected_target(&base, location)), expected, "{location}");
        }
        for location in ["https:///nohost", "https://user:pw@example.com/", "https://example.com:0/", "https:relative", "https:/rooted"] {
            assert_eq!(error_id(redirected_target(&base, location)), "SecureFetchBadResponse", "{location}");
        }
        Ok(())
    }

    #[test]
    fn only_a_redirect_status_with_a_location_is_followed() -> PsResult<()> {
        let target = Target::parse("https://example.com/")?;
        let location = |raw: &str| message(raw).and_then(|m| redirect_location(&m, &target));
        for code in [301, 302, 303, 307, 308] {
            assert_eq!(location(&format!("HTTP/1.1 {code} X\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"))?, Some("/next".to_string()), "{code}");
        }
        for code in [200, 300, 304, 305, 306, 404] {
            assert_eq!(location(&format!("HTTP/1.1 {code} X\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"))?, None, "{code}");
        }
        assert_eq!(location("HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")?, None);
        assert_eq!(location("HTTP/1.1 302 Found\r\nLocation: /a\r\nlocation: /a\r\nContent-Length: 0\r\n\r\n")?, Some("/a".to_string()));
        assert_eq!(error_id(location("HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n")), "SecureFetchBadResponse");
        Ok(())
    }

    #[test]
    fn a_redirect_turns_a_request_into_a_get_only_where_rfc_9110_says() -> PsResult<()> {
        let entries = vec![("Authorization", one("Bearer x")), ("Cookie", one("a=1")), ("Content-Language", one("en")), ("X-Keep", one("yes"))];
        let post = outgoing("POST", entries, text_body(), Some("text/plain"))?;
        let names = |o: &Outgoing| o.fields.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>();
        for status in [301, 302, 303] {
            let next = post.redirected(status, false);
            assert_eq!((next.method.as_str(), body_of(&next), next.content_type.as_deref()), ("GET", None, None), "{status}");
            assert_eq!(names(&next), ["User-Agent", "Accept", "Accept-Encoding", "Authorization", "Cookie", "X-Keep"], "{status}");
        }
        for status in [307, 308] {
            let next = post.redirected(status, false);
            assert_eq!((next.method.as_str(), body_of(&next), next.content_type.as_deref()), ("POST", Some("SecureFetch test".as_bytes()), Some("text/plain")), "{status}");
            assert_eq!(names(&next), names(&post), "{status}");
        }
        let put = outgoing("PUT", Vec::new(), text_body(), None)?;
        assert_eq!((put.redirected(302, false).method.as_str(), body_of(&put.redirected(302, false))), ("PUT", Some("SecureFetch test".as_bytes())));
        assert_eq!(put.redirected(303, false).method, "GET");
        assert_eq!(outgoing("HEAD", Vec::new(), None, None)?.redirected(303, false).method, "HEAD");
        let crossed = post.redirected(307, true);
        assert_eq!(names(&crossed), ["User-Agent", "Accept", "Accept-Encoding", "Content-Language", "X-Keep"]);
        let crossed = outgoing("GET", vec![("authorization", one("Bearer x")), ("COOKIE", one("a=1"))], None, None)?.redirected(302, true);
        assert_eq!(names(&crossed), ["User-Agent", "Accept", "Accept-Encoding"]);
        Ok(())
    }

    #[test]
    fn gzip_deflate_br_and_zstd_bodies_are_decoded() -> PsResult<()> {
        let text = b"SecureFetch decodes a body its server compressed.";
        let gzip = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()), text, |e| e.finish())?;
        let zlib = compressed(flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default()), text, |e| e.finish())?;
        let raw_deflate = compressed(flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default()), text, |e| e.finish())?;
        let zstd = ruzstd::encoding::compress_to_vec(&text[..], ruzstd::encoding::CompressionLevel::Fastest);
        for (coding, body) in [("gzip", &gzip), ("x-gzip", &gzip), ("deflate", &zlib), ("deflate", &raw_deflate), ("zstd", &zstd)] {
            let (m, _) = framed(&encoded(coding, body))?;
            assert_eq!(m.body, text, "{coding}");
        }
        let brotli: [u8; 54] = [
            0x1B, 0x39, 0x00, 0xE0, 0x8D, 0x94, 0x6E, 0xDE, 0x34, 0xA8, 0x93, 0xA5, 0xFA, 0xB9, 0xC2, 0x6D, 0x12, 0x1B, 0xD2, 0xC5, 0xC8, 0x0D, 0x1C,
            0x72, 0xE0, 0x72, 0xC0, 0x43, 0x0B, 0x13, 0x0D, 0x6E, 0xC0, 0x96, 0xB9, 0x29, 0x3C, 0x43, 0x17, 0x1F, 0xA5, 0xA4, 0xFA, 0x58, 0x5F, 0x2D,
            0x84, 0xD2, 0xF4, 0x25, 0x34, 0xC7, 0x6C, 0x1A,
        ];
        let (m, _) = framed(&encoded("br", &brotli))?;
        assert_eq!(m.body, b"SecureFetch decodes a br body from a server that sent one.");
        let stacked = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()), &zlib, |e| e.finish())?;
        let (m, _) = framed(&encoded("deflate, identity, gzip", &stacked))?;
        assert_eq!(m.body, text);
        Ok(())
    }

    #[test]
    fn a_chunked_gzip_body_is_unframed_then_decoded() -> PsResult<()> {
        let gzip = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()), b"chunked and gzipped", |e| e.finish())?;
        let (first, rest) = gzip.split_at(7);
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        for part in [first, rest] {
            raw.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            raw.extend_from_slice(part);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\n\r\n");
        let (m, framing) = framed(&raw)?;
        assert_eq!((m.body.as_slice(), framing), (b"chunked and gzipped".as_slice(), Framing::Chunked));
        Ok(())
    }

    #[test]
    fn a_decoded_body_past_the_bound_is_too_large_and_an_identity_body_is_not_bounded() -> PsResult<()> {
        let zeros = vec![0u8; 1 << 20];
        let bomb = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best()), &zeros, |e| e.finish())?;
        assert!(bomb.len() < 4096, "{} compressed bytes", bomb.len());
        assert_eq!(error_id(framed_within(&encoded("gzip", &bomb), 1000)), "SecureFetchTooLarge");
        let (m, _) = framed_within(&encoded("gzip", &bomb), 1 << 20)?;
        assert_eq!(m.body.len(), 1 << 20);
        assert_eq!(error_id(framed_within(&encoded("gzip", &bomb), (1 << 20) - 1)), "SecureFetchTooLarge");
        let (m, _) = framed_within(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", 4)?;
        assert_eq!(m.body, b"0123456789");
        Ok(())
    }

    #[test]
    fn a_body_that_does_not_decode_or_is_cut_short_is_refused() -> PsResult<()> {
        assert_eq!(error_id(framed(&encoded("gzip", b"not gzip at all"))), "SecureFetchBadResponse");
        assert_eq!(error_id(framed(&encoded("br", b"\xFF\xFF\xFF\xFF"))), "SecureFetchBadResponse");
        assert_eq!(error_id(framed(&encoded("zstd", b"not zstd"))), "SecureFetchBadResponse");
        let gzip = compressed(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()), b"cut short by the server", |e| e.finish())?;
        let mut cut = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", gzip.len() + 10).into_bytes();
        cut.extend_from_slice(&gzip[..gzip.len() - 4]);
        assert_eq!(error_id(framed(&cut)), "SecureFetchTruncated");
        Ok(())
    }

    #[test]
    fn a_content_length_ends_the_body_where_it_says() -> PsResult<()> {
        let (m, framing) = framed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nbody")?;
        assert_eq!((m.body.as_slice(), framing), (b"bo".as_slice(), Framing::Length(2)));
        let cancel = Cancel::default();
        let mut open = Held(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
        let mut input = Input::new(&mut open, &cancel, "test.invalid", Duration::from_secs(5));
        let mut kept = Kept { host: "test.invalid", body: Vec::new() };
        let (head, _, _) = read_response(&mut input, &mut kept, u64::MAX, false)?;
        assert_eq!((head.status_code, kept.body.as_slice()), (200, b"body".as_slice()));
        Ok(())
    }

    #[test]
    fn a_chunked_body_is_decoded_with_its_trailer_fields() -> PsResult<()> {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;name=value\r\npedia\r\n00E \t\r\n in\r\n\r\nchunks.\r\n0\r\nX-Checksum: abc\r\nX-Folded: one\r\n two\r\n\r\n";
        let (m, framing) = framed(raw.as_bytes())?;
        assert_eq!(framing, Framing::Chunked);
        assert_eq!(m.body, b"Wikipedia in\r\n\r\nchunks.");
        assert_eq!(m.trailers, [("X-Checksum".to_string(), "abc".to_string()), ("X-Folded".to_string(), "one two".to_string())]);
        let (m, _) = framed(b"HTTP/1.1 200 OK\ntransfer-encoding: Chunked\n\nA\n0123456789\n0\n\n")?;
        assert_eq!((m.body.as_slice(), m.trailers.len()), (b"0123456789".as_slice(), 0));
        let cancel = Cancel::default();
        let mut open = Held(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n");
        let mut input = Input::new(&mut open, &cancel, "test.invalid", Duration::from_secs(5));
        let mut kept = Kept { host: "test.invalid", body: Vec::new() };
        read_response(&mut input, &mut kept, u64::MAX, false)?;
        assert_eq!(kept.body, b"body");
        Ok(())
    }

    #[test]
    fn a_chunked_body_cut_short_is_truncated_and_a_bad_one_is_refused() {
        for raw in [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nfour",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-Trailer: yes\r\n",
        ] {
            assert_eq!(error_id(message(raw)), "SecureFetchTruncated", "{raw:?}");
        }
        for raw in [
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nbody\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n;ext\r\nbody\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\nbody\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nbody\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nno colon\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
            "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
        ] {
            assert_eq!(error_id(message(raw)), "SecureFetchBadResponse", "{raw:?}");
        }
    }

    #[test]
    fn interim_responses_are_skipped_and_bodiless_statuses_have_no_body() -> PsResult<()> {
        let m = message("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        assert_eq!((m.status_code, m.body.as_slice()), (200, b"ok".as_slice()));
        assert_eq!(error_id(message("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n")), "SecureFetchBadResponse");
        for code in [204, 304] {
            let (m, framing) = framed(format!("HTTP/1.1 {code} X\r\nContent-Length: 5\r\nContent-Encoding: gzip\r\n\r\n").as_bytes())?;
            assert_eq!((m.status_code, m.body.len(), framing), (code, 0, Framing::Empty));
        }
        Ok(())
    }

    #[test]
    fn a_connection_is_kept_only_when_http_1_1_framing_and_the_server_allow_it() -> PsResult<()> {
        let kept = |raw: &str| framed(raw.as_bytes()).map(|(m, framing)| (Head { version: (1, 1), status_code: m.status_code, reason: m.reason, fields: m.fields }, framing));
        let (head, framing) = kept("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        assert!(persistent(&head, framing));
        let (head, framing) = kept("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")?;
        assert!(persistent(&head, framing));
        let (head, framing) = kept("HTTP/1.1 200 OK\r\nConnection: Keep-Alive, Close\r\nContent-Length: 2\r\n\r\nok")?;
        assert!(!persistent(&head, framing));
        let (head, framing) = kept("HTTP/1.1 200 OK\r\n\r\nuntil the close")?;
        assert!(!persistent(&head, framing));
        let (m, framing) = framed(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        let head = Head { version: (1, 0), status_code: m.status_code, reason: m.reason, fields: m.fields };
        assert!(!persistent(&head, framing));
        Ok(())
    }

    #[test]
    fn the_status_line_and_header_fields_are_read() -> PsResult<()> {
        let m = message(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nX-Folded: one\r\n\t two\r\nset-cookie: b=2\r\nContent-Length: 4\r\n\r\nbody",
        )?;
        assert_eq!((m.status_code, m.reason.as_str(), m.body.as_slice()), (200, "OK", b"body".as_slice()));
        let owned = |name: &str, values: &[&str]| (name.to_string(), values.iter().map(|v| v.to_string()).collect::<Vec<_>>());
        assert_eq!(
            group_fields(&m.fields),
            [
                owned("Content-Type", &["text/plain"]),
                owned("Set-Cookie", &["a=1", "b=2"]),
                owned("X-Folded", &["one two"]),
                owned("Content-Length", &["4"]),
            ]
        );
        Ok(())
    }

    #[test]
    fn bare_line_feeds_and_a_missing_reason_are_accepted() -> PsResult<()> {
        let m = message("HTTP/1.0 404 Not Found\nServer: x\n\nnope")?;
        assert_eq!((m.status_code, m.reason.as_str(), m.body.as_slice()), (404, "Not Found", b"nope".as_slice()));
        let m = message("HTTP/1.1 204\r\n\r\n")?;
        assert_eq!((m.status_code, m.reason.as_str(), m.fields.len(), m.body.len()), (204, "", 0, 0));
        Ok(())
    }

    #[test]
    fn a_malformed_response_is_refused() {
        for raw in [
            "HTTP/1.1 200 OK\r\nServer: x\r\n",
            "SSH-2.0-OpenSSH_9.5\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 099 Early\r\n\r\n",
            "HTTP/11 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nno colon here\r\n\r\n",
            "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
            "HTTP/1.1 200 OK\r\n continued: x\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4, 5\r\n\r\nbody",
            "HTTP/1.1 200 OK\r\nContent-Length: four\r\n\r\nbody",
        ] {
            assert_eq!(error_id(message(raw)), "SecureFetchBadResponse", "{raw:?}");
        }
    }

    #[test]
    fn a_body_shorter_than_its_content_length_is_truncated() {
        assert_eq!(error_id(message("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nbody")), "SecureFetchTruncated");
    }

    #[test]
    fn repeated_equal_content_lengths_are_one_length() -> PsResult<()> {
        let m = message("HTTP/1.1 200 OK\r\nContent-Length: 4, 4\r\nContent-Length: 4\r\n\r\nbody")?;
        assert_eq!(m.body, b"body");
        Ok(())
    }

    #[test]
    fn an_encoding_this_version_does_not_decode_is_refused() -> PsResult<()> {
        assert_eq!(error_id(message("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n")), "SecureFetchEncoding");
        assert_eq!(error_id(message("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\ncompressed")), "SecureFetchEncoding");
        assert_eq!(error_id(message("HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\n\r\ncompressed")), "SecureFetchEncoding");
        assert_eq!(error_id(message("HTTP/1.1 200 OK\r\nContent-Encoding: gzip, x-bzip2\r\n\r\ncompressed")), "SecureFetchEncoding");
        let m = message("HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n\r\nplain")?;
        assert_eq!(m.body, b"plain");
        Ok(())
    }

    #[test]
    fn a_4xx_or_5xx_status_is_an_error_and_every_other_status_is_not() {
        for code in [400, 404, 451, 499, 500, 503, 599] {
            assert!(is_http_error(code), "{code}");
        }
        for code in [100, 200, 204, 301, 304, 399, 600, 999] {
            assert!(!is_http_error(code), "{code}");
        }
    }

    #[test]
    fn requiring_post_quantum_offers_x25519mlkem768_alone() -> PsResult<()> {
        let groups = |config: &rustls::ClientConfig| config.crypto_provider().kx_groups.iter().map(|group| group.name()).collect::<Vec<_>>();
        let (required, default) = (client_config(true, bundled_roots())?, client_config(false, bundled_roots())?);
        assert_eq!(groups(&required), [rustls::NamedGroup::X25519MLKEM768]);
        let offered = groups(&default);
        assert_eq!(offered.first(), Some(&rustls::NamedGroup::X25519MLKEM768), "{offered:?}");
        assert!(offered.contains(&rustls::NamedGroup::X25519), "{offered:?}");
        Ok(())
    }

    #[test]
    fn a_server_turning_the_post_quantum_offer_down_is_told_from_other_failures() {
        use rustls::AlertDescription as Alert;
        let wrapped = |e: rustls::Error| std::io::Error::new(ErrorKind::InvalidData, e);
        for alert in [Alert::HandshakeFailure, Alert::InsufficientSecurity, Alert::ProtocolVersion] {
            assert!(refused_post_quantum(&wrapped(rustls::Error::AlertReceived(alert))), "{alert:?}");
        }
        for why in [
            rustls::PeerIncompatible::NoKxGroupsInCommon,
            rustls::PeerIncompatible::ServerDoesNotSupportTls12Or13,
            rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
        ] {
            assert!(refused_post_quantum(&wrapped(rustls::Error::PeerIncompatible(why.clone()))), "{why:?}");
        }
        let retry = rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup);
        assert!(refused_post_quantum(&wrapped(retry)));
        assert!(!refused_post_quantum(&wrapped(rustls::Error::AlertReceived(Alert::BadCertificate))));
        assert!(!refused_post_quantum(&wrapped(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))));
        assert!(!refused_post_quantum(&wrapped(rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoCipherSuitesInCommon))));
        for kind in [ErrorKind::UnexpectedEof, ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted] {
            assert!(refused_post_quantum(&std::io::Error::new(kind, "the server closed the connection")), "{kind:?}");
        }
        assert!(!refused_post_quantum(&std::io::Error::new(ErrorKind::TimedOut, "the server kept the connection waiting")));
    }

    #[test]
    fn a_status_reads_as_its_code_and_reason() {
        assert_eq!(status_text(404, "Not Found"), "404 Not Found");
        assert_eq!(status_text(503, ""), "503");
    }

    /// The fields of a response whose Content-Type is `content_type`.
    fn typed(content_type: &str) -> Fields {
        vec![("Content-Type".to_string(), content_type.to_string())]
    }

    #[test]
    fn a_body_without_a_charset_is_utf8_and_keeps_its_valid_text() {
        assert_eq!(text_of(&[b'f', 0xFF, b'o'], &Fields::new()), "f\u{FFFD}o");
        assert_eq!(text_of("caf\u{e9}".as_bytes(), &typed("text/plain")), "caf\u{e9}");
        assert_eq!(text_of("caf\u{e9}".as_bytes(), &typed("text/plain; charset=no-such-charset")), "caf\u{e9}");
    }

    #[test]
    fn a_body_is_decoded_by_the_charset_its_content_type_names() {
        assert_eq!(charset_label("text/html; charset=ISO-8859-1"), Some("ISO-8859-1"));
        assert_eq!(charset_label("text/html;CHARSET=\"utf-8\"; q=1"), Some("utf-8"));
        assert_eq!(charset_label("text/html"), None);
        let latin = [b'c', b'a', b'f', 0xE9, b' ', 0x80];
        assert_eq!(text_of(&latin, &typed("text/html; charset=ISO-8859-1")), "caf\u{e9} \u{20ac}");
        assert_eq!(text_of(&latin, &typed("text/html; charset=latin1")), "caf\u{e9} \u{20ac}");
        assert_eq!(text_of(&latin, &typed("text/html; charset=windows-1252")), "caf\u{e9} \u{20ac}");
        let utf16le = [0x3D, 0xD8, 0x00, 0xDE, b'h', 0x00, b'i', 0x00];
        assert_eq!(text_of(&utf16le, &typed("text/plain; charset=utf-16le")), "\u{1F600}hi");
        assert_eq!(text_of(&utf16le, &typed("text/plain; charset=utf-16")), "\u{1F600}hi");
        let utf16be = [0xD8, 0x3D, 0xDE, 0x00, 0x00, b'h', 0x00, b'i'];
        assert_eq!(text_of(&utf16be, &typed("text/plain; charset=utf-16be")), "\u{1F600}hi");
        let shift_jis = [0x93, 0xFA, 0x96, 0x7B];
        assert_eq!(text_of(&shift_jis, &typed("text/html; charset=Shift_JIS")), "\u{65E5}\u{672C}");
    }

    #[test]
    fn a_byte_order_mark_outranks_the_label_and_is_dropped() {
        assert_eq!(text_of(&[0xEF, 0xBB, 0xBF, b'o', b'k'], &typed("text/plain; charset=iso-8859-1")), "ok");
        assert_eq!(text_of(&[0xFF, 0xFE, b'o', 0x00, b'k', 0x00], &Fields::new()), "ok");
        assert_eq!(text_of(&[0xFE, 0xFF, 0x00, b'o', 0x00, b'k'], &typed("text/plain; charset=utf-8")), "ok");
    }

    /// What `worker` returns if it finishes within `limit`, or None when it
    /// is still running then, so a test that would hang fails instead.
    fn finished_within<T>(worker: JoinHandle<T>, limit: Duration) -> Option<T> {
        let deadline = Instant::now() + limit;
        match wait_on(worker, || (Instant::now() >= deadline).then_some(Halt::TimedOut)) {
            Ok(value) => Some(value),
            Err((_, still_running)) => {
                drop(still_running);
                None
            }
        }
    }

    /// A lookup that answers only after three seconds.
    fn slow_lookup() -> std::io::Result<Vec<SocketAddr>> {
        std::thread::sleep(Duration::from_secs(3));
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], 443))])
    }

    /// Accepts one connection on `listener`, reads the first five bytes
    /// the client sends, and returns the server's side of the connection,
    /// kept open, with those bytes. Once the client hello has arrived this
    /// way, the client's handshake waits on a server that never answers.
    fn take_client_hello(listener: &std::net::TcpListener) -> std::io::Result<(TcpStream, [u8; 5])> {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut server_side = loop {
            match listener.accept() {
                Ok((accepted, _)) => break accepted,
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Err(std::io::Error::new(ErrorKind::TimedOut, "no client connected within 10 s")),
                Err(e) => return Err(e),
            }
        };
        server_side.set_nonblocking(false)?;
        server_side.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut record = [0u8; 5];
        server_side.read_exact(&mut record)?;
        Ok((server_side, record))
    }

    #[test]
    fn a_stop_ends_the_phase_at_once_while_the_handshake_waits() -> PsResult<()> {
        let _host = pwrs::testing::install();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let mut cmdlet = InvokeSecureFetch {
            uri: format!("https://127.0.0.1:{}/", listener.local_addr()?.port()),
            timeout_seconds: 60,
            no_proxy: true,
            trusted_roots: vec!["Bundled".to_string()],
            ..InvokeSecureFetch::default()
        };
        let stopping = AtomicBool::new(false);
        let scratch = std::cell::Cell::new(Vec::new());
        // SAFETY: the fake host is installed and held above, and the token
        // is used only on this thread for this one phase.
        let ps = unsafe { Pipeline::new(pwrs::sys::PsHandle::NULL, &stopping, &scratch) };
        let (result, returned, stopper) = std::thread::scope(|scope| {
            let stopper = scope.spawn(|| -> std::io::Result<(TcpStream, [u8; 5], Instant)> {
                let (server_side, record) = take_client_hello(&listener)?;
                std::thread::sleep(Duration::from_millis(200));
                stopping.store(true, Ordering::Relaxed);
                Ok((server_side, record, Instant::now()))
            });
            let result = cmdlet.process(&ps);
            (result, Instant::now(), stopper.join())
        });
        let (server_side, record, stopped_at) = match stopper {
            Ok(outcome) => outcome?,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        assert_eq!(record[0], 0x16, "the first record is not a TLS handshake record");
        assert_eq!(error_id(result), "SecureFetchStopped");
        let took = returned.duration_since(stopped_at);
        assert!(took < Duration::from_secs(1), "the phase ended {took:?} after the stop");
        drop(server_side);
        Ok(())
    }

    #[test]
    fn a_stopped_request_ends_as_stopped_when_its_wait_runs_out() -> PsResult<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let target = Target::parse(&format!("https://127.0.0.1:{}/", listener.local_addr()?.port()))?;
        let cancel = Arc::new(Cancel::default());
        let wait = Duration::from_secs(1);
        let outgoing = Arc::new(Outgoing::new("GET", true, Vec::new(), None, None)?);
        let job = Job {
            target,
            config: client_config(false, bundled_roots())?,
            post_quantum_only: false,
            wait,
            keep_alive: false,
            outgoing,
            max_decoded: 1 << 20,
            out_file: None,
            http_errors_to_file: false,
            redirects_followed: true,
            proxy: None,
            idle: None,
        };
        let worker = {
            let cancel = Arc::clone(&cancel);
            start("test-request", move || exchange(job, &cancel))?
        };
        let (server_side, record) = take_client_hello(&listener)?;
        assert_eq!(record[0], 0x16, "the first record is not a TLS handshake record");
        let stopped_at = Instant::now();
        assert!(cancel.stop().is_none());
        let result = finished_within(worker, Duration::from_secs(5));
        let took = stopped_at.elapsed();
        assert_eq!(result.map(error_id), Some("SecureFetchStopped".to_string()));
        assert!(took < wait + Duration::from_secs(1), "the stopped request ran {took:?} past the stop with a 1 s wait");
        drop(server_side);
        Ok(())
    }

    #[test]
    fn a_lookup_that_outlasts_the_wait_is_a_timeout() {
        let started = Instant::now();
        let result = resolve("slow.invalid", Duration::from_millis(300), &Cancel::default(), slow_lookup);
        let took = started.elapsed();
        assert_eq!(error_id(result), "SecureFetchTimeout");
        assert!(took < Duration::from_secs(2), "resolve waited {took:?} for a 300 ms bound");
    }

    #[test]
    fn a_stop_ends_the_wait_for_a_lookup() -> PsResult<()> {
        let cancel = Arc::new(Cancel::default());
        let stopper = {
            let cancel = Arc::clone(&cancel);
            start("test-stopper", move || {
                std::thread::sleep(Duration::from_millis(200));
                cancel.stop().is_none()
            })?
        };
        let started = Instant::now();
        let result = resolve("slow.invalid", Duration::from_secs(60), &cancel, slow_lookup);
        let took = started.elapsed();
        assert_eq!(error_id(result), "SecureFetchStopped");
        assert!(took < Duration::from_secs(2), "resolve waited {took:?} after a stop at 200 ms");
        assert_eq!(finished_within(stopper, Duration::from_secs(3)), Some(true));
        Ok(())
    }

    #[test]
    fn a_lookup_answer_becomes_addresses_or_a_resolve_error() -> PsResult<()> {
        let cancel = Cancel::default();
        let wait = Duration::from_secs(10);
        let one = SocketAddr::from(([127, 0, 0, 1], 443));
        assert_eq!(resolve("one.test", wait, &cancel, move || Ok(vec![one]))?, vec![one]);
        assert_eq!(error_id(resolve("none.test", wait, &cancel, || Ok(Vec::new()))), "SecureFetchResolve");
        let refused = || Err(std::io::Error::new(ErrorKind::NotFound, "no such host"));
        assert_eq!(error_id(resolve("refused.test", wait, &cancel, refused)), "SecureFetchResolve");
        let local = resolve("localhost", wait, &cancel, system_lookup("localhost", 443))?;
        assert!(local.iter().all(|addr| addr.ip().is_loopback() && addr.port() == 443), "{local:?}");
        Ok(())
    }

    #[test]
    fn a_panic_on_a_worker_resumes_on_the_waiting_thread() -> PsResult<()> {
        let worker = start("test-panics", || -> u8 { panic!("the worker panicked on purpose") })?;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wait_on(worker, || None)));
        assert!(caught.is_err());
        Ok(())
    }
}
