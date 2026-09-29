---
title: How To Choose Trusted Roots
weight: 9
---

rustls verifies every server certificate against a set of roots. By default the set is the Mozilla roots compiled into the module and, on Windows, the roots in the Windows certificate store; on a system without that store the default is the bundled roots alone, and naming `Windows` there is refused before any connection. `-TrustedRoots` chooses the sources and `-RootCertificate` adds roots of your own. Source: `src/lib.rs` (`trusted_roots`, `root_sources`, `windows_roots`, `client_config`).

## The default, and each source alone

`-TrustedRoots` takes Bundled, Windows and None:

- **Bundled**: the Mozilla roots that [webpki-roots](https://github.com/rustls/webpki-roots) compiles into the module.
- **Windows**: the current user's Root store (`Cert:\CurrentUser\Root`), which also shows the machine's and Group Policy's roots, read through the schannel crate. Only entries whose purposes allow server authentication and that are valid now are taken; an entry whose purposes or validity cannot be read, or that rustls cannot take as a root, is skipped with a verbose message naming its thumbprint.
- **None**: neither, so only `-RootCertificate` roots are trusted.

In the next example a test server on this machine (`https://localhost:8443/`) used a certificate issued by a private test root, which the test had added to `LocalMachine\Root`:

```powershell
(Invoke-SecureFetch https://localhost:8443/).Content
Invoke-SecureFetch https://localhost:8443/ -TrustedRoots Bundled -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
```

```text
SecureFetch test root
SecureFetchTls,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
the TLS exchange with localhost failed: invalid peer certificate: UnknownIssuer
```

## A root of your own

`-RootCertificate` takes `X509Certificate2` objects, such as those in the `Cert:` drive or one read with `[System.Security.Cryptography.X509Certificates.X509Certificate2]::new('ca.cer')`, which reads DER or PEM. They are trusted beside whatever `-TrustedRoots` names; with `-TrustedRoots None` they are the only roots. After the test root was removed from the store, `$root` held it:

```powershell
(Invoke-SecureFetch https://localhost:8443/ -TrustedRoots None -RootCertificate $root).Content
```

```text
SecureFetch test root
```

A choice that trusts nothing, or None beside another source, is refused before any connection:

```powershell
Invoke-SecureFetch https://localhost:8443/ -TrustedRoots None -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
```

```text
SecureFetchRootStore,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
no root is trusted: -TrustedRoots names no source of roots and no -RootCertificate is given, so no server could be verified
```

A `-RootCertificate` rustls cannot take as a root is refused before any connection too, as `SecureFetchRootStore` with category SecurityError, naming its subject and thumbprint. rustls-webpki, which parses certificates for rustls, reads none longer than 65535 bytes, so a certificate made longer with a 70000-byte extension shows it (the extension's identifier is under 2.25, the arc for identifiers made from a UUID):

```powershell
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Oversized example root', [System.Security.Cryptography.RSA]::Create(2048), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509Extension]::new('2.25.48383620782397916158158488059118089869', (New-Object byte[] 70000), $false))
$oversized = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
Invoke-SecureFetch https://localhost:8443/ -TrustedRoots None -RootCertificate $oversized -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].CategoryInfo.Category
$failed[0].Exception.Message
```

```text
SecureFetchRootStore,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
SecurityError
the -RootCertificate CN=Oversized example root (thumbprint B325565D4EDA325444C5791B9037CA4F2DEB59A9) cannot be used as a root: invalid peer certificate: BadEncoding
```

(The key is made anew each run, so Windows PowerShell's thumbprint was another one.)

## What trusting the Windows store costs

- The native library imports `crypt32.dll` to read the store.
- The default depends on the machine: it trusts whatever roots that machine's store holds, a corporate TLS-inspection root included.
- The Disallowed store is not consulted.
- A root Windows would download on demand is not in the store until Windows has fetched it; the bundled Mozilla roots cover the public ones.
- The roots are read once per invocation, not per request.
