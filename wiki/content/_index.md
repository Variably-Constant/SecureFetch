---
title: SecureFetch Wiki
toc: false
---

`Invoke-SecureFetch` makes HTTPS requests from PowerShell with its own TLS stack: rustls, running inside the module, which offers the X25519MLKEM768 hybrid post-quantum key exchange first. It runs in Windows PowerShell 5.1 and PowerShell 7.4 or later, and every response it writes says which protocol version, key exchange and cipher suite carried it.

```powershell
Install-Module SecureFetch -Scope CurrentUser
Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace | Select-Object StatusCode, Protocol, KeyExchange
```

```text
StatusCode Protocol KeyExchange
---------- -------- -----------
       200 TLSv1_3  X25519MLKEM768
```

{{< cards >}}
  {{< card link="docs/tutorials/" title="Tutorials" subtitle="Learning-oriented. Getting Started installs the module, makes a first request and reads what came back." icon="academic-cap" >}}
  {{< card link="docs/how-to/" title="How-to" subtitle="Task-oriented recipes: methods and bodies, headers, errors, post-quantum, timeouts and stopping, redirects, files, proxies, roots, compression, charsets, keep-alive." icon="cog" >}}
  {{< card link="docs/explanation/" title="Explanation" subtitle="Why a module of its own, and how one request runs from the pipeline thread to the socket and back." icon="book-open" >}}
  {{< card link="docs/reference/" title="Reference" subtitle="Invoke-SecureFetch's parameters, the SecureFetch.Response type, every error id, and where it has been run." icon="document-text" >}}
  {{< card link="docs/building/" title="Building From Source" subtitle="The build, the module folder it writes, and the tests, for working on the module itself." icon="code" >}}
{{< /cards >}}

## Quick links

- **New here?** [Getting Started](Getting-Started.md): install, first request, what came back.
- **Looking up a parameter?** [Invoke-SecureFetch Reference](Invoke-SecureFetch-Reference.md).
- **Reading a response?** [SecureFetch.Response Reference](Response-Reference.md).
- **An error record in hand?** [Error Reference](Error-Reference.md), by the id its `FullyQualifiedErrorId` starts with.
- **Only post-quantum, or nothing?** [How To Require Post-Quantum TLS](How-To-Require-Post-Quantum-TLS.md).

## Where the output on these pages comes from

Every example on these pages was run on Windows 11 Pro 10.0.26200 on an AMD Ryzen 9 7900X, in PowerShell 7.6.6 and in Windows PowerShell 5.1.26100.9444, against the module `cargo pwrs build --release` built from the code these pages describe, with PoWerRuSt 0.3.0 and cargo-pwrs 0.3.0 from crates.io. The output shown is PowerShell 7's; Windows PowerShell printed the same, apart from the differences each page names. Examples that talk to public servers show what those servers answered in that run. Where a page says outside an example what a run showed, it reports a build, a test run or an end-to-end run that [Where It Has Been Run](Where-It-Has-Been-Run.md) lists with its machine and build.

## License

MIT, in [LICENSE](https://github.com/Variably-Constant/SecureFetch/blob/main/LICENSE) on the repository.
