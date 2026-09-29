---
title: Documentation
toc: false
sidebar:
  open: true
---

The SecureFetch docs are organized under the [Diataxis](https://diataxis.fr/) framework: four kinds of documentation, each answering a different reader question, and a fifth section for building the module from its repository. Every page names the source it describes; the module is one file, `src/lib.rs`, with its Pester suite in `tests/SecureFetch.Tests.ps1`.

{{< cards >}}
  {{< card link="tutorials/" title="Tutorials" subtitle="Learning-oriented. Getting Started: install, a first response, and what it says." icon="academic-cap" >}}
  {{< card link="how-to/" title="How-to" subtitle="Task-oriented recipes, one per parameter family." icon="cog" >}}
  {{< card link="explanation/" title="Explanation" subtitle="Why a module of its own, and how a request runs." icon="book-open" >}}
  {{< card link="reference/" title="Reference" subtitle="Every parameter, every property with its type, every error id, and where it has been run." icon="document-text" >}}
  {{< card link="building/" title="Building From Source" subtitle="What the build needs, cargo pwrs build and test, and the module folder." icon="code" >}}
{{< /cards >}}
