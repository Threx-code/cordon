# Why this exists

What the other tools in this space do, what they do not, and the gap
this was built to sit in.

## Why this exists

```
   SAST / linters / CVE DBs  answer:  "does the code I WROTE contain a bug?"
   Cordon                    answers:  "is the code I did NOT write attacking me?"
```

A typical app is a few thousand lines of first-party code on top of a few
**hundred thousand** lines of third-party code — resolved transitively and run on
the developer's machine at **install time**, before any test, review or container.

```
   THE ATTACK, ON REPEAT
   gain publish rights ──▶ publish a version identical to the last ──▶ + a
   (phished account,        plus one lifecycle script                  lifecycle
    expired domain,         (postinstall, prepare, build.rs,           hook runs
    typosquat, handed-off   setup.py, a Gradle task)                   as YOU
    package)                                                             │
        the script reads SSH keys / cloud creds / publish tokens ◀───────┘
        and sends them out — then uses them to poison every package you maintain.

   All of it between typing `install` and getting a prompt back. No review, no
   CI gate, no sandbox. This is event-stream, ua-parser-js, coa, rc, node-ipc,
   the torchtriton dependency-confusion, the xz-utils backdoor, the 2025 npm worms.
```

Three properties follow, and shape everything:

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │ 1  THE TARGET IS UNTRUSTED INPUT, config file included. A repo cannot   │
   │    use its own config to blind the scan without the output saying so.   │
   │ 2  NOTHING FROM THE TARGET IS EXECUTED. Lockfiles are parsed, never     │
   │    resolved. No package manager is invoked.                             │
   │ 3  REDUCED COVERAGE IS ALWAYS REPORTED. A limit hit, a detector off, a  │
   │    file excluded, a rule disabled — each is a finding. Examined-nothing │
   │    must never look like found-nothing.                                  │
   └─────────────────────────────────────────────────────────────────────────┘
```

### The guarantee, stated precisely

Cordon is a static analyser; static analysis cannot decide what a program does
at runtime. So the promise is deliberately narrow:

> **No evasion is silent.** A technique used to hide behaviour is either resolved
> to the real behaviour, or produces a signal of its own.

```
   RESOLVED (each has a test)          →  the real callee
   ─────────────────────────
   rename an import, bind to a local, split a token across a concat,
   compute a name at runtime, encode in layers, write shell inside another lang
                                       │
   what CANNOT be resolved ────────────┴──▶ becomes its OWN finding
                                            (a runtime-assembled target = dynamic dispatch)

   what remains = behaviour that exists only when the code RUNS (a payload
   decoded from a network response). No static tool sees that; this one does not
   pretend to — that is the separate, opt-in sandbox.
```

Detection is strongest where a language pack defines the capability primitives; a
language with no pack inherits no behavioural rules (the coverage matrix says
which). Registry-answered checks (withdrawal, published-hash) need `--online`.

---

### What leaves the machine, and when

```
   NEVER, in any mode      source code, file contents, evidence snippets, credentials

   by default              the signed intel feed is PULLED — static files, identical
                           for everyone, so the request says nothing about what is
                           scanned. --offline / CORDON_OFFLINE=1 stops even that.

   only with --online      package names and versions: to the registry (withdrawal,
                           hashes, provenance), to OSV (an image's OS packages), and
                           MCP server packages are FETCHED (never installed, never run)

   only when asked         --upload (results), --notify (rule, path, fingerprint),
                           cordon agent report (inventory and findings)
```

Each line is a choice about one kind of disclosure. A dependency's name is the one thing a scan
of a private repository would leak by asking about it, so every check that asks is behind
`--online`; the feed is on by default because pulling it leaks nothing.

### Why exploited is its own rule

A known vulnerability and one attackers are using call for different responses, and the EU Cyber
Resilience Act makes the difference legal: an actively exploited vulnerability in a product a
manufacturer ships is reportable within 24 hours. So a dependency whose CVE is on CISA's KEV
catalogue or ENISA's EUVD exploited list is `VULNERABLE.DEPENDENCY.EXPLOITED.001` at CRITICAL,
whatever its CVSS rating, and a policy can fail on it alone.

### Reachability annotates, never suppresses

The call tier names which of a vulnerable package's functions first-party code calls, and leaves
the comparison with the advisory to a reviewer: the advisory data rarely says which function is
vulnerable, and a scanner that guessed would be hiding findings on a guess. Only two verdicts lower
a severity, and both are about code that cannot run from here: a transitive dependency nothing
imports, and an import made only for type checking.

### What blocks is what runs on its own

The default gate fails a build on code that executes without anyone deciding to run it: an install
hook, a `.pth` file, a pipeline step, a Makefile or Dockerfile a build runs unattended, a library's
top level that executes on import. The same fetch-and-run in an `install.sh`, or inside a function
a CLI calls on request, is reported at MEDIUM: it is true, and it is what installers do, and a gate
that fails on the installer scripts of a third of popular repositories gets switched off. A script
that decodes on the way to running is never lowered; in Python or JavaScript the decode is lowered
only when it too sits in a function nothing on the load path calls -- decoding an API response in a
method is not a payload. `--fail-on medium` puts the stricter line back for a team that wants it.

Evidence about what runs outranks a guess about what a file is for. A directory called
`@acme-data-samples` is not a samples directory when a `preinstall` hook names a file in it, and a
local workspace package is not the registry package squatted under its name.
