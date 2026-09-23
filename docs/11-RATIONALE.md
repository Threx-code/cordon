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
