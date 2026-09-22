# 02 · How detection works

Cordon is a pipeline of pure stages. Nothing here runs your code.

```
   SOURCE            UNITS                DETECTORS              FINDINGS       REPORT
  ┌────────┐      ┌──────────┐        ┌────────────────┐      ┌─────────┐   ┌───────┐
  │ working│      │ one file │        │ content checks │      │ sorted, │   │ text  │
  │  tree, │ ───▶ │  = a unit│ ─────▶ │ graph checks   │ ───▶ │ deduped,│──▶│ json  │
  │  git,  │      │ the graph│        │ repo checks    │      │ scored  │   │ sarif │
  │ archive│      │  = a unit│        └────────────────┘      └─────────┘   │  ...  │
  └────────┘      └──────────┘                                              └───────┘
```

## The core idea: capabilities compose into rules

A single dangerous line is usually not a finding. A *combination* is.

```
   CAPABILITY PRIMITIVES                       COMPOSITE RULE
   (one thing the code can do)                 (a dangerous combination, in one file)

   ┌──────────────┐
   │ CAP.*.DECODE │ base64/hex decode ─────┐
   └──────────────┘                        │      ┌─────────────────────────────┐
   ┌──────────────┐                        ├────▶ │ decode  ──▶  execute        │
   │ CAP.*.EXECUTE│ eval / exec / vm ──────┘      │ within N lines of each other│
   └──────────────┘                               │  = second-stage loader      │
   ┌──────────────┐                               └─────────────────────────────┘
   │ CAP.*.SPAWN  │ child_process / subprocess          SUSPECT.DECODE_EXEC.001
   └──────────────┘
```

Capabilities are cross-language: the same composite fires whether the decode+exec
is in Python, JavaScript, or a shell script.

## How a rule "sees" — the match kinds

```
   literal      exact byte substring                     fastest, known indicators
   regex        validated safe subset                    no backrefs, no runaway nesting
   entropy      Shannon entropy + shape guard            embedded keys / blobs
   structural   query a parsed manifest/config           lockfiles, CI YAML
   ast          resolve real calls through the syntax    sees through aliases & folding
   graph        predicate over the dependency graph      advisories, provenance
   composite    boolean over other rules, with a scope   the combinations above
```

## Why `ast` matters — obfuscation doesn't help

```
   The regex tier sees text.          The ast tier resolves the call.

   os.system("id")                    ─┐
   f = os.system; f("id")             ─┤──▶  all resolve to →  os.system
   getattr(os,"sys"+"tem")("id")      ─┘

   import { exec as e } from 'child_process'; e("id")   →  child_process.exec
```

Python resolves via the standard library (always on). JavaScript/TypeScript need
the `[ast-js]` extra — without it those files still get the regex tier, and the
AST tier reports the language as *not analysed* rather than pretending it was.
See **09**.

## Every detector must prove it works

```
   A detector that never fires looks exactly like one that ran and found nothing.
   So each ships with a corpus sample that makes it fire — or it does not ship.
```

Next: **03 — malware & vulnerabilities**, the detectors that use outside intel.
