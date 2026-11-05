# 13 — Intent: effects a package's purpose does not explain

A rule asks whether code contains a pattern, and an attacker answers by writing the pattern
another way. The intent layer asks a different question, from the package's content alone:

> Is every effect this package has on the machine explained by what it says it is, and by its
> user asking for it?

Spellings, splits and obfuscation change how code is written. They do not change what it does,
when it runs, or what the package claims to be.

```
  npm package
      │
      ├─► rules, then the package verdict        (unchanged; the layer runs after both)
      │
      └─► facts, content only ─────────────────────────────────────────────┐
            what the code can do       install_can_egress, hook, ...       │
            when each effect runs      t:install:egress   t:export:spawn   │
            what hides it              conceal:loader     conceal:computed_require
            what gates it              gate:env           gate:time        │
            purpose mismatch           m:import:egress  (effect rare for   │
                                       benign packages of the claimed purpose)
                                                                            ▼
                         weights file  detect/data/intent.json.gz  (measured, versioned)
                                                                            │
                         per group: the strongest fact; log weights summed; cosmetic total capped
                                                                            │
                 ┌──────────────────────────────────┬───────────────────────┴───────┐
                 ▼                                  ▼                               ▼
     score >= line                      a file that runs on install       otherwise: nothing
     SUSPECT.INTENT.                    or import was not read:           added
     UNEXPLAINED_EFFECT.001  (high)     verdict.intent "unknown",
     lists every fact, its cost         with the file and the cause;
     class and its weight               never a pass
```

## When an effect runs

The same call means different things in different places. A network call an HTTP client makes
when its user calls `get()` is its job; the same call at install, or at the top level of a colour
library, runs on every machine that installs or imports it, unasked.

```
  trigger    where the code is                                  runs when
  ─────────  ─────────────────────────────────────────────────  ─────────────────────────
  install    an install hook and what it loads, top level       npm install, unasked
  import     main / exports and what they require, top level    require() or import, unasked
  export     a function of imported code nothing loaded calls   the user calls it
  bin        a command the package links                        the user runs it
  test       test, spec, fixture, example files                 the developer runs tests
  unreached  a function of install code nothing calls, and      nothing runs it on its own
             shipped code nothing above loads
```

Code wrapped to look deferred is still read as running: an immediately invoked function, a
callback handed to `setTimeout`, `.then` or `process.on`, a function a running one calls by name,
and the methods the language calls itself (`constructor`, `then`, `toString`, accessors). A
module's effect runs where its binding is used, not where it is imported: `const https =
require('https')` inside an otherwise exported-only library is not a network call on import.

## What makes the weights trustworthy

Every weight comes from a measurement, and the loader refuses a file that breaks any of these:

```
  rule   what it means                                                        refused when
  ─────  ───────────────────────────────────────────────────────────────────  ─────────────────────
  M1     a fact weighs its conservative ratio: malware-rate lower bound over  weight is not log of
         the benign-rate upper bound (95% Wilson), capped at 50                its ratio, ratio <= 1
  E2     a fact needs at least 5 malware families                             fewer families
  E3     one attacker's clones count as one family                            (builder)
  M2     measured on study data only; the test half is scored once            (builder)
  M3     weights measured on npm decide only npm                              no scope
  M6     cosmetic facts (README, licence, types, tests, changelog, sizes)     cap not under the line
         add at most a capped total and never cross the line alone
  M7     rule outcomes are never facts                                        a rule id as a fact
  E6     only content facts, each tagged with its provenance: nothing from    an external fact, or
         the registry, intel, publisher or the scanner's own logs              provenance not content
  M8     a fact weighs only if it keeps its weight under cross-validation     not kept
  S3     facts are versioned; weights for other facts are not applied         facts version differs
  T5     the line keeps held-out benign npm within 0.5% (95% upper bound),    benign bound over 0.5%
         and popular npm the same; the stricter line wins
```

Without a weights file the facts are still computed and reported under `verdict.intent` in the
JSON output, and nothing is decided. The layer only adds a finding: it never lowers, holds or
removes one the rules made, and the package verdict never takes it as evidence.

Building the weights (`bench/model/intent_build.py`) reports aggregates only: rates, intervals and
family counts. It writes nothing per sample.

The shipped file (2026-10-19, scanner 15b212c, facts version 1) was built from npm half A only:
7,695 benign packages, 961 popular-npm packages and 1,903 malware packages in 1,531 families
(S5 family index), adjudication candidates left out.

```
  STUDY DATA (half A, cross-validated within it; half B is the test, scored once)
  ────────────────────────────────────────────────────────────────────────────────
  rows kept (M8: in >= 4 of 5 folds, held-out malware rate > benign)   129 of 138
  line                                                                  33.35
  held-out benign npm blocked          3 / 7,695   95% upper  0.115%    bar 0.5%
  popular npm blocked                  0 / 961     95% upper  0.398%    sets the line
  held-out malware blocked, alone      34.2% of packages  (31.8% - 36.6%)
```

Popular npm sets the line: one block in 961 would put its upper bound past 0.5%. The malware rate
is the layer on its own; what it adds over the rules is measured by the A/B.

Not read today: npm packages whose verdict area is `mcp` (MCP servers; 2.9% of the benign sample),
and tarballs whose single top directory is not `package/` (0.8% of the benign sample), which the
engine does not recognise as npm yet.

## What it does not claim

It does not claim that no attack passes. It changes what passing requires: an effect that looks
necessary for the stated purpose, runs only when the user asks for it, and is not hidden. Known
limits:

```
  A1  purpose laundering    a package whose stated job is fetching and running code
                            (a binary installer) explains a download by its purpose
  A5  moved payload         the payload in a dependency, or a clean first release and a
                            malicious later one: judged per package and per release
  A6  payload as data       benign code steered by remote data: the effect is explained,
                            what it is told to do is not read
  A8  offline probing       an open scanner can be run against a payload until it passes;
                            caps, family weighting and hard rules outside the score raise
                            the cost, they do not remove it
```

npm is read first. Every other ecosystem gets the layer once its facts are measured on its own
benign corpus and malware.
