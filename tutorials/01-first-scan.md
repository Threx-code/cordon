# 01 · Your first scan

```
  pip install cordon-scanner
  cordon-scanner scan .
```

That is the whole thing. No config, no network, no setup.

## What happens

```
   cordon-scanner scan .
        │
        ▼
   ┌─────────────┐   walk the tree      ┌──────────────┐
   │  your repo  │ ───────────────────▶ │  identify    │  what is this? which
   │  (a dir,    │                      │  the target  │  languages, manifests,
   │   file or   │                      └──────┬───────┘   lockfiles, CI files?
   │   archive)  │                             ▼
   └─────────────┘                      ┌──────────────┐
                                        │   detectors  │  run every applicable check
                                        └──────┬───────┘
                                               ▼
                                        ┌──────────────┐
                                        │   findings   │  sorted, de-duplicated
                                        └──────┬───────┘
                                               ▼
                                        ┌──────────────┐
                                        │    report    │  to your terminal
                                        └──────────────┘
```

## Reading a finding

```
   .  CRITICAL   package "left-pad" decodes a payload and executes it   MALWARE.DROPPER.001
      │          │                                                       │
   severity   what it found (plain language)                         rule id (stable)

   Run again with -v for the evidence, the score, and the fix.
```

## Exit codes — the part CI cares about

```
   0  clean          nothing met the failure policy
   1  findings        something met --fail-on
   2  scanner error   cordon itself broke   (never your code's fault)
   3  config error    bad config/policy/override
   4  incomplete      scan was degraded and --fail-on-incomplete was set

   if cordon-scanner scan . ; then echo ok ; fi     # any non-zero fails safe
```

## Narrowing what you scan

```
   cordon-scanner scan .  --include "src/**"          only these paths
   cordon-scanner scan .  --exclude "vendor/**"        skip these (repeatable)
   cordon-scanner scan .  --tracked                    only files git tracks
   cordon-scanner scan .  --git-diff origin/main       only what changed vs a ref
```

## Turning the dial

```
   --severity   LEVEL     report at/above  info|low|medium|high|critical
   --fail-on    LEVEL     break the build  at/above this severity
   --quiet   /  --verbose  less / more (the evidence and score derivation)
```

Next: **02 — how detection works**, to understand *why* a finding fired.
