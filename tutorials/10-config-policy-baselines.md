# 10 · Config, policy & baselines

Three layers, from most local to most binding:

```
   ┌───────────────────────────────────────────────────────────────┐
   │  ORG POLICY   (--policy)   a ceiling: can FORBID weakening      │  most binding
   │  ┌─────────────────────────────────────────────────────────┐   │
   │  │  REPO CONFIG (--config)  the project's own settings       │   │
   │  │  ┌───────────────────────────────────────────────────┐   │   │
   │  │  │  CLI FLAGS   the single run                         │   │   │  most local
   │  │  └───────────────────────────────────────────────────┘   │   │
   │  └─────────────────────────────────────────────────────────┘   │
   └───────────────────────────────────────────────────────────────┘
     A local flag cannot loosen what the org policy pins. --no-detector
     can be FORBIDDEN centrally, so a pipeline can't quietly disable a check.
```

```
   cordon-scanner scan .  --config cordon.toml  --policy org-policy.toml
   cordon-scanner config  --config cordon.toml           # validate without scanning
```

## Baselines — adopt on a messy codebase

```
   DAY 0                                 EVERY DAY AFTER
   ─────                                 ───────────────
   baseline create -o base.json          scan . --baseline base.json
        │                                     │
   record ALL current findings           known findings = silent
   as "already known"                    only NEW findings fail the build
```

```
   baseline create   -o base.json        snapshot the current findings
   baseline compare  ... base.json       report only what's outside the baseline
```

```
   THE POINT
   ┌──────────────────────────────────────────────────────────────┐
   │ You don't have to fix 400 legacy findings before you start     │
   │ catching the 401st. The baseline draws the line at "today".    │
   └──────────────────────────────────────────────────────────────┘
```

## Evidence redaction — safe to share a report

```
   --evidence  masked      (default)   matched secret shown masked
   --evidence  hash_only               only a hash of the match
   --evidence  none                    no evidence  (only where a rule permits;
                                        no shipped rule permits it)

   The STRICTER of --evidence and each rule's own policy wins.
```

Next: **11 — output formats**.
