# 07 · CI & git hooks

Two places to run Cordon: in the pipeline, and before a commit ever lands.

```
   DEVELOPER                        CI PIPELINE
   ─────────                        ───────────
   git commit                       push / PR
      │                                │
   pre-commit hook (--staged)       cordon-scanner scan . --fail-on high
      │                                │           --format sarif:cordon.sarif
   fail closed on a finding         upload SARIF ─▶ code-scanning UI
```

## In CI — the gate

```
   cordon-scanner scan .  --fail-on high  --format sarif:cordon.sarif

        exit 0  clean          ─▶ pipeline continues
        exit 1  findings       ─▶ pipeline fails (something ≥ high)
        exit 2  scanner error  ─▶ pipeline fails (cordon broke, not your code)
        exit 3  config error
        exit 4  incomplete     (only with --fail-on-incomplete)
```

```
   --format text        humans (default, to the terminal)
   --format json:out.json    machines / your own tooling
   --format sarif:cordon.sarif   GitHub/GitLab code-scanning
   --format github      inline PR annotations
   -f  is repeatable — emit several at once.
```

## Adopting on a dirty codebase — don't drown in day-one noise

```
   cordon-scanner baseline create -o cordon-baseline.json   # record what's there now
   cordon-scanner scan . --baseline cordon-baseline.json    # only NEW findings fail
```

See tutorial **10** for the baseline lifecycle.

## The pre-commit guard — fail closed, tamper-evident

```
   cordon-scanner guard install        # writes fail-closed git hooks
   cordon-scanner guard verify         # check the hooks are intact
   cordon-scanner guard update         # regenerate the hash manifest
```

```
   WHY "fail closed" + "tamper-evident"
   ┌───────────────────────────────────────────────────────────────────┐
   │ staged mode reads the git INDEX, not the working tree — so the    │
   │ add-then-restore bypass is closed.                                │
   │ the guard hashes its own hooks; a replaced or removed hook is     │
   │ detected, not silently skipped.                                   │
   └───────────────────────────────────────────────────────────────────┘

   the hook runs:  cordon-scanner scan --staged ...   (fast, only staged content)
```

Next: **08 — air-gapped**.
