# 04 · Reachability — cut noise without hiding anything

The loudest complaint about scanners: a CVE in a package three levels down that
your code never touches, screaming at the same volume as one you call constantly.

```
   cordon-scanner scan . --reachability
```

## The rule that keeps it honest

```
                    ANNOTATE, NEVER SUPPRESS
   ┌─────────────────────────────────────────────────────────────┐
   │  An unreached finding is LOWERED and TAGGED — never dropped.│
   │  Gate on "reached only" if you want; the rest stay in the   │
   │  report where a reviewer can still see them.                │
   └─────────────────────────────────────────────────────────────┘
```

## The decision

```
   vulnerable dependency
          │
          ▼
   does first-party code import it?
          │
   ┌──────┴───────┐
   YES            NO
   │              │
   │        is it a DIRECT dependency?
   │          │            │
   │        YES            NO (transitive)
   │          │            │
   ▼          ▼            ▼
 IMPORTED   UNKNOWN     NOT_IMPORTED
 (severity  (severity   (severity LOWERED
  kept)      kept)       one step + tagged)
```

## Two rules you must not get wrong

```
   UNKNOWN ≠ UNREACHED
   ───────────────────
   A direct dep you don't see imported may be loaded dynamically, or under a name
   the distribution doesn't publish (beautifulsoup4 → bs4). Import-checking can't
   rule that out, so it stays UNKNOWN and its severity does NOT move.

   MALWARE never moves
   ───────────────────
   A compromised release must not be installed whether or not it is called.
   Reachability only ever lowers a VULNERABILITY, never a malicious package.
```

## What it looks like

```
   BEFORE                                  AFTER  --reachability
   ──────                                  ──────────────────────
   HIGH   CVE in leftpad (transitive)  ──▶ MEDIUM  CVE in leftpad
                                              "…not imported by first-party code,
                                               lowered rather than dropped"
   HIGH   CVE in requests (you import) ──▶ HIGH    CVE in requests
                                              "…imported by first-party code"
```

This is the cheap, always-available import tier. The precise call-graph tier —
is the vulnerable *symbol* on a path you actually reach — builds on the AST
providers (tutorial 09) and is a later layer.

Next: **05 — provenance & attestation**.
