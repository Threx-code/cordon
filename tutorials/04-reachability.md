# 04 · Reachability — cut noise without hiding anything

> **For Cordon 0.5.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

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
providers (tutorial 13) and is a later layer.

Next: **[05 · Provenance & attestation](05-provenance-attestation.md)**.

## Go: is the vulnerable *function* called?

For Go, Cordon goes one level deeper. The Go vulnerability database names the functions each
advisory is about, and Cordon checks first-party code for calls to them:

```bash
cordon-scanner scan . --reachability
```

```
  html.Parse(...) in main.go     "first-party code calls the vulnerable function the
                                  advisory names (golang.org/x/net/html.Parse)"   unchanged

  only html.EscapeString(...)    "first-party code calls none of them. A dependency
                                  still could, so it is lowered rather than dropped" one step lower
```

Nothing is ever removed, and the standard library is annotated but never lowered: dependencies
call it constantly, so first-party code not calling a function proves little there.
