# 15 · Output formats

One scan, any number of renderings. Pick by audience.

```
   FORMAT      AUDIENCE                        HOW
   ──────      ────────                        ───
   text        humans at a terminal (default)  -f text
   json        your tooling / storage          -f json:out.json
   sarif       code-scanning UIs (GH/GL)        -f sarif:cordon.sarif
   junit       test-report dashboards          -f junit:cordon.xml
   markdown    a PR comment / a wiki            -f markdown:report.md
   github      inline PR annotations           -f github
```

## Emit several at once

```
   cordon-scanner scan . \
       -f text \                        # to the terminal for the human
       -f sarif:cordon.sarif \          # to a file for code-scanning
       -f json:cordon.json              # to a file for your own tooling

   --output/-o writes a single format to a file; :PATH does the same inline and
   is repeatable, so prefer -f FMT:PATH when emitting more than one.
```

## Render again later — no re-scan

```
   scan once, keep the JSON            then re-render, offline, any time
   ───────────────────────            ───────────────────────────────
   scan . -f json:result.json    ──▶  report convert  result.json  -f markdown
                                        report convert  result.json  -f sarif
```

## The bill of materials

```
   cordon-scanner sbom generate .        CycloneDX or SPDX, from the RESOLVED graph
```

```
   The SBOM is reconciled against the graph Cordon actually resolved — not a
   separate parse that could quietly disagree with what was scanned.
```

## Inventory — "what does Cordon think this repo is?"

```
   cordon-scanner inventory .            languages, manifests, lockfiles, CI files,
   cordon-scanner inventory . -f json    and the evidence for each call
```

Next: **[16 · The sandbox](16-the-sandbox.md)** — the one component that runs
what it is given, and everything that keeps it away from the rest.
