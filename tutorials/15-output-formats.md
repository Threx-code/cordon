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


## Two formats for somebody else's tooling

```
   codeclimate   GitLab Code Quality. The only report GitLab renders inline on
                 every plan -- its security dashboards are a licensed feature,
                 this is not. Findings appear in the merge request against the
                 lines they touch.

   vex           CycloneDX VEX. An SBOM says what is in the artefact; a VEX
                 says which of its vulnerabilities apply. With --reachability,
                 a transitive dependency your code does not import is recorded
                 as not_affected / code_not_reachable, so a consumer's tooling
                 can drop what you have already ruled out instead of raising it
                 again in their inbox.
```

```yaml
# .gitlab-ci.yml
scan:
  script:
    - cordon-scanner scan . --format codeclimate:gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

```bash
cordon-scanner sbom . --format cyclonedx --output sbom.cdx.json
cordon-scanner scan . --reachability --format vex --output sbom.vex.json
```

Publish the two together: the VEX references components by purl rather than
restating them, which is what the specification calls an independent VEX.

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
