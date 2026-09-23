# Running it somewhere

Pre-commit, CI, containers, and the organisation-wide policy that a
repository cannot weaken. Each block below is complete: copy it, change
the paths, and it runs.

## Environments

```
   LOCAL          cordon-scanner scan .
                  incremental cache in $XDG_CACHE_HOME/cordon (authenticated;
                  a foreign entry is ignored). --cache-dir moves it.

   PRE-COMMIT     cordon-scanner guard install     # fail-closed shims in .git/hooks
                  guard verify                      # check they're intact
                  hooks live in .git/hooks (untracked): no commit/switch/clean
                  removes them, and if cordon can't run, the commit is refused.
```

Or the `pre-commit` framework — pinned to a release tag:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Threx-code/cordon
    rev: v0.4.0
    hooks:
      - id: cordon
```

```
   GITHUB ACTIONS
   - uses: Threx-code/cordon/action@<sha>     # pin by commit, not tag
     with: {target: ., severity: medium, fail-on: high, sarif: true}

   inputs pass through the ENV, never interpolated into a shell. The action
   refuses to run under pull_request_target (writable token + secrets on a job
   that may check out untrusted code).
```

Or call the CLI directly — note `if: always()`, or uploading only on success
hides findings exactly when there are some:

```yaml
- run: pipx install cordon-scanner
- run: cordon-scanner scan . -f github -f sarif:cordon.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: cordon.sarif}
```

```
   GITLAB · JENKINS · AZURE   templates in ci/ — all reduce to two lines:
     pip install cordon-scanner
     cordon-scanner scan . --fail-on high -f junit:cordon-junit.xml

   MONOREPO      cordon-scanner scan . --tracked --jobs 8 --exclude 'third_party/**'
                 cordon-scanner scan . --git-diff origin/main     # pull requests
                 exclude generated trees rather than lowering a limit — an
                 exclusion is visible; a lowered limit is a coverage loss.

   AIR-GAP       offline by default, no runtime deps. Nothing need be reachable.
                 --advisories ./advisories.json    to bring your own intel
                 see tutorial 11 for the signed offline bundle
```

Templates live in [`ci/`](https://github.com/Threx-code/cordon/tree/main/ci).
The advisory database ships inside the wheel (malicious entries + high/critical
vulns, to bound size); `cordon-scanner advisories sync` fetches the full,
unfiltered set into a local cache a scan then prefers — still no network at scan
time, only at the moment you ask for a refresh. A supplied `--advisories` file
*replaces* the bundled one rather than merging, so what you act on is what you chose.

```
   DYNAMIC ANALYSIS is a SEPARATE binary — on purpose, so nothing in a scan can
   ever execute what it scans:
     cordon-sandbox pypi suspicious-package --sandbox --fail-on high
```

### Enterprise — an organisation ceiling

```yaml
# org-policy.yaml   (point at it with --policy or $CORDON_POLICY)
version: 1
name: "acme-baseline"
enforce:
  min_severity_threshold: low       # repositories may not report less
  min_confidence_threshold: low
  detectors_required: [capability, manifest, secrets]
  allow_limit_increase: false
  allow_plugins: false
  allow_extra_rule_packs: false
  allow_network: false
  max_total_timeout: 600
policy: {fail_on: [high, {category: malicious}], fail_on_incomplete: true}
suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_path_only: true
  forbid_categories: [malicious]
```

A repository config that conflicts with the ceiling is **refused, with the
conflict named** — not silently clamped. Command-line flags are checked against
the same ceiling.

---
