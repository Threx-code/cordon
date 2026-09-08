# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-08

First release. Everything below is in it; there is no earlier published
version, so nothing here is a change from one.

### Names

The distribution is `cordon-scanner`, the console script is `cordon-scanner`,
and the import package is `cordon_scanner`.

Not `cordon` in any of the three. That name belongs on PyPI to an unrelated
project which ships both a top-level `cordon` package and a `cordon` console
script, so installing both into one environment has pip write two distributions
into the same directory and leave whichever landed last. Configuration
filenames (`cordon.yaml`), cache paths and the `CORDON_*` variables are
unaffected -- they are not installed names and cannot collide.

### Scanning

- Scans a directory, a file or an archive across eight package ecosystems, with
  no third-party runtime dependencies and no network access.
- `--staged`, `--tracked` and `--git-diff REF`, through a file-source
  abstraction. Staged mode reads blobs from the git index rather than the
  working tree, so a payload cannot be staged and the clean copy restored.
- Findings in five categories with independent severity and confidence axes.
  `MALICIOUS` at `CONFIRMED` confidence is reachable only through an exact
  package-and-version match against the advisory database.
- `text`, `json`, `sarif`, `markdown` and `junit` output.
- A live progress line on standard error while a scan runs, showing the phase,
  the count and the current file. On only when standard error is an
  interactive terminal; `--progress always|never` overrides that. It is on
  standard error so it stays out of the report a pipeline parses, and the paths
  it shows are escaped, because a filename may legally contain an ANSI control
  sequence or a bidirectional override.
- Incremental cache keyed on content, configuration and detector identity, with
  every entry authenticated by a per-machine HMAC.
- `cordon-scanner baseline create|compare` and `scan --baseline PATH`, so the tool can
  be adopted on a repository that is not clean yet.
- `cordon-scanner rules`, `cordon-scanner config`, `cordon-scanner inventory`, `cordon-scanner report` and
  `cordon-scanner guard`, plus `python -m cordon_scanner_scanner`.

### Not looking is reported as not looking

The invariant the design is built around: a scan that examined nothing must
never report like a scan that found nothing.

- Configuration supplied by the scan target cannot exclude paths, disable
  detectors or disable rules without that appearing in the report at a severity
  the default gate fails on.
- A scan that examined no files fails, whether the files were excluded, removed
  by the selected source, or could not be read.
- Truncated files, per-file and whole-scan timeouts, memory and path limits,
  rejected archive members and detector failures are each reported and mark the
  scan incomplete.
- Reporting thresholds cannot hide a finding from the failure gate.
- Organisation policy acts as a ceiling that command-line overrides are
  re-checked against.

### Not becoming the leak

- Evidence is redacted at construction, never at render time, so unredacted
  content never reaches a reporter. Secret-category rules cannot opt out.
- Package coordinates are bounded at the model, so a parser that reads past the
  field it wanted cannot publish the rest of the line.
- Reports carry no absolute filesystem paths.

### Not executing the target

- Manifests and lockfiles are parsed, never invoked; `setup.py` is read through
  `ast.parse` and nothing in it is evaluated.
- Git runs with system and global configuration disabled and with every
  configuration key that names an external command neutralised, so a
  repository cannot execute code through the scan that examines it.
- Rule patterns are validated by walking the parsed regex, so nesting,
  lookaheads and non-capturing groups cannot hide a catastrophic shape. Every
  pattern compiled inside the package is held to the same rule by test.
- File loading opens with `O_NOFOLLOW` and checks the descriptor, closing a
  time-of-check/time-of-use window. Symbolic links are recorded, never
  followed.
- A third-party distribution cannot shadow a built-in detector.

### The Action

- Installs with `--require-hashes` against `action/requirements.txt`, generated
  at release time from the artefacts actually published. Pinning the Action to
  a commit SHA covers `action.yml` only; without this it says nothing about
  what pip downloads, and a compromised index or release account would replace
  the scanner in every workflow using it.
- A ref carrying no pin refuses to install rather than installing unverified.
  `allow-unverified-install: true` overrides that in the workflow file, where
  it is reviewable, and warns about what it gives up.
- Every action referenced by this project's own workflows is pinned to a commit
  digest, enforced by test rather than by review.

### Known limits

- The bundled advisory database is deliberately small and covers documented
  supply-chain incidents. It is not a substitute for a feed; load one with
  `--advisories`.
- `kind: ast` rules require the `ast` extra. Without it they fall back to their
  declared regex form and the scan reports that they did.
- The YAML accepted in configuration is a restricted subset: no anchors,
  aliases or tags.
