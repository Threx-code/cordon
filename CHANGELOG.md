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
  sequence or a bidirectional override. The line is measured in terminal
  columns rather than code points, so a CJK or emoji filename does not wrap.
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

### Rule kinds

`MatchKind` declares `ast`, `structural` and `graph`, and nothing implements
them. A rule pack using one is refused at load with a message saying so, rather
than accepted and silently unable to match. A rule that never fires looks
exactly like a rule that found nothing, which is the failure this project is
organised around, applied to rules.

### Air-gapped installation

- `cordon-scanner bundle create|verify|install` moves a release across an air
  gap with the transfer made checkable. The bundle carries a `MANIFEST.sha256`
  in `sha256sum` format, so an operator who distrusts it does not have to run
  the program inside it to decide whether to trust it.
- `verify` fails closed on a modified file, a missing file, an unlisted extra
  file, a traversal member, a symlink, or a missing manifest. `install`
  verifies first and writes nothing if verification fails.
- It reports what it did *not* prove: the manifest shows the bundle is the one
  its own manifest describes, not who produced it. That comes from the detached
  signature made at release.

### Organisation policy distribution

- `--policy` accepts a URL, which must carry a `#sha256=` digest. Without one
  it is refused: an organisation policy is the ceiling, so whoever controls the
  network would otherwise control whether the ceiling exists.
- Fetching requires `--allow-network`, the only network operation the tool has.
  Scanning never uses the network.
- Verified policies are cached by digest, so the second scan on a machine needs
  no network and an air-gapped site can populate the cache by hand. The digest
  is re-checked on every use, because the cache is an ordinary directory other
  processes can write.
- HTTPS only, a 1 MB cap, and nothing is cached when verification fails.

### Audit

- `--audit-log PATH` appends one JSON line per scan: the rule pack and
  configuration hashes, the commit, counts by severity, whether the scan
  completed, the exit code, and every suppression that applied with its
  justification, approver and expiry. Never file content.
- A git remote is recorded with its credential stripped. Every CI checkout
  looks like `https://x-access-token:<token>@host/org/repo.git`, and an audit
  log is retained longer and read by more people than a report.
- An unwritable path is refused before the scan runs, not after it.
- `Repository.revision` and `remote` are now populated. They were declared,
  serialised into every report and SARIF upload, and never set, so results
  recorded `null` for the two fields that say which code was examined.

### Release integrity

- Every release carries a CycloneDX and an SPDX SBOM, generated from packaging
  metadata rather than restated, and recording the digests of the exact files
  published. The dependency list is empty and that is the point: the claim is
  checkable rather than asserted.
- Artefacts and both SBOMs are signed with Sigstore keyless signing, so there
  is no signing key to protect, rotate or leak.
- SLSA build provenance is attested for each artefact, and PyPI receives PEP
  740 attestations, so an installer can ask not only whether the project signed
  something but whether it was built by the process the project describes.
- Builds set `SOURCE_DATE_EPOCH`, so a third party can rebuild from the tag and
  compare digests with the SBOM.

### Known limits

- The bundled advisory database is deliberately small and covers documented
  supply-chain incidents. It is not a substitute for a feed; load one with
  `--advisories`.
- Semantic (`ast`), structural and graph rule kinds are not implemented, and a
  pack declaring one is refused rather than silently ignored. There is no
  `[ast]` extra: it declared two packages nothing imported, which do not work
  together at their current releases, for a feature that does not exist.
- The source distribution ships `corpus/benign`, so the false-positive suite
  runs downstream, and not `corpus/malicious`. The detection suite therefore
  skips from an sdist and says so; clone the repository at the release tag to
  run it.
- The YAML accepted in configuration is a restricted subset: no anchors,
  aliases or tags.
