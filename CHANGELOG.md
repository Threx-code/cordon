# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - unreleased

Two defaults that were wrong, both found by adopting the tool on real
repositories rather than by running its suite.

### Changed

- `baseline create` and `baseline compare` cover tracked files only when the
  target is inside a git repository. `--all-files` restores the previous
  behaviour.

  A baseline is a committed artefact, and walking the working tree wrote
  findings about paths git ignores into it. The first baseline taken on a real
  repository named a local `.env`. The entries cannot be reproduced, because no
  other clone has the file, so `compare` reports them as "no longer occurs" on
  every machine but the one that wrote them; the file misrepresents the
  repository to anybody reading it to find out what is being carried; and a
  secret scanner reading untracked `.env` files by default is the wrong default
  whatever it does with what it finds. Nothing leaked -- an entry holds a
  fingerprint, a rule id and a path, and evidence is hash-only throughout -- but
  the shape of the mistake is the one this tool objects to elsewhere.

  A target that is not a repository is not an error, unlike `scan --tracked`.
  That flag is a promise about which bytes were read and has to fail rather than
  quietly widen; this is a default about which files are worth recording, and
  refusing to baseline an unversioned directory would refuse the thing that was
  asked. The scope is printed either way, because a scope a reader has to infer
  is a scope they will get wrong.

  Regenerate any existing baseline to drop the entries it should never have had.
  Nothing breaks if you do not: a baseline with extra entries suppresses
  findings that no longer occur, which `compare` already reports.

- The cache's identity for a detector is now `id@version@code`, where `code` is
  a hash of the module the detector is defined in.

  `version` alone was the whole identity, which made cache correctness depend on
  a person remembering to edit a string in the same commit as a behaviour
  change. 0.1.1 came one line from proving how that fails: its entire content
  was a false-positive fix in `detect/secrets.py`, and the file content, rule
  pack and configuration were all unchanged, so every affected entry would have
  been served from the cache and the release would have done nothing for anybody
  who had ever run a scan.

  The declared version is still worth having -- it is what a report, a release
  note and a pack's `requires` clause can name, and a code hash is not something
  anyone can reason about. It is no longer what correctness rests on.

  Line endings are normalised before hashing, so one release does not produce
  two signatures depending on whether the checkout used LF or CRLF. A build with
  no readable source contributes `nosource` and falls back to the declared
  version rather than refusing to scan.

  The cost is deliberate and is the right way round: editing a docstring in a
  detector module invalidates that detector's entries, and a needless re-scan
  costs seconds, where reusing a result the current code would not have produced
  is a wrong answer -- and in this tool a wrong answer is usually a missed
  payload. Expect one cold scan after upgrading.

## [0.1.1] - 2026-09-11

A false-positive fix. No new detection, no configuration change, and no
migration.

### Fixed

- `SECRET.GENERIC.ASSIGNMENT.001` no longer reads the line below a definition
  as the value assigned to it. The operator in the assignment pattern allowed
  `\s*` on both sides, and `\s` matches a newline, so `class AuthTokenService:`
  followed by `@staticmethod` was reported as "a credential assigned to
  'AuthTokenService'". Any Python class, or YAML key, whose name contains one of
  the credential words and whose next line opened with twelve or more
  characters of unbroken text produced a high-severity finding; one Django
  codebase of ordinary service classes produced nine.

  This was the worst kind of noise this rule can make. A finding a reviewer
  cannot act on is a finding that teaches them to stop reading the rule, and
  the real `SECRET_KEY = "..."` three files away goes with it.

  The operator now allows horizontal whitespace only, on both sides, which also
  closes the `\r` form of the same mistake on a CRLF checkout. An assignment
  puts its value on the same line as its name; a value on a later line is a
  class body, a mapping or the next statement. The multi-line case that is real,
  a literal built across several lines, was never matched here and continues to
  be matched by the assembled-literal path, which looks for a joiner.

### Also fixed

- The pre-commit `rev` in the README and the version pins in the GitLab and
  Azure templates named `0.1.0` and would have kept naming it. Every pipeline
  set up from a template, and every repository using the pre-commit hook, would
  have gone on installing the version this release exists to replace with no
  signal that a fix had been published. A test now asserts each of those pins
  against `__version__`, the way the changelog entry was already asserted.

### Known, not fixed here

- `cordon-scanner baseline create` has no `--tracked`, so it walks the working
  tree and records findings in files git is ignoring. A repository with a local
  `.env` gets that file's path written into a baseline that is then committed.
  Nothing leaks -- evidence is hash-only -- but a baseline naming paths that do
  not exist in any clone is wrong, and a secret scanner reading untracked `.env`
  files by default is the wrong default. Use `--tracked` on `scan` and prune the
  baseline by hand until this is fixed.
- A detector's cache identity is a `version` string a person has to remember to
  change, which is how this fix came within one line of reaching nobody. It
  should be derived from a hash of the detector's own source.
- `ci/generic/scan.sh` defaults to a container image at
  `ghcr.io/threx-code/cordon`, and no workflow in this repository builds or
  publishes one. The template cannot work as written for anybody who does not
  set `CORDON_IMAGE`.

### Cache

- The `secrets` detector is at `0.2.1`. `ScanCache` composes its key from the
  file content, the rulepack hash, the configuration hash and a signature over
  every detector's `id@version`, and a fix like this one changes none of the
  first three. Without the bump, anyone who had already scanned a tree would
  upgrade and keep being served the findings this release removes, out of a
  cache with no reason to believe anything had changed. No action is needed and
  `--no-cache` is not necessary: installing this version invalidates the
  affected entries on its own.

- `RULEPACK_VERSION` is unchanged at `0.1.0`. The pattern lives in detector
  code, not in a bundled pack, so nothing a security review signed off on has
  moved.

## [0.1.0] - 2026-09-09

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
