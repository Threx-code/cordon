# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - unreleased

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

Across four real repositories: **72 findings to 63, and 26 high-or-critical to
13.** Two of the four now report no high-severity findings at all, and every one of
the thirteen that remain is a real hardcoded credential or a real secret leaving a
runner. Nothing was added anywhere. Suite: 2,260 passing.

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
