# Accuracy

Every number here was produced by a script in this repository, against
code nobody here wrote. The method for each one is stated beside it,
because three different questions are being asked and conflating them
would flatter the answer.

## Accuracy, measured

Every number is measured against real code and re-run for the release. The
noise corpus and its driver ship here (`scripts/measure_noise.py`, over the
repository list in `scripts/data/measurement-corpus.json`), so anyone can
reproduce that row. The two malicious corpora are public datasets rather than
files in this repository: the methodology is in
[docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/05-COVERAGE-MATRIX.md), and no driver for
them ships here.

| corpus | size | result |
|---|---|---|
| Every known-malicious package record in the intel | **249,646 records**, 287,899 checks, 10 ecosystems | **100%** caught |
| Packages in real lockfiles, read against Trivy | **190,274 packages, 1,687 lockfiles**, 14 registries | **99.6%** agree (98.9% per lockfile); the rest sorted by cause |
| Dependencies in 12 ecosystems Trivy does not read, against each ecosystem's own tool | **9,061 dependencies, 337 repositories** | **99.9%** agree (F1); every difference read |
| Real malicious packages | **39,328** (every DataDog npm, PyPI, AI-skill and IDE-extension sample, and malregistry) | **94.2%** detected; **79.7%** by reading the code alone, the rest by matching a known malicious release |
| The same malware, against GuardDog | **498** (a fixed-seed draw) | **95.2%** vs GuardDog's 85.5% |
| Popular packages wrongly blocked | top **1,000 PyPI + 1,000 npm** | **1.6%** vs GuardDog's 16.8% |
| CVEs agreed with Trivy and OSV-Scanner | **100 lockfiles** | **98.4%**, every disagreement explained |
| AI-agent attacks, Agent Threat Rules test cases | **4,034 attacks, 289 evasions, 4,369 benign** | **97.7%** detected, 80.6% of evasions, 92.4% of benign left clean |
| AI-agent configs in real repositories, never tuned on | **372 repositories** | 10.5% warned, **1.1% blocked** (each block read and correct) |
| Widely used open-source repositories (0.4.0 run) | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it (0.4.0 run) | **13 repos, 20,310 files** | 2,560 findings, 795 blocking |
| Known-vulnerable releases, by advisory | **940 pins, 11 ecosystems** | 100% reported |

## At scale: every item, not a sample

A percentage is only as good as what it was measured on, so the runs below take whole
corpora, every record and every file, inside Docker with the network off for anything
that reads untrusted content. Each defect a run found was fixed, with a test, before the
number was written down.

### Every known-malicious record

`bench/malicious_records.py` plants each malicious-package record in the bundled intel as
a pinned dependency in its ecosystem's own lockfile shape, scans it, and checks the record
is reported. 249,646 records, 287,899 checks (a record naming several versions is checked
once per version), **none missed**.

| Ecosystem | Checks | Caught |
|---|---:|---:|
| npm | 260,391 | 100% |
| PyPI | 17,130 | 100% |
| NuGet | 5,215 | 100% |
| RubyGems | 5,047 | 100% |
| VS Code extensions | 69 | 100% |
| Cargo | 22 | 100% |
| Go | 20 | 100% |
| Maven | 3 | 100% |
| Composer | 1 | 100% |
| Git | 1 | 100% |

Records whose only listed version is npm's empty takedown placeholder (`0.0.1-security`)
are counted and set aside: there is nothing malicious left to install. The first full run
missed two records, a name and a version longer than the reader's bounds allowed; both
bounds were raised and the run repeated.

### What real lockfiles contain, against Trivy

`bench/fetch_lockfiles.py` takes the lockfiles of the most-downloaded projects on 14
registries (1,796 fetched; 1,687 that both tools read), and `bench/parse_agreement.py`
compares the packages Cordon and Trivy each read from them, offline.

```
   190,274 packages read by Cordon     191,192 by Trivy     189,969 the same
   ──────────────────────────────────────────────────────────────────────────
   per package   99.6% (F1)            per lockfile   98.9% mean, 1,503 exact
```

| Registry | Lockfiles | Mean agreement |
|---|---:|---:|
| crates.io | 123 | 100.0% |
| packagist.org | 12 | 100.0% |
| hackage.haskell.org | 2 | 100.0% |
| nuget.org | 40 | 99.99% |
| pub.dev | 231 | 99.98% |
| cran.r-project.org | 5 | 99.96% |
| cocoapods.org | 67 | 99.86% |
| rubygems.org | 152 | 99.73% |
| npmjs.org | 247 | 99.62% |
| swiftpackageindex.com | 112 | 99.41% |
| repo1.maven.org | 36 | 99.32% |
| pypi.org | 184 | 99.22% |
| hex.pm | 267 | 96.72% |
| proxy.golang.org | 186 | 96.42% |

Normalised before comparing: the development dependencies both tools can report, the
package managers' own entries (bundler, CocoaPods, Go's stdlib), and the project's own
packages. The figures are left raw beyond that, and `bench/parse_gaps.py` sorts every
remaining difference by cause, each checked against the lockfile itself:

| Cause | Packages |
|---|---:|
| A module go.sum records only by its go.mod hash: read while choosing versions, never built. Trivy lists it, Cordon does not | 322 |
| A mix.lock entry whose key is not its Hex package: Cordon names the package, Trivy the key | 96 |
| In the lockfile as that name and version, not read by Trivy | 94 |
| An npm alias: Cordon names the package installed, Trivy the alias | 76 |
| The project's own workspace package, listed by Trivy | 76 |
| A local `file:` or `link:` dependency, listed by Cordon as local | 20 |
| Not yet explained (125 Cordon-only, 88 Trivy-only) | 213 |
| **All differences** | **897** |

The Go and Hex rows are why those two registries sit lowest: both are Trivy listing what
the build does not use, or naming a package differently. The comparison found five real
Cordon defects on the way, each fixed with a test: pnpm 10's two-document lockfiles, npm
directories linked without a name, pre-1.17 and untidied go.mod files that leave indirect
modules to go.sum, and a lone go.sum.

### The ecosystems no other scanner reads, against each one's own tool

Trivy reads none of Terraform, Helm, Julia, opam, Bazel, Nix, Ansible, vcpkg, Conan, conda or
GitHub Actions workflows, and its CRAN coverage gave 5 lockfiles. So `bench/tool_agreement.py`
compares each with the reader that ecosystem treats as authoritative, on 30 real repositories
apiece: the most-downloaded packages' repositories where a registry lists them, GitHub topic search
where it does not (flakes, collections, C++ projects, renv projects). Every tool runs in its own
image (`bench/tool_reference/run.sh`), and nothing collected is executed.

```
   9,061 dependencies read by the tools     9,067 by Cordon     9,052 the same
   ─────────────────────────────────────────────────────────────────────────────
   precision 99.8%    recall 99.9%    337 repositories, 324 in full agreement
```

| Ecosystem | Reference | Repositories | Agree | F1 |
|---|---|---:|---:|---:|
| Terraform | `terraform-config-inspect` (HashiCorp) | 30 | 182 of 182 | 1.000 |
| Helm | `helm dependency list` | 29 | 176 of 176 | 1.000 |
| opam | `opam show --just-file` | 30 | 282 of 282 | 1.000 |
| vcpkg | `vcpkg format-manifest` | 30 | 1,893 of 1,893 | 1.000 |
| CRAN (renv.lock) | `renv::lockfile_read` | 30 | 4,196 of 4,196 | 1.000 |
| conda | conda's `from_file` | 30 | 546 of 546 | 1.000 |
| Bazel | `bazel mod graph --include_builtin` | 25 | 864 of 864 | 0.997 |
| Nix | `nix flake metadata` | 30 | 431 of 433 | 0.997 |
| Conan | Conan 2's conanfile.txt and lock readers | 26 | 225 of 225 | 0.993 |
| Julia | Pkg (`read_project`, `read_manifest`) | 30 | 129 of 131 | 0.989 |
| GitHub Actions | GitHub's dependency graph (SBOM API) | 17 | 66 of 66 | 0.978 |
| Ansible | `ansible-galaxy`'s requirements and galaxy.yml readers | 30 | 62 of 67 | 0.947 |

Homebrew is not in the table: Homebrew Bundle reads a Brewfile by evaluating it as Ruby, and
running a repository's code is the one thing this comparison does not do. For the same reason
Conan's row covers conanfile.txt and conan.lock, not conanfile.py. Actions covers the 17
repositories whose dependency graph GitHub publishes.

The comparison found nine Cordon defects, each fixed with a conformance case before the figures
above were taken:

| Defect | Found on |
|---|---|
| A Terraform `for` expression in braces, and a computed key `(local.x) = ...`, dropped the whole file | terraform-aws-modules/ecs, project-factory |
| A provider used without `required_providers` was not listed; Terraform installs `hashicorp/<name>` | cloudposse/null-label and others |
| A Julia standard library in Project.toml was read as a registry package | 26 of 30 Julia packages |
| A YAML scalar starting on the line below its key failed the file | ansible.netcommon's galaxy.yml |
| A task list named requirements.yml was read as roles | ansible.mysql |
| conda installs `pip` for a `pip:` subsection that does not list it | 2 environments |
| FlakeHub inputs were named "0.1" or "source"; forge archives by commit hash | Sly-Harvey/NixOS, Mic92/dotfiles |
| A Conan 1 recipe name with a capital (`Poco/1.9.0@pocoproject/stable`) refused the file | Maverobot/cpp_playground |
| renv before 1.0 wrote a bare `NA`, which renv reads and Cordon refused | edavidaja/you-should-use-renv |

What still differs, every case read:

| Difference | Count |
|---|---:|
| Bazel: `http_archive` repositories in MODULE.bazel; Bazel downloads them, `mod graph` lists modules only. Cordon lists them | 5 |
| Ansible: a task list ansible-galaxy would read as roles if asked; nothing asks it to. Cordon declines | 5 |
| Ansible: requirements files ansible-galaxy refuses or crashed on (ansible-test's extra keys; a scratch-directory error). Cordon reads them | 2 |
| Conan: Conan 1's `build_requires` section, which Conan 2's reader refuses. Cordon reads it | 3 |
| Actions: `uses:` lines GitHub's graph for a fork omits, and a repository using its own action. Cordon lists them | 3 |
| Julia: Julia 1.12 standard libraries Pkg 1.11 does not know as such; TOML downloaded from the registry in a pre-1.6 manifest | 2 |
| Nix: `file:///dev/null`, devenv's way of saying "no input". Cordon does not list it | 1 |
| Nix: not yet explained (one input each way) | 2 |

Results, repository by repository: `bench/results/tool-agreement-2026-10-10/`.

### What container images contain, against Syft

`bench/image_agreement.py` saves each of 182 public images (175 read by both tools; 7 could not
be pulled through the registry mirrors) and compares the packages Cordon and Syft 1.18.1 each
inventory, by normalised package URL.

```
   operating-system packages   21,719 of 21,758 the same         99.9%
   (deb, apk, rpm, pacman, portage)
   every package, per image    93.4% mean raw    95.1% adjusted   133 images at 98% or above
```

Adjusted leaves out three things Syft lists that are not packages: the RPM signing-key entry
(31), Go `(devel)` main modules built from a checkout (128), and .NET assembly file versions,
which Syft reports from each DLL and which are not NuGet packages (1,862). The rest of the gap,
by cause, is in `bench/results/full-2026-10-07/image-agreement.json`. One gap the run found is
fixed since: a jar past 256 MB (metabase's single 450 MB jar of every library it uses) was not
read for the Maven artifacts it records, and is now walked entry by entry; metabase went from
0.33 to 1.0 (444 of 444). The figures above are from before that fix and the ones after it.

After them, an image's inventory is what is installed in it, as Syft reads one: a lockfile or
manifest inside the image counts only where its package is installed, and a distribution's own
Python, Ruby or npm package is listed under the language's name as well as its own, as Syft lists
it. (0.6.0 skipped those as already counted; on ten images that ship them, listing them raised
agreement on every one -- odoo from 0.85 to 1.0 -- and added nothing Syft does not list, so 0.6.1
lists them.) Installed R packages,
PECL extensions, every `composer/installed.json`, every `package.json` that names itself, programs
copied in without a package database (bash, curl, OpenSSL, xz, zstd, util-linux, PHP), a Go
toolchain's own programs, and jars nested two levels down are read. Measured again, image by image:

| Image | Before | After |
|---|---:|---:|
| clearlinux | 0.00 | 1.00 |
| metabase | 0.33 | 1.00 |
| r-base | 0.70 | 1.00 |
| nextcloud | 0.14 | 0.996 |
| joomla | 0.97 | 0.997 |
| node:22 | 0.99 | 0.999 |
| jupyter/base-notebook | 0.93 | 0.998 |
| haskell | 0.44 | 0.99 |
| drupal | 0.32 | 0.99 |

Known gaps remaining:

| Gap | Where it shows |
|---|---|
| Maven groups for jars with no metadata are inferred differently where neither tool knows them | groovy, gradle: the same jars under different groups |

### Detection rate, by target

Two different questions, measured two different ways, because they need
different evidence and conflating them would flatter the result.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  CONTENT          real malicious packages, unpacked and read            │
   │                   39,328 releases: DataDog's dataset and malregistry    │
   │                   ──► what the file actually does                       │
   │                                                                         │
   │  ADVISORY         a manifest pinning a release an advisory names        │
   │                   ──► what the graph actually resolves                  │
   │                                                                         │
   │  TECHNIQUE        the labelled corpus in corpus/malicious/              │
   │                   ──► whether each attack shape is covered at all       │
   └─────────────────────────────────────────────────────────────────────────┘
```

**Content analysis.** Real malicious releases, extracted without executing,
scanned, deleted -- every sample in both datasets, in batches of 5,000, with
`bench/run.py`. Public sample sets exist for npm and PyPI only.

| Test | Samples | Detected | By the code alone |
|---|---:|---:|---:|
| Malicious npm packages, DataDog | 25,766 | **93.7%** | 75.8% |
| Malicious PyPI packages, DataDog | 2,502 | **93.4%** | 86.3% |
| Malicious AI-agent skills and IDE extensions, DataDog | 326 | **35.6%** | 35.6% |
| Malicious packages, malregistry | 10,734 | **97.4%** | 88.9% |
| **All** | **39,328** | **94.2%** | **79.7%** |

"By the code alone" counts a sample only when something other than the known-release lookup
blocked it. Releases 0.5.x published the first column under that name ("94.1% by content
alone"): the figure was the overall rate, mislabelled. Measured again on one fixed-seed draw of
1,500 samples, 0.5.2 and 0.6.0 detect the same share by the code alone (79.65%), so nothing
regressed; the label was wrong. Of the 204 malicious AI-agent skills, 179 are flagged and 22
blocked: the agent rules warn on their own, and blocking more is a trade against the false-alarm
rate on real repositories, measured before it is made.

GuardDog, run over one fixed-seed draw of 498 of the same samples, detected 85.5% to Cordon's
95.2% on exactly those (the 0.5 release measured 83.9% to 95.4% on a different draw of 995).

**Advisory matching.** A manifest in each ecosystem's own shape, pinning
releases the bundled database names. This is the path that reaches every
ecosystem, and the one a lockfile scan depends on.

| Test | Pinned | Cordon |
|---|---:|---:|
| Malicious npm packages | 120 | **100%** |
| Malicious PyPI packages | 120 | **100%** |
| Malicious NuGet packages | 120 | **100%** |
| Malicious RubyGems packages | 120 | **100%** |
| Malicious Cargo packages | 20 | **100%** |
| Malicious Go packages | 18 | **100%** |
| Malicious Maven/Gradle packages | 2 | **100%** |
| Malicious Composer packages | 1 | **100%** |
| Known vulnerable dependencies | 940 across 11 ecosystems | **100%** |

Pub, Hex and Swift carry no malicious records in the bundled set, so there is
nothing to measure; their known-vulnerable rows are included in the 940.

**Attack technique.** The labelled corpus, where each sample is a named
technique and `expected.yaml` states what has to be found.

| Test | Samples | Cordon |
|---|---:|---:|
| Install-hook attacks | 5 | **100%** |
| Credential exfiltration | 9 | **100%** |
| Obfuscated payloads | 7 | **100%** |
| Download-and-execute payloads | 11 | **100%** |
| Persistence mechanisms | 1 | **100%** |
| Supply-chain integrity | 4 | **100%** |
| CI/CD pipeline attacks | 2 | **100%** |
| Infrastructure misconfiguration | 4 | **100%** |
| Dependency confusion | 3 | **100%** |
| Typosquatting | 20 | **95%** |

The typosquat miss is deliberate: a single character appended to a short name
is how ecosystems name companion packages (`vuex`, `reacts`), so that shape is
excused by name. `POLICY.DEPENDENCY.SOURCE` reports the same package by a
different route.

**What the content numbers are not.**

```
   content only ── no advisory lookup, no network

   what it misses ──┬─ ~2 in 5   almost-empty packages: a bare package.json,
                    │            a placeholder, a researcher's proof of concept
                    ├─ ~1 in 5   a prebuilt binary and nothing else
                    └─ the rest  the long tail, fixed shape by shape
                    the first two are caught BY NAME ─▶ the advisory rows above

   measured on the release's code before its last detection changes,
   all of which add detections
```

**AI agents.**

```
   ATR test cases, each on its rule's scan path        bench/atr_bench.py
     attacks ............ 3,933 / 4,026   97.7%
     evasions ...........   209 /   289   72.3%   regex ceiling: what --judge is for
     benign left clean .. 4,038 / 4,364   92.5%   ATR's near-misses: a floor

   real repositories never used for tuning          bench/agent_realworld.py
     372 repositories ── 10.5% warned ── 1.1% blocked, every block read and correct

   the judge, per model                             bench/judge_bench.py
```

```
   NOISE     1,427 maintained projects (incl. security tools — a security tool's
             own signature file is the canonical false positive). 1,218 pass the
             default gate. Both MALWARE.* findings across the corpus are correct.
   IAC       the infrastructure the vendors themselves publish as correct — the
             Terraform modules AWS, Azure and Google ship, AWS's CloudFormation
             library, Kubernetes' own examples, Microsoft's Bicep registry and
             quickstart templates. All 79 blocking rule classes were read against
             the files they fired on, not sampled; nine findings in four classes
             were wrong and each rule was fixed. 2,722 findings became 2,560 and
             837 blocking became 795. What blocks now is 345 Azure rules opening
             SSH or RDP to the whole internet (Azure's demo templates really do
             that) and 320 CVEs in those repositories' own dependencies.
   RECALL    39,328 real malicious releases, DataDog's dataset and malregistry,
             extracted WITHOUT executing, scanned, deleted, in batches inside a
             container with no network. 94.2% detected, 79.7% by the code alone.
   READ      every rule class firing across >10 repositories was read by hand —
             a rule wrong across 40 unrelated projects is wrong whatever one case looks like.
   SUITE     18,000+ tests every push · Linux/macOS/Windows · Py 3.11/3.12/3.13 ·
             fuzzing · latency budgets · reproducibility · Cordon scanning itself.
```

---
