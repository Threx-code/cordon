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
| Real malicious packages, by content alone | **39,002** (every DataDog npm and PyPI sample, and malregistry) | **94.1%** detected (npm 93.3%, PyPI 92.3%, malregistry 96.4%) |
| The same malware, against GuardDog | **995** | **95.4%** vs GuardDog's 83.9% |
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
by cause, is in `bench/results/full-2026-10-07/image-agreement.json`; the largest are known
Cordon gaps, listed rather than hidden:

| Gap | Where it shows |
|---|---|
| Maven metadata nested inside a single bundled ("uber") jar is not read | metabase: 357 libraries Syft names, 1 Cordon does |
| Clear Linux bundles are not read | clearlinux: 6 packages, none from Cordon |
| A shipped application's Composer and npm lockfiles are read, development packages included | nextcloud, drupal, haskell: Cordon names more than Syft |

### Detection rate, by target

Two different questions, measured two different ways, because they need
different evidence and conflating them would flatter the result.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  CONTENT          real malicious packages, unpacked and read            │
   │                   39,002 releases: DataDog's dataset and malregistry    │
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

| Test | Samples | Cordon |
|---|---:|---:|
| Malicious npm packages, DataDog (content) | 25,766 | **93.3%** |
| Malicious PyPI packages, DataDog (content) | 2,502 | **92.3%** |
| Malicious packages, malregistry (content) | 10,734 | **96.4%** |
| **All** | **39,002** | **94.1%** |

GuardDog, run over the same 995-sample draw, detected 83.9% to Cordon's 95.4%.

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
   RECALL    39,002 real malicious releases, DataDog's dataset and malregistry,
             extracted WITHOUT executing, scanned, deleted, in batches inside a
             container with no network. 94.1% by content alone.
   READ      every rule class firing across >10 repositories was read by hand —
             a rule wrong across 40 unrelated projects is wrong whatever one case looks like.
   SUITE     18,000+ tests every push · Linux/macOS/Windows · Py 3.11/3.12/3.13 ·
             fuzzing · latency budgets · reproducibility · Cordon scanning itself.
```

---
