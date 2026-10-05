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
[docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/v0.5.1/docs/05-COVERAGE-MATRIX.md), and no driver for
them ships here.

| corpus | size | result |
|---|---|---|
| Real malicious packages, by content alone | **39,002** (every DataDog npm and PyPI sample, and malregistry) | **94.1%** detected (npm 93.3%, PyPI 92.3%, malregistry 96.4%) |
| The same malware, against GuardDog | **995** | **95.4%** vs GuardDog's 83.9% |
| Popular packages wrongly blocked | top **1,000 PyPI + 1,000 npm** | **1.6%** vs GuardDog's 16.8% |
| CVEs agreed with Trivy and OSV-Scanner | **100 lockfiles** | **98.4%**, every disagreement explained |
| AI-agent attacks, Agent Threat Rules test cases | **4,026 attacks, 4,364 benign** | **97.7%** detected, 92.5% of benign left clean |
| AI-agent configs in real repositories, never tuned on | **372 repositories** | 10.5% warned, **1.1% blocked** (each block read and correct) |
| Widely used open-source repositories (0.4.0 run) | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it (0.4.0 run) | **13 repos, 20,310 files** | 2,560 findings, 795 blocking |
| Known-malicious releases, by advisory | **521 pins, 8 ecosystems** | 100% reported |
| Known-vulnerable releases, by advisory | **940 pins, 11 ecosystems** | 100% reported |

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
