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
[docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/main/docs/05-COVERAGE-MATRIX.md), and no driver for
them ships here.

| corpus | size | result |
|---|---|---|
| Widely used open-source repositories | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it | **13 repos, 20,310 files** | 2,560 findings, 795 blocking |
| Real malicious packages, by content | **1,000** | 81.3% detected (npm 83.0%, PyPI 79.6%) |
| Known-malicious releases, by advisory | **521 pins, 8 ecosystems** | 100% reported |
| Known-vulnerable releases, by advisory | **940 pins, 11 ecosystems** | 100% reported |

### Detection rate, by target

Two different questions, measured two different ways, because they need
different evidence and conflating them would flatter the result.

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  CONTENT          real malicious packages, unpacked and read            │
   │                   1,000 releases from DataDog's public dataset          │
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
scanned, deleted. Public sample sets exist for npm and PyPI only.

| Test | Samples | Cordon |
|---|---:|---:|
| Malicious npm packages (content) | 500 | **83.0%** |
| Malicious PyPI packages (content) | 500 | **79.6%** |

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

**What the content numbers are not.** 83.0% and 79.6% are one sample of one
dataset, chosen by recorded blob size so the run stayed bounded, which biases
toward purpose-built malware and away from compromised copies of large
libraries. The advisory rows above are exhaustive over what is pinned; these
two are not. The script that produced every number here is in the repository.

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
   RECALL    1,000 real malicious releases from DataDog's public dataset,
             extracted WITHOUT executing, scanned, deleted. Re-measured for this
             release against the version before it: 813 of 1,000 either way, so
             the rules narrowed in 0.4.0 cost no detection. The two that a first
             pass DID lose are in the changelog -- a payload padded off the right
             of the screen -- and are caught again.
   READ      every rule class firing across >10 repositories was read by hand —
             a rule wrong across 40 unrelated projects is wrong whatever one case looks like.
   SUITE     10,000+ tests every push · Linux/macOS/Windows · Py 3.11/3.12/3.13 ·
             fuzzing · latency budgets · reproducibility · Cordon scanning itself.
```

---
