# Benchmark

Cordon side by side with GuardDog, OSV-Scanner and Trivy, run entirely inside Docker. Malware
samples are downloaded into a Docker volume, opened only inside a container with its network off,
and never touch the host.

```
docker build -f bench/Dockerfile -t cordon-bench:dev .      # needs bench/.dist/<cordon wheel>
docker volume create cordon-bench-data
docker run --rm -v cordon-bench-data:/data --entrypoint python cordon-bench:dev /bench/fetch.py all --count 100
docker run --rm --network none -v cordon-bench-data:/data:ro -v "$PWD/bench/results:/results" cordon-bench:dev malware benign
docker run --rm -v cordon-bench-data:/data:ro -v "$PWD/bench/results:/results" cordon-bench:dev cve
docker run --rm -v cordon-bench-data:/data:ro -v "$PWD/bench/results:/results" cordon-bench:dev cve --full-database
```

Tools: Trivy 0.74.0 and OSV-Scanner 2.6.0 (release binaries, checksum-verified), GuardDog 3.2.0,
Cordon from this checkout. Socket and Snyk need the runner's own API keys: set
`SOCKET_SECURITY_API_KEY` and `SNYK_TOKEN` and add the `commercial` suite (network on), and their
verdicts are merged into the malware, benign and CVE tables on the same inputs. Without a key the
summary says the tool was not run and why. No result below includes either tool yet.

## Results, 2026-10-01 (superseded)

The current, larger measurement is the 39,002-sample run in
`docs/08-ACCURACY.md`; read the numbers there. What follows is the first small run, kept for the
record. Small first run: 199 DataDog samples (the first 100 npm and 99 PyPI in the dataset), the top 100
PyPI and top 100 npm packages, 50 lockfiles from popular repositories. The bar in the plan is the
full run (thousands of samples, 1,000 + 1,000 packages, 100 lockfiles); these numbers are the
direction, not the claim.

| Measure | Cordon | GuardDog | Bar | |
|---|---|---|---|---|
| Malware blocked by the default gate | 78.4% (156/199) | 82.3% (163/198) | at or above GuardDog | **loss** |
| Top packages blocked by the default gate | 5.0% (10/200) | 18.5% (37/200) | at or below GuardDog | win |
| Vulnerability agreement with OSV-Scanner + Trivy, bundled database | 15.8% | -- | 98% | **loss** |
| The same, after `advisories sync` (full OSV set) | 87.3% | -- | 98% | **loss** |

### What the losses are

- **Malware, 43 samples passed.** Not yet triaged one by one; that is the next piece of work, by
  rule family, against the corpus and the noise corpus before any rule changes.
- **Vulnerabilities, bundled database.** The wheel ships malicious records plus high/critical
  vulnerabilities only, to bound its size, and those records carry no CVE aliases until the next
  data refresh (the importer now keeps them). Comparing a severity-filtered set against two tools
  that report every severity is mostly measuring the filter.
- **Vulnerabilities, full database.** Of the misses, 131 are CVE-2026 records: `advisories sync`
  serves a periodic snapshot, while OSV-Scanner asks OSV live. Closing that is the signed intel
  feed's job (deltas, minutes not days) once the cloud publishes it. The rest are Go module
  advisories (`GO-2026-*`) and a handful of older records still to explain.

### What the first run already fixed

Before this release the benign number was 24% of the top 100 PyPI packages. Eighteen of those
blocks were vulnerabilities pinned in lockfiles inside the published package (`uv.lock`,
`requirements-dev.txt`, `docs/requirements.txt`): the maintainers' development environment, which
installing the package never installs. They are now reported at LOW with that explanation. The
other blocks on PyPI packages, still open:

| Package | Rule | Cause |
|---|---|---|
| setuptools | `SUSPECT.INSTALL.SCRIPT.001` | overrides the `install` command in its own setup.py |
| pyyaml | `SUSPECT.DYNAMIC_DISPATCH.001` | `__import__` in the constructor that implements YAML python tags |
| numpy | `SUSPECT.DROPPER.001` | vendored meson's wrap downloader: fetch, decode and spawn in one file |
| typing-inspection | `SUSPECT.DROPPER.001` | `curl ... \| sh` in a docs build script |
| ghapi | `SUSPECT.DROPPER.001` | base64-decoding API content in a file that also spawns |
| python-dotenv, huggingface-hub | `SUSPECT.ANTI_ANALYSIS.001` | reading CI or OIDC environment variables in a file that also reaches the network |
| litellm | `SECRET.GENERIC.ASSIGNMENT.001` | a credential assembled from parts |
| urllib3 | `SECRET.PRIVATE_KEY.001` | test certificates under `dummyserver/certs/` |

The composite rules (`DROPPER`, `ANTI_ANALYSIS`, `DYNAMIC_DISPATCH`) combine capabilities found
anywhere in one file; narrowing them is measured against the malicious corpus and the 1,427-repository
noise corpus before it ships, not tuned to this list.

Raw per-sample verdicts are in `results/results.json`.
