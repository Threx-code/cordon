# Benchmark and measurement

The tools that measure Cordon. The numbers they produce, with the method beside each one, are in
[`docs/08-ACCURACY.md`](../docs/08-ACCURACY.md); this folder holds how they are made, not the results.

## What is here

| Path | What it does |
|---|---|
| `run.py`, `Dockerfile` | The side-by-side suites (`malware`, `benign`, `cve`, `agents`, and `commercial` when the runner has the vendors' own keys), run inside the bench image. A tool that is not installed or fails on an input is recorded as such for that input, never counted as clean. |
| `suites/` | Focused measurement drivers: agent configurations and MCP tool poisoning, extensions, the long tail of registries, identity, budgets, the judge. |
| `tools/` | Fetchers (malicious and benign packages, lockfiles, skills, agent configurations, extensions), the content rule that separates content findings from intel, comparisons with other tools, and miss and gap analysis. |
| `model/` | Datasets, feature extraction and training for the verdict and area models, with cross-validation for MCP servers and skills. |
| `cdi/` | The learning pipeline: feature sets from scan rows, candidate rules, discovery, the paired gate that admits a candidate, and the loop around them. |
| `tool_reference/`, `lockfiles.json`, `agent-suite.json` | Pinned inputs the suites read. |

## How samples are handled

Malware samples are real and dangerous, and none of them ever touches the host:

- **Fetching and scanning are separate containers.** A fetcher has network and writes only into a
  Docker volume; it never scans. A scan has no network.
- **A scan container** runs with `--network none`, a read-only root, all capabilities dropped and no
  new privileges, with the samples volume mounted read-only and its output written only to another
  Docker volume.
- **No host folder is ever mounted writable** into a container that mounts a samples volume.
- **Results are read back as counts**, inside a container. Per-sample rows name samples and stay in
  the results volume.

```
docker build -f bench/Dockerfile -t cordon-bench:dev .        # needs bench/.dist/<cordon wheel>
docker volume create cordon-bench-data
docker volume create cordon-bench-results

# fetch: network on, writes only to the data volume, scans nothing
docker run --rm -v cordon-bench-data:/data --entrypoint python cordon-bench:dev /bench/tools/fetch.py all --count 100

# measure: no network, read-only root and samples, output to the results volume
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -v cordon-bench-data:/data:ro -v cordon-bench-results:/results cordon-bench:dev malware benign
```

The `cve` suite compares vulnerability findings with OSV-Scanner and Trivy (release binaries,
checksum-verified). The `commercial` suite needs the runner's own `SOCKET_SECURITY_API_KEY` and `SNYK_TOKEN`;
without a key the summary says the tool was not run and why.
