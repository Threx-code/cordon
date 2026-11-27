# Registry response captures (fetched 2026-11-27)

Real responses from each registry's public API, fetched with plain `curl` and a generic User-Agent, no token. Each
is trimmed by whole entries (the first few packages of the page), re-serialised as JSON where the response was JSON,
and used by `test_package_list_sources.py`. They are registry metadata, not package contents.

| File | Request |
|---|---|
| `hex.json` | `https://hex.pm/api/packages?sort=downloads&page=1` |
| `hackage.json` | `https://hackage.haskell.org/packages/top` (Accept: application/json) |
| `artifacthub.json` | `https://artifacthub.io/api/v1/packages/search?kind=0&sort=stars&limit=60&offset=0` |
| `terraform.json` | `https://registry.terraform.io/v2/providers?page%5Bsize%5D=5&sort=-downloads` |
| `galaxy.json` | `https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/?limit=3&offset=0` |
| `hub_library.json` | `https://hub.docker.com/v2/repositories/library/?page_size=3&ordering=-pull_count` |
| `hub_search.json` | `https://hub.docker.com/v2/search/repositories/?query=nginx&page_size=3` |
| `github_actions.json` | `https://api.github.com/search/repositories?q=topic:github-action&sort=stars&order=desc&per_page=3&page=1` |
| `conda_channeldata.json` | `https://conda.anaconda.org/conda-forge/channeldata.json` (first four packages) |
| `swift_packages.json` | `https://raw.githubusercontent.com/SwiftPackageIndex/PackageList/main/packages.json` (Apache-2.0; first six) |
| `cocoapods_shard.txt` | `https://cdn.cocoapods.org/all_pods_versions_d_a_2.txt` (first six lines) |
| `julia_registry.toml` | `https://raw.githubusercontent.com/JuliaRegistries/General/master/Registry.toml` (three packages) |
| `julia_requests.csv.gz` | `https://julialang-logs.s3.amazonaws.com/public_outputs/current/package_requests.csv.gz` (the rows of those three) |
| `maven.json` | `https://search.maven.org/solrsearch/select?q=*:*&rows=1&start=0&wt=json` |
