# Ecosystems

Every package ecosystem Cordon reads, the files it reads for each, and which
checks that ecosystem gets. Generated from the shipped code -- the manifest and
lockfile patterns are the ones the walker actually matches, and the capability
columns are read from the data and detectors that actually ship.

Regenerate after adding an ecosystem or a feed:

```bash
python tests/ecosystems.py > docs/07-ECOSYSTEMS.md
```

## How to read the columns

```
  MANIFESTS      what a project declares: ranges, no resolved versions
  LOCKFILES      what a project resolved: exact versions, usually hashes
  ADVISORIES     known-malicious and known-vulnerable matching, offline
  TYPOSQUAT      name-similarity checks against that ecosystem's popular set
  REGISTRY       --online only: withdrawal, version distance, hash agreement
  PROVENANCE     --online only: attestation presence, and verification with [attest]
```

A dependency whose ecosystem has no advisory feed still gets everything else --
the graph, typosquat and confusion checks, lockfile integrity, licences, install
hooks. What it cannot get is a vulnerability match, and a scan that includes one
says so through `OPERATIONAL.ADVISORY.NO_FEED.001` rather than reporting a clean
result that was never checked.

| Ecosystem | Manifests | Lockfiles | Advisories | Typosquat | Registry | Provenance | Allowlist |
|---|---|---|---|---|---|---|---|
| `bazel` | `MODULE.bazel` | `MODULE.bazel.lock` | -- | yes | -- | -- | 53 |
| `cargo` | `Cargo.toml` | `Cargo.lock` | yes | yes | -- | -- | 19,999 |
| `cocoapods` | `Podfile`, `*.podspec` | `Podfile.lock` | -- | yes | -- | -- | 200 |
| `composer` | `composer.json` | `composer.lock` | yes | yes | -- | -- | 904 |
| `conan` | `conanfile.txt`, `conanfile.py` | `conan.lock` | -- | yes | -- | -- | 92 |
| `conda` | `environment.yml`, `environment.yaml` | `conda-lock.yml`, `conda-lock.yaml` | -- | yes | -- | -- | 120 |
| `cran` | `DESCRIPTION` | `renv.lock` | -- | yes | -- | -- | 119 |
| `gomod` | `go.mod` | `go.sum` | yes | yes | -- | -- | 89 |
| `gradle` | `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` | `gradle.lockfile`, `gradle/verification-metadata.xml` | yes | yes | -- | -- | 110 |
| `hex` | `mix.exs` | `mix.lock` | yes | yes | -- | -- | 92 |
| `maven` | `pom.xml` | -- | yes | yes | -- | -- | 110 |
| `npm` | `package.json` | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` | yes | yes | yes | yes | 17,356 |
| `nuget` | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config` | `packages.lock.json`, `project.assets.json` | yes | yes | -- | -- | 4,026 |
| `pub` | `pubspec.yaml` | `pubspec.lock` | yes | yes | -- | -- | 7,353 |
| `pypi` | `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements*.txt`, `requirements/*.txt`, `requirements*.in`, `Pipfile` | `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `requirements*.txt` | yes | yes | yes | yes | 12,487 |
| `rubygems` | `Gemfile`, `*.gemspec` | `Gemfile.lock` | yes | yes | -- | -- | 2,855 |
| `swift` | `Package.swift` | `Package.resolved` | yes | yes | -- | -- | 62 |

## What is not here

- **Operating-system packages** (`dpkg`, `rpm`, `apk`) and container image
  layers. Cordon reads a source tree; image scanning is a different product.
- **An ecosystem's own resolver.** Nothing here runs `npm install`, `pip
  download` or `conan install` to find out what a range resolves to -- see
  constraint C2 in `docs/01-ARCHITECTURE.md`. A range stays a range, and the
  checks that need an exact version skip it rather than guess.
