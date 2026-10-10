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
| `actions` | `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `action.yml`, `action.yaml` | -- | yes | yes | yes | -- | 178 |
| `ansible` | `requirements.yml`, `requirements.yaml`, `roles/requirements.yml`, `collections/requirements.yml`, `galaxy.yml`, `meta/main.yml`, `meta/runtime.yml`, `execution-environment.yml`, `execution-environment.yaml` | `ansible_collections/*/*/MANIFEST.json`, `meta/.galaxy_install_info` | -- | yes | yes | -- | 43 |
| `bazel` | `MODULE.bazel`, `WORKSPACE`, `WORKSPACE.bazel`, `WORKSPACE.bzlmod`, `BUILD.bazel` | `MODULE.bazel.lock` | -- | yes | yes | yes | 54 |
| `cargo` | `Cargo.toml`, `.cargo/config.toml`, `.cargo/config` | `Cargo.lock` | yes | yes | yes | -- | 19,999 |
| `cocoapods` | `Podfile`, `*.podspec` | `Podfile.lock` | -- | yes | yes | -- | 200 |
| `composer` | `composer.json`, `composer.lock`, `auth.json` | `composer.lock` | yes | yes | yes | -- | 904 |
| `conan` | `conanfile.txt`, `conanfile.py`, `profiles/default`, `conan/profiles/*`, `remotes.json`, `conanws.yml`, `conanws.yaml` | `conan.lock` | -- | yes | yes | -- | 93 |
| `conda` | `environment.yml`, `environment.yaml`, `meta.yaml`, `.condarc` | `conda-lock.yml`, `conda-lock.yaml`, `explicit*.txt`, `conda-*.lock` | -- | yes | yes | -- | 120 |
| `cran` | `DESCRIPTION`, `renv/settings.json`, `PACKAGES` | `renv.lock` | yes | yes | yes | -- | 119 |
| `gomod` | `go.mod`, `go.work` | `go.mod`, `go.sum`, `go.work.sum`, `vendor/modules.txt` | yes | yes | yes | -- | 89 |
| `gradle` | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle/libs.versions.toml`, `gradle/wrapper/gradle-wrapper.properties` | `gradle.lockfile`, `buildscript-gradle.lockfile`, `settings-gradle.lockfile`, `gradle/dependency-locks/*.lockfile`, `gradle/verification-metadata.xml` | yes | yes | yes | yes | 110 |
| `hackage` | `*.cabal`, `cabal.project`, `stack.yaml`, `package.yaml` | `cabal.project.freeze`, `stack.yaml.lock` | yes | yes | yes | -- | 48 |
| `helm` | `Chart.yaml`, `Chart.lock`, `requirements.lock` | `Chart.lock`, `requirements.lock`, `charts/*.tgz` | -- | yes | yes | -- | 57 |
| `hex` | `mix.exs`, `rebar.config` | `mix.lock`, `rebar.lock` | yes | yes | yes | -- | 92 |
| `homebrew` | `Brewfile`, `.Brewfile`, `Brewfile.txt`, `Brewfile.local`, `Brewfile.symlink`, `*.Brewfile`, `Formula/*.rb`, `Casks/*.rb`, `Formula/*/*.rb`, `Casks/*/*.rb` | `Brewfile.lock.json`, `Cellar/*/*/INSTALL_RECEIPT.json` | -- | yes | yes | yes | 57 |
| `image` | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `*.dockerfile`, `Containerfile`, `Containerfile.*`, `compose.yaml`, `compose.yml`, `compose.*.yaml`, `compose.*.yml`, `docker-compose.yml`, `docker-compose.yaml`, `docker-compose.*.yml`, `docker-compose.*.yaml`, `k8s/**/*.yaml`, `k8s/**/*.yml`, `kubernetes/**/*.yaml`, `kubernetes/**/*.yml`, `kube/**/*.yaml`, `kube/**/*.yml`, `manifests/**/*.yaml`, `manifests/**/*.yml`, `deploy/**/*.yaml`, `deploy/**/*.yml`, `deployment/**/*.yaml`, `deployment/**/*.yml`, `deployments/**/*.yaml`, `deployments/**/*.yml`, `kustomize/**/*.yaml`, `kustomize/**/*.yml`, `overlays/**/*.yaml`, `overlays/**/*.yml`, `kustomization.yaml`, `kustomization.yml`, `deployment.yaml`, `deployment.yml`, `statefulset.yaml`, `statefulset.yml`, `daemonset.yaml`, `daemonset.yml`, `cronjob.yaml`, `cronjob.yml`, `job.yaml`, `job.yml`, `pod.yaml`, `pod.yml`, `*-deployment.yaml`, `*-deployment.yml`, `*-statefulset.yaml`, `*-statefulset.yml`, `*-daemonset.yaml`, `*-daemonset.yml`, `*-cronjob.yaml`, `*-cronjob.yml`, `*-job.yaml`, `*-job.yml`, `*-pod.yaml`, `*-pod.yml` | -- | -- | -- | yes | yes | 70 |
| `julia` | `Project.toml`, `JuliaProject.toml` | `Manifest.toml`, `JuliaManifest.toml`, `Manifest-v*.toml`, `Artifacts.toml` | yes | yes | yes | -- | 40 |
| `maven` | `pom.xml`, `.mvn/wrapper/maven-wrapper.properties` | `dependency-tree.txt`, `.mvn/checksums/*.sha1`, `.mvn/checksums/*.sha256`, `.mvn/checksums/*.sha512` | yes | yes | yes | yes | 110 |
| `nix` | `flake.nix`, `default.nix`, `shell.nix` | `flake.lock` | -- | yes | -- | -- | 23 |
| `npm` | `package.json`, `deno.json`, `deno.jsonc` | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `deno.lock` | yes | yes | yes | yes | 17,356 |
| `nuget` | `*.csproj`, `*.fsproj`, `*.vbproj`, `packages.config`, `Directory.Packages.props`, `Directory.Build.props`, `NuGet.Config`, `nuget.config`, `NuGet.config`, `obj/project.assets.json` | `packages.lock.json`, `project.assets.json` | yes | yes | yes | -- | 4,026 |
| `opam` | `*.opam`, `opam`, `dune-project`, `dune-workspace`, `dune.lock/lock.dune` | `*.opam.locked`, `dune.lock/*.pkg` | yes | yes | yes | -- | 34 |
| `pub` | `pubspec.yaml` | `pubspec.lock`, `.dart_tool/package_config.json` | yes | yes | yes | -- | 7,359 |
| `pypi` | `pyproject.toml`, `setup.py`, `setup.cfg`, `requirements*.txt`, `requirements/*.txt`, `requirements*.in`, `requirements/*.in`, `Pipfile` | `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `requirements*.txt`, `requirements/*.txt` | yes | yes | yes | yes | 12,487 |
| `rubygems` | `Gemfile`, `gems.rb`, `*.gemspec`, `.ruby-version` | `Gemfile.lock`, `gems.locked` | yes | yes | yes | yes | 2,847 |
| `swift` | `Package.swift` | `Package.resolved` | yes | yes | -- | -- | 62 |
| `terraform` | `*.tf`, `*.tf.json` | `.terraform.lock.hcl` | -- | yes | yes | -- | 58 |
| `vcpkg` | `vcpkg.json`, `vcpkg-configuration.json`, `vcpkg-lock.json` | `vcpkg-lock.json` | -- | yes | yes | -- | 39 |

## What is not here

- **Operating-system packages as an ecosystem of a project.** They are read
  where they are installed: `scan image.tar` reads the dpkg, apk, RPM, pacman and
  portage databases inside a saved image, and `scan --host /` reads them on a
  machine (tutorial 23), each matched against distribution advisories.
- **An ecosystem's own resolver.** Nothing here runs `npm install`, `pip
  download` or `conan install` to find out what a range resolves to -- see
  constraint C2 in `docs/01-ARCHITECTURE.md`. A range stays a range, and the
  checks that need an exact version skip it rather than guess.
