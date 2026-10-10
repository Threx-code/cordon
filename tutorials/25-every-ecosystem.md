# 25 · Every ecosystem

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Every package ecosystem Cordon reads, 28 of them, and how to scan each one. The files,
the checks and the commands below are rendered from the shipped code, so this page names
exactly what a scan reads. The same facts as one table:
[docs/07-ECOSYSTEMS.md](../docs/07-ECOSYSTEMS.md).

```
   One command reads all of them at once. A repository with a package.json, a
   go.mod, a Dockerfile and a workflow is four ecosystems in one scan:

   cordon-scanner scan .

   Offline by default. --online adds the registry and provenance checks, and
   names each package to its own registry; nothing else leaves the machine.
```

## Ansible Galaxy

Roles and collections a playbook installs. Ecosystem id `ansible`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       requirements.yml, requirements.yaml,                       │
│                 roles/requirements.yml, collections/requirements.yml,      │
│                 galaxy.yml, meta/main.yml, meta/runtime.yml, execution-    │
│                 environment.yml, execution-environment.yaml                │
│ LOCKFILES       ansible_collections/*/*/MANIFEST.json,                     │
│                 meta/.galaxy_install_info                                  │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Bazel

Modules from the Bazel Central Registry. Ecosystem id `bazel`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       MODULE.bazel, WORKSPACE, WORKSPACE.bazel,                  │
│                 WORKSPACE.bzlmod, BUILD.bazel                              │
│ LOCKFILES       MODULE.bazel.lock                                          │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Cargo

Rust crates from crates.io. Ecosystem id `cargo`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Cargo.toml, .cargo/config.toml, .cargo/config              │
│ LOCKFILES       Cargo.lock                                                 │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:cargo/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## CocoaPods

IOS and macOS pods. Ecosystem id `cocoapods`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Podfile, *.podspec                                         │
│ LOCKFILES       Podfile.lock                                               │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Composer

PHP packages from Packagist. Ecosystem id `composer`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       composer.json, composer.lock, auth.json                    │
│ LOCKFILES       composer.lock                                              │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Conan

C and C++ packages. Ecosystem id `conan`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       conanfile.txt, conanfile.py, profiles/default,             │
│                 conan/profiles/*, remotes.json, conanws.yml, conanws.yaml  │
│ LOCKFILES       conan.lock                                                 │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Conda

Conda-forge and Anaconda packages. Ecosystem id `conda`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       environment.yml, environment.yaml, meta.yaml, .condarc     │
│ LOCKFILES       conda-lock.yml, conda-lock.yaml, explicit*.txt,            │
│                 conda-*.lock                                               │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Container images

The images a Dockerfile, compose file or workload runs. Ecosystem id `image`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Dockerfile, Dockerfile.*, *.Dockerfile, *.dockerfile,      │
│                 Containerfile, Containerfile.*, compose.yaml, compose.yml, │
│                 compose.*.yaml, compose.*.yml, docker-compose.yml, docker- │
│                 compose.yaml, docker-compose.*.yml, docker-compose.*.yaml, │
│                 k8s/**/*.yaml, k8s/**/*.yml, kubernetes/**/*.yaml,         │
│                 kubernetes/**/*.yml, kube/**/*.yaml, kube/**/*.yml,        │
│                 manifests/**/*.yaml, manifests/**/*.yml, deploy/**/*.yaml, │
│                 deploy/**/*.yml, deployment/**/*.yaml,                     │
│                 deployment/**/*.yml, deployments/**/*.yaml,                │
│                 deployments/**/*.yml, kustomize/**/*.yaml,                 │
│                 kustomize/**/*.yml, overlays/**/*.yaml, overlays/**/*.yml, │
│                 kustomization.yaml, kustomization.yml, deployment.yaml,    │
│                 deployment.yml, statefulset.yaml, statefulset.yml,         │
│                 daemonset.yaml, daemonset.yml, cronjob.yaml, cronjob.yml,  │
│                 job.yaml, job.yml, pod.yaml, pod.yml, *-deployment.yaml,   │
│                 *-deployment.yml, *-statefulset.yaml, *-statefulset.yml,   │
│                 *-daemonset.yaml, *-daemonset.yml, *-cronjob.yaml,         │
│                 *-cronjob.yml, *-job.yaml, *-job.yml, *-pod.yaml,          │
│                 *-pod.yml                                                  │
│ LOCKFILES       none                                                       │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:docker/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## CRAN

R packages, through renv. Ecosystem id `cran`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       DESCRIPTION, renv/settings.json, PACKAGES                  │
│ LOCKFILES       renv.lock                                                  │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## GitHub Actions

Workflows and the actions they use, pinned or not. Ecosystem id `actions`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       .github/workflows/*.yml, .github/workflows/*.yaml,         │
│                 action.yml, action.yaml                                    │
│ LOCKFILES       none                                                       │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Go modules

Go modules from the module proxy. Ecosystem id `gomod`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       go.mod, go.work                                            │
│ LOCKFILES       go.mod, go.sum, go.work.sum, vendor/modules.txt            │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:golang/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## Gradle

JVM dependencies, Gradle's way. Ecosystem id `gradle`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       build.gradle, build.gradle.kts, settings.gradle,           │
│                 settings.gradle.kts, gradle/libs.versions.toml,            │
│                 gradle/wrapper/gradle-wrapper.properties                   │
│ LOCKFILES       gradle.lockfile, buildscript-gradle.lockfile, settings-    │
│                 gradle.lockfile, gradle/dependency-locks/*.lockfile,       │
│                 gradle/verification-metadata.xml                           │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Hackage

Haskell packages, through cabal and stack. Ecosystem id `hackage`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       *.cabal, cabal.project, stack.yaml, package.yaml           │
│ LOCKFILES       cabal.project.freeze, stack.yaml.lock                      │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Helm

Charts a chart depends on. Ecosystem id `helm`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Chart.yaml, Chart.lock, requirements.lock                  │
│ LOCKFILES       Chart.lock, requirements.lock, charts/*.tgz                │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Hex

Elixir and Erlang packages. Ecosystem id `hex`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       mix.exs, rebar.config                                      │
│ LOCKFILES       mix.lock, rebar.lock                                       │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:hex/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## Homebrew

Formulae and casks in a Brewfile. Ecosystem id `homebrew`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Brewfile, .Brewfile, Brewfile.txt, Brewfile.local,         │
│                 Brewfile.symlink, *.Brewfile, Formula/*.rb, Casks/*.rb,    │
│                 Formula/*/*.rb, Casks/*/*.rb                               │
│ LOCKFILES       Brewfile.lock.json, Cellar/*/*/INSTALL_RECEIPT.json        │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Julia

Packages from the General registry. Ecosystem id `julia`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Project.toml, JuliaProject.toml                            │
│ LOCKFILES       Manifest.toml, JuliaManifest.toml, Manifest-v*.toml,       │
│                 Artifacts.toml                                             │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Maven

JVM dependencies from Maven Central. Ecosystem id `maven`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       pom.xml, .mvn/wrapper/maven-wrapper.properties             │
│ LOCKFILES       dependency-tree.txt, .mvn/checksums/*.sha1,                │
│                 .mvn/checksums/*.sha256, .mvn/checksums/*.sha512           │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:maven/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## Nix

Flake inputs. Ecosystem id `nix`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       flake.nix, default.nix, shell.nix                          │
│ LOCKFILES       flake.lock                                                 │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## npm

JavaScript and TypeScript packages, with npm, pnpm, Yarn or Bun. Ecosystem id `npm`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       package.json, deno.json, deno.jsonc                        │
│ LOCKFILES       package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml,    │
│                 yarn.lock, bun.lock, deno.lock                             │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:npm/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## NuGet

.NET packages. Ecosystem id `nuget`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       *.csproj, *.fsproj, *.vbproj, packages.config,             │
│                 Directory.Packages.props, Directory.Build.props,           │
│                 NuGet.Config, nuget.config, NuGet.config,                  │
│                 obj/project.assets.json                                    │
│ LOCKFILES       packages.lock.json, project.assets.json                    │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:nuget/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## opam

OCaml packages. Ecosystem id `opam`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       *.opam, opam, dune-project, dune-workspace,                │
│                 dune.lock/lock.dune                                        │
│ LOCKFILES       *.opam.locked, dune.lock/*.pkg                             │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Pub

Dart and Flutter packages. Ecosystem id `pub`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       pubspec.yaml                                               │
│ LOCKFILES       pubspec.lock, .dart_tool/package_config.json               │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:pub/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## PyPI

Python packages, with pip, Poetry, Pipenv, PDM or uv. Ecosystem id `pypi`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       pyproject.toml, setup.py, setup.cfg, requirements*.txt,    │
│                 requirements/*.txt, requirements*.in, requirements/*.in,   │
│                 Pipfile                                                    │
│ LOCKFILES       poetry.lock, Pipfile.lock, pdm.lock, uv.lock,              │
│                 requirements*.txt, requirements/*.txt                      │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:pypi/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## RubyGems

Ruby gems, through Bundler. Ecosystem id `rubygems`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Gemfile, gems.rb, *.gemspec, .ruby-version                 │
│ LOCKFILES       Gemfile.lock, gems.locked                                  │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
│                 provenance: whether a build attestation exists, and        │
│                 verifies                                                   │
│                 a published package fetched by digest and compared with    │
│                 the last release                                           │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner scan pkg:gem/<name>@<version> --online
cordon-scanner deps .                      # every package found, with its findings
```

## Swift

Swift Package Manager dependencies. Ecosystem id `swift`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       Package.swift                                              │
│ LOCKFILES       Package.resolved                                           │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 known-malicious and known-vulnerable releases, offline     │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## Terraform

Providers and their pinned hashes. Ecosystem id `terraform`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       *.tf, *.tf.json                                            │
│ LOCKFILES       .terraform.lock.hcl                                        │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```

## vcpkg

C and C++ ports. Ecosystem id `vcpkg`.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ MANIFESTS       vcpkg.json, vcpkg-configuration.json, vcpkg-lock.json      │
│ LOCKFILES       vcpkg-lock.json                                            │
│                                                                            │
│ OFFLINE         the dependency graph, lockfile integrity, licences,        │
│                 install hooks                                              │
│                 no advisory feed: said so, as                              │
│                 OPERATIONAL.ADVISORY.NO_FEED.001                           │
│                 typosquats and dependency confusion against its popular    │
│                 names                                                      │
│ WITH --online   registry: withdrawn releases, version distance, hash       │
│                 agreement                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

```
cordon-scanner scan .                      # every file above, in the project
cordon-scanner deps .                      # every package found, with its findings
```
## Every language

The source Cordon reads inside any of those projects: 38 languages, each identified by its file name or extension, by a script's interpreter line, or by its content. The last column counts the rule-pack rules written for that language. Every file also gets the checks that are not tied to one language (secrets, hidden characters, obfuscation, known-malware signatures), and Dockerfiles, YAML pipelines, manifests and infrastructure are read by their own detectors (tutorials 07 and 08), so a 0 there is not a file left unread. Every rule is in tutorial 28.

| Language | Files | Rule-pack rules |
|---|---|---|
| C | `*.c`, `*.h` | 0 |
| C# | `*.cs` | 10 |
| C++ | `*.cc`, `*.cpp`, `*.cxx`, `*.hpp` | 0 |
| Clojure | `*.bb`, `*.clj`, `*.cljc`, `*.cljs` | 8 |
| CMake | `CMakeLists.txt` | 10 |
| Dart | `*.dart` | 7 |
| Dockerfile | `Containerfile`, `Dockerfile` | 0 |
| Elixir | `*.ex`, `*.exs` | 8 |
| Go | `*.go` | 10 |
| Groovy | `Jenkinsfile`, `build.gradle` | 11 |
| Haskell | `*.hs`, `*.lhs` | 8 |
| Java | `*.java` | 10 |
| JavaScript | `*.cjs`, `*.js`, `*.jsx`, `*.mjs` | 15 |
| JSON | `*.json` | 0 |
| Julia | `*.jl` | 8 |
| Kotlin | `*.kt`, `*.kts`, `build.gradle.kts` | 18 |
| Lua | `*.lua` | 8 |
| Makefile | `GNUmakefile`, `Makefile` | 10 |
| Markdown | `*.markdown`, `*.md`, `*.mdc` | 0 |
| Nim | `*.nim`, `*.nimble`, `*.nims` | 7 |
| Objective-C | `*.m`, `*.mm` | 8 |
| OCaml | `*.ml`, `*.mli` | 8 |
| Perl | `*.pl`, `*.pm` | 8 |
| PHP | `*.php` | 10 |
| PowerShell | `*.ps1`, `*.psm1` | 10 |
| Python | `*.pth`, `*.py`, `*.pyi`, `*.pyw`, `conanfile.py`, `setup.py` | 17 |
| R | `*.r` | 8 |
| Ruby | `*.rb`, `Gemfile`, `Podfile`, `Rakefile` | 10 |
| Rust | `*.rs`, `build.rs` | 10 |
| Scala | `*.scala` | 10 |
| Shell | `*.bash`, `*.sh`, `*.zsh` | 11 |
| SQL | `*.sql` | 0 |
| Swift | `*.swift`, `Package.swift` | 8 |
| TOML | `*.toml` | 0 |
| TypeScript | `*.cts`, `*.mts`, `*.ts`, `*.tsx` | 15 |
| XML | `*.csproj`, `*.fsproj`, `*.props`, `*.targets`, `*.vbproj`, `*.xml` | 11 |
| YAML | `*.yaml`, `*.yml` | 0 |
| Zig | `*.zig`, `build.zig` | 7 |

Next: **[26 · Every command](26-every-command.md)**.
