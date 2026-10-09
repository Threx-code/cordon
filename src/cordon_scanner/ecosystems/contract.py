"""The ecosystem support contract: what "fully supported" means, per ecosystem, testably.

Recognising a manifest is not support. An ecosystem is supported to the degree it meets three
sets of clauses, each one either PROVEN by a conformance case or test that runs in the suite, or
declared NOT APPLICABLE with the reason written down:

```
  files       every manifest, lockfile, workspace and configuration file the ecosystem uses
  universal   UNI-01 .. UNI-30: discovery, parsing, errors, identity, versions, resolution,
              graph, types, workspaces, sources, advisories, malware, typosquat, confusion,
              integrity, registry, provenance, lifecycle, licences, policy, offline, online,
              remediation, explainability, output, scale, scanner safety, tests, coverage,
              compatibility
  specific    the ecosystem's own semantics (npm aliases, PEP 508 markers, Cargo features,
              Go replace directives, Maven BOM imports, ...)
```

Nothing here is asserted by hand as "supported". A clause is met when a conformance case under
`tests/conformance/cases/` lists it in `covers:` and passes, or when a test names it with the
`conformance(...)` marker -- `tests/conformance/test_contract.py` collects both, computes each
ecosystem's coverage and fails the suite below `REQUIRED_COVERAGE`. A NOT APPLICABLE clause needs a
reason, and the reason is published with the coverage table (`docs/07-ECOSYSTEMS.md`), so the gap
is visible rather than quietly counted as a pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

REQUIRED_COVERAGE: Final = 0.98

UNIVERSAL: Final[dict[str, str]] = {
    "UNI-01": "Discovery: every manifest, lockfile, workspace and configuration file is recognised",
    "UNI-02": "Parsing: valid files, syntax variations and version formats parse to the expected structure",
    "UNI-03": "Error handling: malformed, truncated and partial files give a diagnostic, never an empty list",
    "UNI-04": "Identity: name, namespace, source and version are normalised without losing the original",
    "UNI-05": "Version semantics: exact versions are told apart from ranges, prereleases and revisions",
    "UNI-06": "Resolution state: every dependency records whether it is resolved, and why",
    "UNI-07": "Graph: direct and transitive edges, roots, parents and depth",
    "UNI-08": "Dependency types: runtime, development, test, build, optional, peer, tool, platform",
    "UNI-09": "Workspaces: every member is scanned; shared dependencies are neither lost nor duplicated",
    "UNI-10": "Sources: registry, git, local path, archive and vendored sources are told apart",
    "UNI-11": "Vulnerability matching: affected versions are found, unaffected versions are not",
    "UNI-12": "Malicious packages: known-malicious releases are found through the relevant path",
    "UNI-13": "Typosquatting: near-miss and scope-confusion names are flagged, legitimate look-alikes are not",
    "UNI-14": "Dependency confusion: internal names that collide with public ones are flagged",
    "UNI-15": "Integrity: checksums are recorded, and tampered or mismatched values are reported",
    "UNI-16": "Registry verification: existence, metadata, history and digests, with failures told apart",
    "UNI-17": "Provenance: attestations are verified and bound to package, version and digest",
    "UNI-18": "Lifecycle and build risks: install hooks, build scripts and plugins are reported",
    "UNI-19": "Licences: licence metadata is identified and the configured policy applied",
    "UNI-20": "Policy: allow and deny lists, thresholds and exceptions give deterministic decisions",
    "UNI-21": "Offline: every check with local data runs, and the others say what they needed",
    "UNI-22": "Online: registry and feed access is bounded, cached and its failures represented",
    "UNI-23": "Remediation: fixed versions and advisory references are given when known",
    "UNI-24": "Explainability: every finding has a stable rule id, evidence and a reason",
    "UNI-25": "Output consistency: JSON, SARIF and the text report agree on the same findings",
    "UNI-26": "Scale: large files and repeated identities stay bounded and are not duplicated",
    "UNI-27": "Scanner safety: parsing never executes the project's scripts or build code",
    "UNI-28": "Test completeness: valid, invalid, edge, adversarial, regression and real fixtures",
    "UNI-29": "Coverage reporting: unread files, skipped checks and missing feeds are reported",
    "UNI-30": "Compatibility: parser, rule and feed versions are recorded and supported formats documented",
}


@dataclass(frozen=True)
class FileClause:
    pattern: str
    role: str
    """manifest, lockfile, workspace, configuration or metadata."""
    not_applicable: str = ""
    """Why this file is not read, when it is not. Empty means it must be proven read."""


@dataclass(frozen=True)
class EcosystemContract:
    id: str
    title: str
    files: tuple[FileClause, ...]
    specific: dict[str, str]
    """`<ecosystem>.<clause>` -> what it requires."""
    not_applicable: dict[str, str] = field(default_factory=dict)
    """Clause id (universal or specific) -> why it does not apply to this ecosystem."""

    def clause_ids(self) -> list[str]:
        return (
            [f"{self.id}.file:{f.pattern}" for f in self.files]
            + list(UNIVERSAL)
            + list(self.specific)
        )


class _Files:
    @staticmethod
    def of(role: str, *patterns: str) -> tuple[FileClause, ...]:
        return tuple(FileClause(p, role) for p in patterns)


_files = _Files.of


NO_INSTALL_HOOKS: Final = (
    "the ecosystem has no install-time hook: nothing runs when a dependency is fetched"
)
NO_PROVENANCE: Final = "the registry publishes no build attestation to verify"
NO_REGISTRY_API: Final = "there is no registry with a public metadata API to ask"

CONTRACTS: Final[tuple[EcosystemContract, ...]] = (
    EcosystemContract(
        "npm",
        "npm / JavaScript",
        _files("manifest", "package.json", "deno.json", "deno.jsonc")
        + _files(
            "lockfile",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "deno.lock",
        )
        + (FileClause("bun.lockb", "lockfile"),),
        {
            "npm.npm-semantics": "npm lockfile v1, v2 and v3 layouts",
            "npm.pnpm-semantics": "pnpm lockfile v5, v6 and v9 layouts",
            "npm.yarn-classic": "Yarn Classic (v1) lockfiles",
            "npm.yarn-berry": "Yarn 2+ (berry) lockfiles",
            "npm.bun": "Bun's text lockfile",
            "npm.deno": "Deno's lockfile and import map",
            "npm.scoped": "scoped packages",
            "npm.aliases": "npm: aliases",
            "npm.workspaces": "workspaces",
            "npm.peer-optional": "peer and optional dependencies",
            "npm.overrides": "overrides and resolutions",
            "npm.git-url-file": "git, URL and file dependencies",
            "npm.platform-optional": "platform-specific optional packages (os, cpu)",
            "npm.lifecycle": "lifecycle scripts",
            "npm.integrity": "integrity hashes",
            "npm.bundled": "bundled dependencies",
            "npm.nested": "nested lockfile layouts",
        },
    ),
    EcosystemContract(
        "pypi",
        "PyPI / Python",
        _files(
            "manifest",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "requirements/base.txt",
            "requirements.in",
            "requirements/base.in",
            "Pipfile",
        )
        + _files(
            "lockfile",
            "Pipfile.lock",
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
            "requirements.lock.txt",
        ),
        {
            "pypi.pep440": "PEP 440 versions",
            "pypi.pep508-markers": "PEP 508 environment markers",
            "pypi.extras": "extras",
            "pypi.direct-url": "direct URL dependencies",
            "pypi.vcs": "VCS references",
            "pypi.editable": "editable installs",
            "pypi.constraints": "constraints files (-c)",
            "pypi.includes": "nested -r and -c includes",
            "pypi.python-version": "Python version requirements",
            "pypi.optional-groups": "optional dependency groups and dependency groups",
            "pypi.build-system": "build-system requirements",
            "pypi.hashes": "--hash pins",
            "pypi.no-setup-exec": "setup.py is read, never run",
        },
    ),
    EcosystemContract(
        "cargo",
        "Cargo / Rust",
        _files("manifest", "Cargo.toml")
        + _files("lockfile", "Cargo.lock")
        + _files("configuration", ".cargo/config.toml"),
        {
            "cargo.workspace-inheritance": "workspace inheritance",
            "cargo.renamed": "renamed dependencies (package =)",
            "cargo.features": "features, declared versus activated",
            "cargo.optional": "optional dependencies",
            "cargo.target": "target-specific dependencies",
            "cargo.build-dev": "build and dev dependencies",
            "cargo.git": "git sources and revisions",
            "cargo.path": "path dependencies",
            "cargo.registry-replacement": "registry replacement in .cargo/config.toml",
            "cargo.checksums": "checksums",
            "cargo.edition-msrv": "edition and rust-version",
            "cargo.lock-versions": "Cargo.lock format versions",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "gomod",
        "Go modules",
        _files("manifest", "go.mod")
        + _files("lockfile", "go.sum")
        + _files("workspace", "go.work")
        + _files("metadata", "vendor/modules.txt"),
        {
            "gomod.major-suffix": "module paths and major-version suffixes",
            "gomod.replace": "replace directives",
            "gomod.exclude": "exclude directives",
            "gomod.local-replace": "local replacements",
            "gomod.workspace": "workspace modules",
            "gomod.indirect": "indirect dependencies",
            "gomod.pseudo": "pseudo-versions",
            "gomod.checksums": "go.sum checksums",
            "gomod.toolchain": "go and toolchain directives",
            "gomod.vendor": "vendoring through vendor/modules.txt",
            "gomod.private": "private module sources (GOPRIVATE)",
            "gomod.tool": "tool directives",
        },
        {
            "UNI-18": NO_INSTALL_HOOKS,
            "UNI-17": "Go modules publish no build attestation; go.sum is checked against the checksum database instead (UNI-16)",
        },
    ),
    EcosystemContract(
        "maven",
        "Maven",
        _files("manifest", "pom.xml")
        + _files("configuration", ".mvn/wrapper/maven-wrapper.properties")
        + _files("lockfile", "dependency-tree.txt"),
        {
            "maven.parent": "parent inheritance",
            "maven.properties": "property interpolation",
            "maven.dependency-management": "dependency management",
            "maven.bom": "BOM imports",
            "maven.scopes": "scopes",
            "maven.optional-exclusions": "optional dependencies and exclusions",
            "maven.classifier-type": "classifiers and types",
            "maven.snapshots": "snapshots",
            "maven.ranges": "version ranges",
            "maven.profiles": "profiles",
            "maven.repositories": "repositories",
            "maven.plugins": "plugins and build extensions",
            "maven.declared-vs-effective": "declared dependencies told apart from the effective graph",
        },
        {
            "UNI-18": "Maven runs no code from a dependency at install; build plugins are reported under maven.plugins"
        },
    ),
    EcosystemContract(
        "gradle",
        "Gradle",
        _files("manifest", "build.gradle", "build.gradle.kts", "gradle/libs.versions.toml")
        + _files("lockfile", "gradle.lockfile", "gradle/verification-metadata.xml")
        + _files("workspace", "settings.gradle", "settings.gradle.kts"),
        {
            "gradle.groovy-kotlin": "Groovy and Kotlin DSLs",
            "gradle.multi-project": "multi-project builds",
            "gradle.catalog": "version catalogs",
            "gradle.constraints": "dependency constraints",
            "gradle.platforms": "platforms and BOMs",
            "gradle.configurations": "configurations",
            "gradle.plugins": "plugin dependencies",
            "gradle.composite": "composite builds",
            "gradle.dynamic": "dynamic versions",
            "gradle.lock-state": "lock state",
            "gradle.verification": "verification metadata",
            "gradle.no-exec": "build logic is read, never run",
            "gradle.substitutions": "dependency substitutions and forced versions: what resolution rules fetch",
            "gradle.capabilities": "capabilities a dependency requires, selecting its variant",
        },
        {},
    ),
    EcosystemContract(
        "nuget",
        "NuGet / .NET",
        _files(
            "manifest",
            "app.csproj",
            "app.fsproj",
            "app.vbproj",
            "packages.config",
            "Directory.Packages.props",
            "Directory.Build.props",
        )
        + _files("lockfile", "packages.lock.json", "project.assets.json")
        + _files("configuration", "NuGet.Config"),
        {
            "nuget.central": "central package management",
            "nuget.transitive-pinning": "transitive pinning",
            "nuget.target-frameworks": "target frameworks",
            "nuget.rid": "runtime identifiers",
            "nuget.conditional": "conditional references",
            "nuget.floating": "floating versions",
            "nuget.sources": "package sources",
            "nuget.source-mapping": "package source mapping",
            "nuget.project-references": "project references",
            "nuget.declared-vs-resolved": "declared versions told apart from resolved ones per framework",
        },
        {
            "UNI-17": (
                "nuget.org publishes no build attestation; its packages carry X.509 author and repository "
                "signatures inside the .nupkg, which bind a publisher, not a source build, and which only "
                "the package bytes themselves can verify -- `contentHash` integrity (UNI-15/16) is what a "
                "lockfile scan can check"
            )
        },
    ),
    EcosystemContract(
        "composer",
        "Composer / PHP",
        _files("manifest", "composer.json")
        + _files("lockfile", "composer.lock")
        + _files("configuration", "auth.json"),
        {
            "composer.require-dev": "require and require-dev",
            "composer.platform": "platform requirements (php, ext-*)",
            "composer.virtual": "virtual packages, provide and replace",
            "composer.aliases": "aliases",
            "composer.stability": "stability flags",
            "composer.repositories": "repositories, path and VCS",
            "composer.plugins": "plugins",
            "composer.scripts": "scripts",
            "composer.conflict": "conflict",
            "composer.abandoned": "abandoned packages",
            "composer.credentials": "credentials in auth.json are never disclosed",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "rubygems",
        "RubyGems",
        _files("manifest", "Gemfile", "app.gemspec", "gems.rb")
        + _files("lockfile", "Gemfile.lock", "gems.locked")
        + _files("configuration", ".ruby-version"),
        {
            "rubygems.groups": "groups",
            "rubygems.platforms": "platforms",
            "rubygems.ruby-version": "Ruby version constraints",
            "rubygems.git-path": "git and path dependencies",
            "rubygems.gemspec": "gemspec dependencies",
            "rubygems.sources": "source declarations and multiple sources",
            "rubygems.lock-versions": "Bundler lockfile versions",
            "rubygems.native": "native extensions",
            "rubygems.checksums": "checksums",
            "rubygems.source-ambiguity": "source ambiguity",
        },
    ),
    EcosystemContract(
        "hex",
        "Hex / Elixir",
        _files("manifest", "mix.exs", "rebar.config")
        + _files("lockfile", "mix.lock", "rebar.lock"),
        {
            "hex.umbrella": "umbrella applications",
            "hex.git-path": "git and path dependencies",
            "hex.optional-dev": "optional and dev dependencies",
            "hex.compat": "OTP and Elixir compatibility",
            "hex.override": "overrides",
            "hex.graph": "transitive graph",
            "hex.rebar": "Rebar-managed Erlang dependencies",
            "hex.declared-vs-locked": "declaration told apart from lockfile resolution",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "pub",
        "Pub / Dart / Flutter",
        _files("manifest", "pubspec.yaml")
        + _files("lockfile", "pubspec.lock")
        + _files("metadata", ".dart_tool/package_config.json"),
        {
            "pub.hosted": "hosted packages",
            "pub.git-path": "git and path dependencies",
            "pub.overrides": "dependency overrides",
            "pub.dev": "dev dependencies",
            "pub.sdk": "Flutter and Dart SDK constraints",
            "pub.sdk-packages": "SDK packages told apart from registry packages",
            "pub.workspace": "pub workspaces",
            "pub.graph": "transitive resolution",
            "pub.platforms": "the platforms a package declares it supports",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "swift",
        "Swift Package Manager",
        _files("manifest", "Package.swift") + _files("lockfile", "Package.resolved"),
        {
            "swift.semver": "semantic version requirements",
            "swift.branch-revision": "branch and revision pins",
            "swift.path": "local path dependencies",
            "swift.binary-targets": "binary targets and checksums",
            "swift.products": "package products and target dependencies",
            "swift.resolved-versions": "Package.resolved versions 1, 2 and 3",
            "swift.platforms": "platform requirements",
            "swift.immutable": "immutable revisions told apart from floating branches",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-15": (
                "Package.resolved records no archive hash: a git pin's integrity is its commit SHA, which git "
                "itself verifies, and a binary target's SHA-256 lives in Package.swift (swift.binary-targets)"
            ),
            "UNI-16": (
                "SwiftPM has no central registry to ask: packages are git repositories, and the Swift package "
                "registry protocol has no public instance with a metadata API"
            ),
            "UNI-22": "no registry is consulted online (UNI-16): a git source is fetched by SwiftPM itself",
        },
    ),
    EcosystemContract(
        "cocoapods",
        "CocoaPods",
        _files("manifest", "Podfile", "app.podspec") + _files("lockfile", "Podfile.lock"),
        {
            "cocoapods.sources": "source repositories",
            "cocoapods.podspec": "podspec dependencies",
            "cocoapods.subspecs": "subspecs",
            "cocoapods.platform": "platform constraints",
            "cocoapods.configurations": "configurations and test targets",
            "cocoapods.constraints": "version constraints",
            "cocoapods.git-external": "git and external sources",
            "cocoapods.checksums": "checksums",
            "cocoapods.vs-spm": "CocoaPods told apart from SwiftPM in the same app",
            "cocoapods.test-specs": "test and app specs' dependencies, scoped apart from the pod's",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "conda",
        "Conda",
        _files("manifest", "environment.yml", "environment.yaml", "meta.yaml")
        + _files("lockfile", "conda-lock.yml", "conda-lock.yaml", "explicit.txt"),
        {
            "conda.channels": "channels and channel priority",
            "conda.build-strings": "build strings and numbers",
            "conda.subdirs": "subdirectories and platforms",
            "conda.virtual": "virtual packages",
            "conda.pip": "pip subsections, as PyPI",
            "conda.explicit": "explicit exports",
            "conda.partial": "a partial environment is not reported as a resolved graph",
            "conda.channel-priority": "channel order and priority from .condarc",
            "conda.variables": "environment variables an environment sets, named and never valued",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-18": "a conda package's post-link scripts run from the archive, which content scanning reads; the environment file declares none",
        },
    ),
    EcosystemContract(
        "cran",
        "CRAN / R",
        _files("manifest", "DESCRIPTION")
        + _files("lockfile", "renv.lock")
        + _files("configuration", "renv/settings.json")
        + _files("metadata", "PACKAGES"),
        {
            "cran.fields": "Imports, Depends, Suggests, LinkingTo, Enhances",
            "cran.r-version": "R version constraints",
            "cran.repositories": "repository configuration",
            "cran.bioconductor": "Bioconductor told apart from CRAN",
            "cran.remotes": "GitHub and remotes dependencies",
            "cran.sysreqs": "system requirements",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "hackage",
        "Hackage / Haskell",
        _files("manifest", "app.cabal", "cabal.project")
        + _files("lockfile", "cabal.project.freeze", "stack.yaml.lock")
        + _files("workspace", "stack.yaml"),
        {
            "hackage.cabal-constraints": "Cabal constraints and freeze files",
            "hackage.stack-snapshots": "Stack snapshots and resolvers",
            "hackage.flags": "flags",
            "hackage.conditionals": "conditional dependencies",
            "hackage.compiler": "compiler and platform constraints",
            "hackage.source-repos": "source repositories and git dependencies",
            "hackage.revisions": "package revisions",
            "hackage.distinct": "Stack and Cabal semantics kept distinct",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "julia",
        "Julia",
        _files("manifest", "Project.toml")
        + _files("lockfile", "Manifest.toml", "JuliaManifest.toml"),
        {
            "julia.uuid": "UUID-based identity",
            "julia.compat": "compat bounds",
            "julia.manifest-versions": "manifest format versions",
            "julia.julia-version": "Julia version constraints",
            "julia.git": "git URLs and revisions",
            "julia.path": "path dependencies",
            "julia.weak-extensions": "weak dependencies and extensions",
            "julia.artifacts": "platform-specific artifacts",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "opam",
        "OPAM / OCaml",
        _files("manifest", "app.opam", "opam", "dune-project")
        + _files("lockfile", "app.opam.locked")
        + _files("workspace", "dune-workspace"),
        {
            "opam.compiler": "compiler constraints",
            "opam.versions": "package versions",
            "opam.repositories": "repository metadata",
            "opam.pins": "pins",
            "opam.git-local": "git and local sources",
            "opam.dep-kinds": "build, test, doc and optional dependencies",
            "opam.variables": "feature variables and filters",
            "opam.dune": "dune declarations told apart from opam resolution",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "conan",
        "Conan / C and C++",
        _files("manifest", "conanfile.txt", "conanfile.py")
        + _files("lockfile", "conan.lock")
        + _files("configuration", "profiles/default"),
        {
            "conan.versions-1-2": "Conan 1 and Conan 2 lockfiles",
            "conan.recipes": "recipes",
            "conan.ranges": "version ranges",
            "conan.revisions": "recipe revisions",
            "conan.package-id": "package ids",
            "conan.host-build": "host and build contexts",
            "conan.profiles-options": "profiles and options",
            "conan.tool-requires": "tool requirements",
            "conan.overrides": "overrides",
            "conan.remotes": "remotes",
            "conan.recipe-vs-binary": "recipe identity told apart from the binary package",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "vcpkg",
        "vcpkg / C and C++",
        _files("manifest", "vcpkg.json")
        + _files("configuration", "vcpkg-configuration.json")
        + _files("lockfile", "vcpkg-lock.json"),
        {
            "vcpkg.manifest-mode": "manifest mode",
            "vcpkg.baselines": "baselines",
            "vcpkg.registries": "registries",
            "vcpkg.overlays": "overlays",
            "vcpkg.features": "features",
            "vcpkg.host": "host dependencies",
            "vcpkg.platform": "platform expressions",
            "vcpkg.port-versions": "ports and port versions",
            "vcpkg.git-ports": "git-based port sources",
            "vcpkg.triplets": "custom triplets from overlay directories, recorded as build code",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-18": "a port's build runs from its portfile, which is reported as a build script where present",
            "UNI-15": "no vcpkg file records a port's hash: each version is pinned by git-tree in the registry's version database at the baseline commit",
        },
    ),
    EcosystemContract(
        "actions",
        "GitHub Actions",
        _files(
            "manifest",
            ".github/workflows/ci.yml",
            ".github/workflows/ci.yaml",
            "action.yml",
            "action.yaml",
            "nested/action.yml",
        ),
        {
            "actions.uses": "uses: references at workflow, job and step level",
            "actions.sha-pinning": "commit SHAs told apart from tags and branches",
            "actions.reusable": "reusable workflows",
            "actions.local": "local actions",
            "actions.composite": "composite actions",
            "actions.docker": "container actions and docker:// images",
            "actions.expressions": "expressions and untrusted pull-request contexts",
            "actions.permissions": "permissions",
            "actions.secrets": "secrets exposure",
            "actions.separation": "dependency findings kept apart from workflow misconfiguration",
        },
        {
            "UNI-15": "an action reference records no hash beyond the commit it names; SHA pinning is actions.sha-pinning",
            "UNI-14": "an action is named by its repository on github.com: there is no second registry an internal name could be confused with",
            "UNI-17": "an action runs the repository tree at a commit; GitHub's release attestations cover release assets, not that tree",
        },
    ),
    EcosystemContract(
        "ansible",
        "Ansible",
        _files(
            "manifest",
            "requirements.yml",
            "requirements.yaml",
            "roles/requirements.yml",
            "collections/requirements.yml",
            "galaxy.yml",
            "meta/main.yml",
        ),
        {
            "ansible.collections-roles": "collections and roles",
            "ansible.identity": "namespace.name identity",
            "ansible.constraints": "version constraints",
            "ansible.git": "git sources and commit pins",
            "ansible.nested": "nested role dependencies",
            "ansible.collection-deps": "collection dependencies",
            "ansible.playbooks": "playbooks and tasks checked for unsafe configuration, kept apart from package findings",
            "ansible.execution-environment": "execution environments: base image, collections, pip and system packages",
            "ansible.compatibility": "the ansible-core versions a collection supports (requires_ansible)",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-15": "Galaxy requirement files record no hash; git sources are judged by commit pinning (ansible.git)",
            "UNI-18": "ansible-galaxy install runs no code from a role or collection; what they run, they run in plays, which the playbook rules read (ansible.playbooks)",
        },
    ),
    EcosystemContract(
        "bazel",
        "Bazel",
        _files("manifest", "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel", "BUILD.bazel")
        + _files("lockfile", "MODULE.bazel.lock"),
        {
            "bazel.bzlmod": "Bzlmod modules and registries",
            "bazel.extensions": "module extensions",
            "bazel.repository-rules": "repository rules (http_archive, git_repository)",
            "bazel.workspace": "legacy WORKSPACE dependencies",
            "bazel.overrides": "overrides",
            "bazel.checksums": "archive checksums",
            "bazel.git": "external git repositories and commit pins",
            "bazel.apparent-names": "a repo_name kept as the apparent name, the module named by its own",
            "bazel.migration": "a WORKSPACE beside MODULE.bazel said to be unread where Bazel does not read it",
        },
        {"UNI-17": NO_PROVENANCE},
    ),
    EcosystemContract(
        "helm",
        "Helm",
        _files("manifest", "Chart.yaml", "requirements.yaml")
        + _files("lockfile", "Chart.lock", "requirements.lock")
        + _files("metadata", "templates/deployment.yaml", "values.yaml"),
        {
            "helm.dependencies": "chart dependencies and repositories",
            "helm.constraints": "version constraints",
            "helm.lock-digest": "lock digests",
            "helm.alias-condition": "aliases, conditions and tags",
            "helm.local-oci": "local chart paths and OCI references",
            "helm.nested": "nested charts",
            "helm.k8s": "Kubernetes resources checked for deployment risks, kept apart from chart dependencies",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-18": "charts run no code at install beyond hooks, which are Kubernetes resources checked under helm.k8s",
            "UNI-15": "a chart lock records no per-chart hash; a downloaded archive's is computed from its bytes, never read, so no recorded value can be malformed -- a mismatch with the repository's digest is UNI-16",
            "UNI-14": "every chart dependency names its repository's URL: there is no shared public namespace an internal chart's name could be taken in",
        },
    ),
    EcosystemContract(
        "homebrew",
        "Homebrew",
        _files("manifest", "Brewfile", "Formula/tool.rb", "Casks/app.rb")
        + _files("lockfile", "Brewfile.lock.json", "Cellar/<name>/<version>/INSTALL_RECEIPT.json"),
        {
            "homebrew.formulae-casks": "formulae and casks",
            "homebrew.taps": "taps, third-party taps flagged",
            "homebrew.urls-checksums": "URL and checksum declarations",
            "homebrew.categories": "bundle categories (brew, cask, mas, vscode, whalebrew)",
            "homebrew.declared-vs-installed": "declared bundle entries told apart from installed versions",
        },
        {},
    ),
    EcosystemContract(
        "nix",
        "Nix",
        _files("manifest", "flake.nix", "default.nix", "shell.nix")
        + _files("lockfile", "flake.lock"),
        {
            "nix.inputs": "flake inputs and the recursive input graph",
            "nix.locked": "locked revisions and hashes",
            "nix.follows": "follows relationships",
            "nix.indirect": "indirect inputs",
            "nix.nixpkgs": "nixpkgs revisions",
            "nix.git-archive": "git and archive inputs",
            "nix.no-eval": "Nix expressions are read, never evaluated",
            "nix.overlays": "overlays applied to nixpkgs, from inputs and local files",
        },
        {
            "UNI-17": NO_PROVENANCE,
            "UNI-18": NO_INSTALL_HOOKS,
            "UNI-16": "Nix has no registry: an input is fetched from its repository or archive and checked against the NAR hash the lock records, which Nix verifies itself",
            "UNI-22": "Nix has no registry to be unreachable: each input is fetched from its own repository or archive",
            "UNI-14": "a flake input names its repository or archive: there is no shared namespace an internal name could be taken in (an indirect input's registry is the user's own configuration)",
        },
    ),
    EcosystemContract(
        "terraform",
        "Terraform",
        _files("lockfile", ".terraform.lock.hcl") + _files("manifest", "main.tf", "main.tf.json"),
        {
            "terraform.providers": "provider constraints and selections",
            "terraform.hashes": "provider hashes and platform checksums",
            "terraform.modules": "modules from registries, git, archives and local paths",
            "terraform.module-pinning": "module pinning",
            "terraform.aliases": "provider aliases",
            "terraform.iac": "insecure resources, IAM, network exposure and secret references",
            "terraform.tfvars": "variable files read for what static analysis applies: secrets",
        },
        {
            "UNI-17": "a provider release's SHA256SUMS is GPG-signed and terraform init verifies the signature; the lock's zip hashes are compared with those sums (UNI-16)",
        },
    ),
    EcosystemContract(
        "image",
        "Docker and container images",
        _files("manifest", "Dockerfile", "compose.yaml") + _files("metadata", "image.tar"),
        {
            "image.os-packages": "OS packages in image layers",
            "image.app-deps": "application dependencies in image layers",
            "image.multi-stage": "multi-stage builds",
            "image.digests": "image digests reported",
            "image.base-provenance": "base-image pinning and provenance",
            "image.config": "image configuration",
            "image.binaries": "embedded binaries",
            "image.secrets": "secrets, including in deleted layers",
            "image.offline": "offline archives",
        },
        {
            "UNI-13": "image references are not package names: base-image trust is image.base-provenance"
        },
    ),
)

#: Cross-cutting areas of section C, proven the same way.
CROSS_CUTTING: Final[dict[str, str]] = {
    "x.git": "git dependencies: URLs, subdirectories, tags, branches, commits, submodules; mutable refs told apart",
    "x.private-registries": "private registries: authenticated metadata, namespace policy, source mapping, no credential exposure",
    "x.vendored": "vendored dependencies identified from reliable evidence",
    "x.binary": "binary dependencies: metadata, checksums, signatures, architecture",
    "x.sbom": "SBOM ingestion: CycloneDX and SPDX, validated, with source attribution",
    "x.os-packages": "OS packages: dpkg, RPM and APK with distribution-specific matching",
    "x.feeds": "vulnerability feeds: coverage, freshness, aliases, ranges, fixed versions, withdrawn advisories",
    "x.malicious": "malicious intelligence: confirmed malicious, suspicious and vulnerable kept apart, with source",
    "x.provenance": "package provenance: attestations, identities, subject digests, trust policy",
    "x.policy": "policy and exceptions: consistent across inputs, with expiry, justification and scope",
}

#: Every field of the shared dependency record (section 3).
RECORD_FIELDS: Final = (
    "ecosystem",
    "name",
    "namespace",
    "version_constraint",
    "resolved_version",
    "resolution_status",
    "source_type",
    "source_url",
    "integrity",
    "direct",
    "dependency_path",
    "dependency_type",
    "platform_constraints",
    "manifest_location",
    "lockfile_location",
    "advisory_status",
    "malware_status",
    "integrity_status",
    "provenance_status",
    "licence_status",
    "findings",
)


class Contracts:
    @staticmethod
    def get(ecosystem: str) -> EcosystemContract | None:
        return next((c for c in CONTRACTS if c.id == ecosystem), None)


__all__ = [
    "CONTRACTS",
    "CROSS_CUTTING",
    "RECORD_FIELDS",
    "REQUIRED_COVERAGE",
    "UNIVERSAL",
    "Contracts",
    "EcosystemContract",
    "FileClause",
]
