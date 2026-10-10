"""The ecosystem contract.

An ecosystem adapter teaches Cordon how one package manager describes
dependencies: where its manifests live, how to read them, what its lockfile
means, and which paths in it execute during installation.

Two decisions govern every implementation.

**Parse, never invoke.** The graph is built by reading the lockfile, never by
running the ecosystem's own resolver. Running `npm ls` or `pip install` would
execute untrusted tooling against attacker-controlled metadata inside the tool
whose entire purpose is avoiding that, and it would make results
non-reproducible because a resolver consults a live registry.

**Name normalisation is per-ecosystem.** Registries disagree about what makes
two names the same: PyPI folds separators and case, npm folds case, Maven
composes group and artifact, Go encodes capitals. Typosquat detection is
meaningless without this, and it is where most tools generate their false
positives.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from cordon_scanner.core.models import Dependency, Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon_scanner.core.content import FileContent


class Coordinate:
    """Bounds on the strings that identify a package.

    A package coordinate is the one piece of scanned content that is *supposed*
    to be copied verbatim into a finding message, a purl and a SARIF result. It
    therefore never passes the redactor, and that makes every parser a leak
    channel: a parser that reads one field too far turns the rest of the line
    into a "version" and publishes it.

    That is not hypothetical. `req==1.0 --hash=sha256:...` is a legal
    requirements line, and reading the version as everything after `==` put the
    whole tail into `pkg:pypi/req@1.0 --hash=...` in every output format.
    Reviewing eight parsers for the same mistake does not stop the ninth, so the
    bound lives on the model instead, where every parser has to pass through it.

    Names and versions are single tokens in every ecosystem Cordon supports --
    none of them permits whitespace -- so cutting at the first space discards
    only text that was never part of the coordinate. Specs are different: a
    version range legitimately contains spaces, so those are length-bounded
    only.
    """

    # Past every real coordinate: npm allows a 214-character name, and a prerelease tag can run to
    # seventy characters and more. Bounds shorter than that cut a published malicious release's
    # name or version before it was looked up -- 2 of the 249,646 known-malicious records were
    # missed that way (`bench/malicious_records.py`) -- which hands an attacker an evasion: pad the
    # version, and the lookup is of a release that never existed.
    MAX_NAME = 256
    MAX_VERSION = 128
    MAX_SPEC = 256

    @staticmethod
    def token(value: str, limit: int) -> str:
        """Cut a coordinate down to the token it should have been."""
        return value.strip().split(None, 1)[0][:limit] if value.strip() else ""

    @staticmethod
    def phrase(value: str, limit: int) -> str:
        """Bound a field where internal spaces are legitimate."""
        return " ".join(value.split())[:limit]

    #: The shapes an integrity value takes in the formats Cordon reads. An integrity field is copied
    #: from the scanned file into every report, so anything that is not a digest -- a token planted
    #: in `--hash=`, a sentence -- is replaced by `MALFORMED` and a digest of what was there, never
    #: echoed. The integrity rules report it (`SUSPECT.LOCKFILE.INTEGRITY_MALFORMED.001`).
    _DIGEST = re.compile(
        r"(?:"
        r"(?:sha1|sha256|sha384|sha512)-[A-Za-z0-9+/]{20,128}={0,2}"  # SRI (npm, Bun, Nix, Bazel)
        r"|(?:sha1|sha224|sha256|sha384|sha512|md5|blake2b|blake2b_256|sha3_256|sha256-hex|hexinner)[:=][0-9a-fA-F]{32,128}"
        r"|h1:[A-Za-z0-9+/]{43}="  # Go module hash, Terraform h1
        r"|git-tree-sha1:[0-9a-fA-F]{40}"  # Julia: the git tree of a package version or artifact
        r"|sha256:[0-9a-df-np-sv-z]{52}"  # Nix: a sha256 in Nix's own base32 alphabet
        r"|zh:[0-9a-f]{64}"  # Terraform zip hash
        r"|\d{1,3}c\d{1,2}/[0-9a-f]{64,128}|\d{1,2}/[0-9a-f]{64,128}"  # Yarn Berry cache key / checksum
        r"|[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128}"
        r"|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{27}="  # bare base64 sha256 / sha512 / sha1
        r")"
    )
    MALFORMED = "malformed:"

    @staticmethod
    def integrity(value: str | None) -> str | None:
        """A digest as recorded, or `malformed:<sha256 of it>` when it is not one."""
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if len(text) <= 256 and Coordinate._DIGEST.fullmatch(text):
            return text
        import hashlib

        return (
            Coordinate.MALFORMED + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
        )

    MAX_CONDITIONS = 16

    @staticmethod
    def conditions(values: tuple[str, ...]) -> tuple[str, ...]:
        """Bound platform conditions: phrases, deduplicated, at most `MAX_CONDITIONS`."""
        out: list[str] = []
        for value in values:
            phrase = Coordinate.phrase(str(value), Coordinate.MAX_SPEC)
            if phrase and phrase not in out:
                out.append(phrase)
        return tuple(out[: Coordinate.MAX_CONDITIONS])


WORKSPACE_INHERITED = "workspace"

#: The names ecosystems give their public registry when a lockfile or manifest names it rather
#: than giving a URL: Hex's `"hexpm"`, Cargo's `crates-io`, NuGet's `nuget.org` source key.
PUBLIC_REGISTRY_NAMES = frozenset(
    {
        "hexpm",
        "crates-io",
        "crates.io",
        "nuget.org",
        "pypi",
        "npmjs",
        "rubygems",
        "packagist",
        "packagist.org",
        "central",
        "default",
    }
)
"""The spec recorded for a dependency whose version the workspace root sets.

A sentinel rather than an empty string, so the rules that read a spec can tell
"inherited from somewhere this file does not name" from "no constraint at
all" -- the first is pinned and the second is not."""


@dataclass(frozen=True, slots=True)
class DeclaredDependency:
    """A dependency as written in a manifest, before resolution.

    Distinct from :class:`~cordon.core.models.Dependency`, which is resolved.
    The declared form carries the version *range* and the source the author
    asked for, and comparing the two is how a stale security pin is detected.
    """

    name: str
    spec: str
    scope: Scope = Scope.RUNTIME
    field_name: str = ""

    ecosystem: str | None = None
    """The ecosystem this entry belongs to, when it is not the file's own.

    One manifest format carries another's packages: a conda `environment.yml`
    nests a `pip:` list, and those are PyPI packages sitting in a conda file.
    Recording them under the file's ecosystem would match no advisory and name
    nothing a reader could act on; leaving them out meant nothing read them at
    all, because no PyPI glob matches `environment.yml`.
    """

    platform: tuple[str, ...] = ()
    """Conditions on where it applies, as written: a PEP 508 marker, a Cargo `cfg(...)`, a
    .NET target framework. See `Dependency.platform`."""

    alias: str | None = None
    """The name the manifest used when it is not the package's own (an npm alias, a renamed Cargo
    dependency). `name` is the real package."""

    extras: tuple[str, ...] = ()
    """Optional features requested of it: PEP 508 extras (`requests[socks]`), Cargo features,
    vcpkg features. Each can bring in dependencies of its own."""

    editable: bool = False
    """Installed in place from a working tree (`pip install -e`): its code is read live."""

    source: str | None = None
    """Where the manifest says it comes from when that is not the default registry: a named
    registry (`registry:internal`), an index URL. Carried to the record's source."""

    exclusions: tuple[str, ...] = ()
    """Transitive dependencies this declaration excludes (Maven `<exclusions>`, Gradle `exclude`)."""

    note: str | None = None
    """Why the declaration cannot be resolved, when the parser knows (a version managed by a parent
    POM that is not in the scanned tree)."""

    integrity: str | None = None
    """A hash the declaration itself pins (a GitHub Action's commit SHA), where the manifest is the
    only file that records one."""

    signature_sources: tuple[str, ...] = ()
    """Where the declaration says signatures over the package are (a requirements.yml
    collection's `signatures:` URLs), which `ansible-galaxy` checks against its keyring."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", Coordinate.token(self.name, Coordinate.MAX_NAME))
        object.__setattr__(self, "integrity", Coordinate.integrity(self.integrity))
        object.__setattr__(self, "spec", Coordinate.phrase(self.spec, Coordinate.MAX_SPEC))
        object.__setattr__(self, "platform", Coordinate.conditions(self.platform))
        object.__setattr__(self, "extras", Coordinate.conditions(self.extras))
        if self.alias is not None:
            alias = Coordinate.token(self.alias, Coordinate.MAX_NAME)
            object.__setattr__(self, "alias", alias if alias and alias != self.name else None)

    @property
    def is_non_registry(self) -> bool:
        """Whether this resolves from somewhere other than the registry.

        A git URL, archive URL or filesystem path bypasses the lockfile's
        integrity hashes, advisory matching and any release-age cooldown in a
        single move. The dependency may be entirely legitimate; the point is
        that none of the ecosystem's own protections apply to it.
        """
        lowered = self.spec.strip().lower()
        return lowered.startswith(
            (
                "git+",
                "git:",
                "github:",
                "gitlab:",
                "bitbucket:",
                "http://",
                "https://",
                "file:",
                "link:",
                "portal:",
                "path:",
                "../",
                "./",
                "/",
            )
        )

    @property
    def is_unpinned(self) -> bool:
        """Whether the spec admits versions the author has not seen.

        Not a vulnerability on its own, and normal in a library. It matters for
        an application, where it means the artefact that was tested and the
        artefact that ships can differ.

        An inherited spec is not unpinned. The constraint exists, one file up,
        and reporting the member instead of the workspace root would put the
        finding where the fix cannot be made.
        """
        spec = self.spec.strip()
        if spec == WORKSPACE_INHERITED:
            return False
        if not spec or spec in {"*", "latest", "", "any"}:
            return True
        return spec.startswith(("^", "~", ">", "<")) and "==" not in spec


@dataclass(frozen=True, slots=True)
class Manifest:
    """A parsed dependency manifest."""

    path: str
    ecosystem: str
    name: str | None = None
    version: str | None = None
    dependencies: tuple[DeclaredDependency, ...] = ()
    hooks: tuple[Hook, ...] = ()
    overrides: Mapping[str, str] = field(default_factory=dict)
    """Version pins forced across the tree. Read because a pin written to
    satisfy an advisory can fall behind it and then hold a vulnerable version in
    place while reading as protective."""
    private: bool = False
    repository: str | None = None
    """The source repository the manifest claims.

    Read so it can be compared against what a registry records for the
    published artefact. A parser that cannot find one leaves it None, which is
    not the same as a mismatch and is never reported as one."""

    parse_error: str | None = None
    """Set when the file could not be parsed. Reported as an OPERATIONAL
    finding: a manifest that cannot be read is a manifest whose contents were
    not checked, and that must never look like a clean result."""

    includes: tuple[tuple[str, str], ...] = ()
    """Other files this one pulls in, as `(kind, relative path)`: `("requirements", ...)` for
    pip's `-r`, `("constraints", ...)` for `-c`. The engine reads each one the walk has, so a
    dependency named only in an included file is still graphed, and a constraint pins a range."""

    sources: tuple[str, ...] = ()
    """Package sources the file configures (pip `--index-url` / `--extra-index-url`, a Pipfile
    `[[source]]`, Composer `repositories`, Cargo `[registries]`): what dependency-confusion checks
    need to know about where resolution looks."""

    locked_by: str | None = None
    """The directory of the lockfile that resolves this manifest when it is not the manifest's own
    (an umbrella app's `lockfile: "../../mix.lock"`): its declarations join that lock."""

    override_origin: str | None = None
    """The file the `overrides` are written in, when it is not this one: a .NET project carries
    the transitive pins of the `Directory.Packages.props` above it."""

    source_patterns: Mapping[str, str] = field(default_factory=dict)
    """`package pattern -> source` the project's configuration routes packages to (NuGet package
    source mapping: `Acme.*` -> the internal feed). Applied to every package of the project the
    lockfile does not give a source for, transitive ones included."""

    shared_specs: Mapping[str, str] = field(default_factory=dict)
    """Constraints a workspace root defines once for its members (Cargo's
    `[workspace.dependencies]`, a .NET `Directory.Packages.props`, a Gradle version catalog): a
    member that writes `{ workspace = true }` or a version-less reference takes its constraint
    from here."""


@dataclass(frozen=True, slots=True)
class LockEntry:
    """One resolved package in a lockfile."""

    name: str
    version: str
    integrity: str | None = None
    resolved_from: str | None = None
    scope: Scope = Scope.RUNTIME
    dependencies: tuple[str, ...] = ()
    direct: bool = False

    license: str | None = None
    """As the lockfile itself declares it, verbatim -- not yet normalised or
    classified (see `intel/licenses.py`). Populated only where the format
    actually carries it (npm's v2/v3 `packages` map, from registry metadata
    npm cached at lock time); absent elsewhere rather than guessed."""

    local: bool = False
    """This entry is the project's own code, not something fetched.

    A workspace member, a path dependency, a linked package. It has no registry hash
    because there is nothing to hash against: the bytes are in the repository and are
    reviewed as source.

    Recorded by the parser rather than inferred downstream, because only the parser
    knows what an absent field means in its own format. In `Cargo.lock`, no `source`
    line means a local crate; in a `package-lock.json`, `"link": true` means the
    same thing; and in neither case does absence mean "from the registry, hash
    missing" -- which is what `POLICY.LOCKFILE.INTEGRITY.001` concluded for every
    Rust workspace on earth.
    """

    bundled: bool = False
    """This entry arrives inside another package's tarball.

    A package that declares `bundleDependencies` ships its dependencies inside its
    own archive, and npm records them in the lockfile at a nested path with no
    `resolved` and no `integrity` -- there is no separate download to hash. They are
    verified all the same, by the parent's hash, because they are bytes inside the
    file that hash covers.

    Recorded by the parser for the same reason `local` is: only the parser knows what
    an absent field means in its own format. `astral-sh/ruff` carries sixteen of them
    under `@tailwindcss/oxide-wasm32-wasi/node_modules/`, `iamkun/dayjs` two hundred
    and eight, and `POLICY.LOCKFILE.INTEGRITY.001` called every one a package pinned
    without a hash.
    """

    platform: tuple[str, ...] = ()
    """Conditions on where this resolution applies, as the lockfile records them."""

    alias: str | None = None
    """The name it is installed under when that is not its own (`"chalk-four": "npm:chalk@4"`).
    `name` is the package fetched, which advisories are about; this is what the project wrote."""

    deprecated: str | None = None
    """The lockfile's own record that the package is abandoned or deprecated, as a phrase."""

    ecosystem: str | None = None
    """The package's ecosystem when it is not the lockfile's own: a conda-lock file's pip entries
    are PyPI packages, matched against PyPI's advisories."""

    signatures: tuple[str, ...] = ()
    """Detached OpenPGP signatures recorded with the installed package (an Ansible collection's
    `.info/GALAXY.yml`), over `signed`."""

    signed: bytes | None = None
    """The exact bytes those signatures cover (the collection's MANIFEST.json)."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", Coordinate.token(self.name, Coordinate.MAX_NAME))
        object.__setattr__(self, "version", Coordinate.token(self.version, Coordinate.MAX_VERSION))
        object.__setattr__(self, "platform", Coordinate.conditions(self.platform))
        object.__setattr__(self, "integrity", Coordinate.integrity(self.integrity))
        if self.deprecated is not None:
            object.__setattr__(
                self, "deprecated", Coordinate.phrase(self.deprecated, Coordinate.MAX_SPEC) or None
            )
        if self.alias is not None:
            alias = Coordinate.token(self.alias, Coordinate.MAX_NAME)
            object.__setattr__(self, "alias", alias if alias and alias != self.name else None)


@dataclass(frozen=True, slots=True)
class LockGraph:
    """A parsed lockfile."""

    path: str
    ecosystem: str
    entries: tuple[LockEntry, ...] = ()
    parse_error: str | None = None
    workspaces: tuple[str, ...] = ()
    """Directories, relative to the lockfile's own, whose manifests this lockfile resolves:
    workspace members. Their manifests are joined to this graph rather than graphed again."""

    integrity_elsewhere: bool = False
    """The format keeps its hashes in a companion file (`go.mod` beside `go.sum`): a missing hash
    here is not missing, and is judged after the companion is applied."""

    companion: bool = False

    completed_by_companion: bool = False
    """The resolving file lists only what the project requires directly -- a `go.mod` written
    before Go 1.17, which leaves indirect modules out -- so a module its companion hashes and it
    does not list is part of the build, at the highest version hashed, and is added as indirect."""

    companion_tree: bool = False
    """The companion speaks for every project below its owner, not the owner alone: Maven's
    `.mvn/checksums/` at the root of a reactor build holds the checksums of every module's
    dependencies."""

    fragment: bool = False
    """One piece of a graph spread over many files -- an installed tree's per-package records,
    such as Homebrew's one INSTALL_RECEIPT.json per keg. The pieces with the same owner are
    joined into one graph before depths and paths are worked out, so an edge from one file
    reaches an entry in another."""

    owner_levels: int = 0
    """How many directories above the file the project it belongs to is: 2 for Maven's
    `.mvn/checksums/` and Gradle's legacy `gradle/dependency-locks/`, 1 for Gradle's
    `gradle/verification-metadata.xml`. 0: the file's own directory."""
    """This file records facts about another file's resolution, not a resolution of its own:
    `go.sum` holds hashes for what `go.mod` selects (and for versions it no longer does), and
    `vendor/modules.txt` says which of them were vendored. Its entries complete the matching
    entries of the resolving file -- integrity, a vendored source -- and add none of their own."""

    def __len__(self) -> int:
        return len(self.entries)


@runtime_checkable
class Ecosystem(Protocol):
    """One package ecosystem."""

    id: str
    purl_type: str
    manifest_globs: tuple[str, ...]
    lockfile_globs: tuple[str, ...]
    registry_hosts: frozenset[str]

    def parse_manifest(self, content: FileContent) -> Manifest: ...

    def parse_lockfile(self, content: FileContent) -> LockGraph: ...

    def normalize_name(self, name: str) -> str:
        """Fold a name to its canonical form for comparison."""
        ...

    def to_dependencies(
        self, graph: LockGraph, *, project: str | None = None
    ) -> tuple[Dependency, ...]:
        """Flatten a parsed lockfile into dependency records."""
        ...

    def is_registry_host(self, url: str | None) -> bool:
        """Whether a resolved URL points at this ecosystem's registry."""
        ...

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """Package URL qualifiers telling apart artefacts of one name and version."""
        ...


class BaseEcosystem:
    """Shared behaviour. Implementing the protocol directly is equally valid."""

    @staticmethod
    def _json_object(text: str) -> dict[str, Any]:
        """Decode JSON that is required to be an object at the top level.

        `json.loads` returns whatever the document says, and a manifest is only
        ever an object -- but `0` is valid JSON. Every parser here decoded
        straight into `data.get(...)`, so a `package-lock.json` containing one
        byte raised `AttributeError`. The engine catches broadly around
        detectors, so the visible effect was not a crash but a file quietly not
        examined and a scan marked incomplete: a blinding primitive costing an
        attacker one character.

        Raised as `ValueError` rather than returned as a sentinel, because every
        caller already catches `ValueError` alongside `JSONDecodeError` and
        turns it into a reported parse error. The failure then travels the path
        that was already correct.

        `tomllib.loads` cannot return a non-mapping, so the TOML parsers need no
        equivalent.
        """
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"top level is {type(data).__name__}, expected an object")
        return data

    @staticmethod
    def _err(content: FileContent, eco: str, message: str) -> Manifest:
        return Manifest(path=content.path, ecosystem=eco, parse_error=message)

    @staticmethod
    def _table_spec(value: object) -> str:
        if isinstance(value, dict):
            for key in ("version", "git", "url", "path", "hosted"):
                if key in value:
                    return str(value[key])
            # `{ workspace = true }` takes its version from the workspace root,
            # so the member declares no range of its own. Falling through to
            # `"*"` read that as "any version will do" and reported a pinned
            # dependency as unpinned in every member of every Cargo workspace.
            if value.get("workspace") is True:
                return WORKSPACE_INHERITED
            return "*"
        return str(value)

    @staticmethod
    def _s(value: object) -> str | None:
        return str(value) if isinstance(value, str) and value else None

    id: str = "base"
    purl_type: str = "generic"
    manifest_globs: tuple[str, ...] = ()
    lockfile_globs: tuple[str, ...] = ()
    registry_hosts: frozenset[str] = frozenset()
    records_integrity: bool = True
    """Whether this ecosystem's lock format records a per-package hash at all. Where it does
    not (an action ref, Helm's `Chart.lock`, a Galaxy requirements file), a missing hash is the
    format, not an anomaly, and the integrity rules say nothing about it."""

    # Lifecycle keys that execute around installation. An allowlist model is
    # used against these rather than a blocklist of dangerous commands: the
    # attack is *adding* a script, so enumerating known-bad commands is always a
    # step behind whoever is writing the next one.
    lifecycle_keys: frozenset[str] = frozenset()

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        raise NotImplementedError

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        raise NotImplementedError

    def purl(self, name: str, version: str | None = None) -> str:
        """Build a Package URL.

        The cross-ecosystem identity, so findings, advisories and threat
        intelligence correlate without per-ecosystem special cases.
        """
        base = f"pkg:{self.purl_type}/{name}"
        return f"{base}@{version}" if version else base

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """Package URL qualifiers that tell apart two artefacts of one name and version (Maven's
        `classifier` and `type`), from a record's conditions. Most ecosystems have none."""
        return ""

    def to_dependencies(
        self, graph: LockGraph, *, project: str | None = None
    ) -> tuple[Dependency, ...]:
        """Convert a lockfile into domain dependencies, computing depth.

        Depth is derived by walking outward from the direct dependencies rather
        than trusting any field in the file, because depth feeds the risk score
        and a lockfile is attacker-controlled input like everything else.
        """
        # Nodes are entries, not names: a lockfile can hold two versions of one package (the
        # root's ms 2.1.3 and debug's own ms 2.0.0), and keying by name merged them -- both
        # became direct, both took every parent. An edge names its child either by name (every
        # entry of that name) or as `name@version` when the parser knows exactly which one.
        # Matched by the ecosystem's own normalisation: a lockfile writes an edge as `django`
        # and the package as `Django`, or `typing_extensions` beside `typing-extensions`.
        entries = list(graph.entries)
        by_name: dict[str, list[int]] = {}
        by_key: dict[tuple[str, str], int] = {}
        for index, entry in enumerate(entries):
            normal = self.normalize_name(entry.name)
            by_name.setdefault(normal, []).append(index)
            by_key.setdefault((normal, entry.version), index)

        def children(entry: LockEntry) -> list[int]:
            out: list[int] = []
            for edge in entry.dependencies:
                # The last `@`: a name may hold one itself (`openssl@3@3.4.0`, `@scope/pkg@1.0`).
                at = edge.rfind("@")
                key = (self.normalize_name(edge[:at]), edge[at + 1 :]) if at > 0 else None
                if key is not None and key in by_key:
                    out.append(by_key[key])
                else:
                    out.extend(by_name.get(self.normalize_name(edge), ()))
            return out

        depths: dict[int, int] = {}
        parents: dict[int, set[str]] = {}
        frontier = [(i, 0) for i, e in enumerate(entries) if e.direct]
        if not frontier:
            # No direct markers: treat everything as depth zero rather than
            # silently reporting a flat graph as deeply nested.
            frontier = [(i, 0) for i in range(len(entries))]
        position = 0
        while position < len(frontier):
            index, depth = frontier[position]
            position += 1
            if depths.get(index, 1 << 30) <= depth:
                continue
            depths[index] = depth
            for child in children(entries[index]):
                parents.setdefault(child, set()).add(entries[index].name)
                if depths.get(child, 1 << 30) > depth + 1:
                    frontier.append((child, depth + 1))

        return tuple(
            Dependency(
                purl=(
                    f"pkg:{entry.ecosystem}/{entry.name}"
                    + (f"@{entry.version}" if entry.version else "")
                    if entry.ecosystem
                    else self.purl(entry.name, entry.version) + self.qualifiers(entry.platform)
                ),
                ecosystem=entry.ecosystem or self.id,
                name=entry.name,
                version=entry.version,
                direct=entry.direct,
                local=entry.local,
                depth=depths.get(index, 0),
                scope=entry.scope,
                resolved_from=entry.resolved_from,
                integrity=entry.integrity,
                parents=tuple(sorted(parents.get(index, ()))),
                project=project,
                license=entry.license,
                platform=entry.platform,
                alias=entry.alias,
                bundled=entry.bundled,
                deprecated=entry.deprecated,
                signatures=entry.signatures,
                signed=entry.signed,
            )
            for index, entry in sorted(
                enumerate(entries), key=lambda pair: (pair[1].name, pair[1].version)
            )
        )

    def is_registry_host(self, url: str | None) -> bool:
        """Whether a resolution points at this ecosystem's own registry.

        Any scheme counts, not only http. Checking for ``http://`` alone
        classified ``git+ssh://...`` as "not a URL, therefore the registry",
        which is exactly backwards: a git-over-SSH dependency is one of the
        clearest cases of resolution outside the registry, and treating it as
        internal silently disabled the provenance check for it.
        """
        if not url:
            return True  # nothing recorded means the default registry

        lowered = url.lower()

        # Anything naming a location outside the registry: a VCS reference, a
        # filesystem path, or a link protocol. Checked before the "no scheme"
        # shortcut, since `file:` and `git:` carry no `//`.
        if lowered.startswith(
            ("git@", "git:", "git+", "ssh://", "file:", "link:", "portal:", "path:")
        ):
            return False

        # A named registry (`registry:acme`, a Cargo `registry = "..."`, a private Hex
        # organisation, a NuGet source key) is a registry the project configured on purpose:
        # a registry, so not a "resolved from outside the registry" finding. Whether it is the
        # PUBLIC one is a different question -- `is_public_registry` -- that only the
        # dependency-confusion check asks.
        if lowered.startswith("registry:"):
            return True

        # A bare name with no scheme is a registry reference by definition.
        if "://" not in lowered:
            return True

        host = lowered.split("://", 1)[1].split("/", 1)[0]
        host = host.rpartition("@")[2]  # strip any userinfo
        return any(known in host for known in self.registry_hosts)

    def is_public_registry(self, url: str | None) -> bool:
        """Whether a resolution is this ecosystem's PUBLIC registry, where anyone can publish a
        name. A named registry is public only under the name that registry goes by (`hexpm`,
        `crates-io`, a Gemfile source block on rubygems.org); any other is the project's own."""
        if url and url.lower().startswith("registry:"):
            named = url.lower().removeprefix("registry:").strip()
            if "://" in named:
                host = named.split("://", 1)[1].split("/", 1)[0].rpartition("@")[2]
                return any(known in host for known in self.registry_hosts)
            return named in PUBLIC_REGISTRY_NAMES
        return self.is_registry_host(url)

    def lifecycle_hooks(self, scripts: Mapping[str, str], path: str) -> Iterable[Hook]:
        """Hooks among a manifest's scripts.

        Only the lifecycle keys, not every script. A `test` script runs when
        somebody chooses to run tests; a `postinstall` script runs whether they
        wanted it to or not.
        """
        for key, command in sorted(scripts.items()):
            if key in self.lifecycle_keys:
                yield Hook(
                    kind=key,
                    path=path,
                    name=key,
                    command=str(command),
                    ecosystem=self.id,
                )


__all__ = [
    "BaseEcosystem",
    "DeclaredDependency",
    "Ecosystem",
    "LockEntry",
    "LockGraph",
    "Manifest",
]
