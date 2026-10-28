"""Published packages with nothing in them but a name (review 98, REC-4).

A large share of the malicious packages in the public datasets carry no payload a content rule
could find. They are dependency-confusion probes (`@rb3ca/domains` 11.11.11, a `preinstall` that
only echoes `poc possible by golu`), brand-squats of a company's internal package names
(`epic-diesel-services` 1.0.0, nothing but a `package.json`), typosquats waiting for the typo
(`botocote`), and researchers' stubs. Measured on DataDog and malregistry (review 98, MEAS-4):
1,567 samples whose shape holds no code, or under 400 bytes of it with no network or process
primitive, and whose install hooks, if any, only print.

The evidence for those is the name and the metadata around it, so that is what this reads. Every
signal here already existed somewhere in the scanner or is one line of arithmetic on the manifest;
what is new is putting them in one place and grading them together, because none of them is
enough alone. An empty package is ordinary in the long tail (a `my-first-package` 1.0.0 is the
commonest shape on npm) and so is a high version number. A name that impersonates an organisation,
in a package that contains nothing and names no source, is not.

```
  name signals                content                      provenance
  (how the name was chosen)   (is there anything to run)   (who stands behind it)
  ------------------------    -------------------------    ----------------------
  typosquat of a popular      no code file at all          no repository, no homepage
  dependency-confusion        one code file, no hook       no description
    version (99.0.0, 7.7.7)     that runs a file
  says it is a PoC / bounty
  organisation's name, unscoped
  another registry's package
  internal-looking name
  install hook only prints
            \\                          |                          /
             +-------- one score: the weights in `NameRisk.WEIGHTS` -------+
                                        |
         BLOCK  only when no source is named, there is nothing to run (<= 3 code files,
                no dependency, no hook running a file), the package does not call itself
                a defensive placeholder, AND the name evidence is strong (a weight-3
                signal), or medium (2) in a package with no code and no description
         WARN   otherwise, when the score reaches 4 (or 3 with any name evidence)
```

Only a published package's own metadata is read, located the way the engine's own release check
(`ReleaseChecks.known_malicious_release`) locates it: an npm tarball's `package/package.json`, an sdist's
`<name>-<version>/PKG-INFO`, a wheel's `*.dist-info/METADATA`. A repository's root manifest is a
project, not a release, and an empty project is not suspicious.
"""

from __future__ import annotations

import html
import io
import json
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit, ScanContext

RULE: Final = "SUSPECT.PACKAGE.NAME_RISK.001"

CODE_SUFFIXES: Final = (
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".py",
    ".pyw",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".go",
    ".rs",
    ".pl",
    ".lua",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".node",
    ".wasm",
    ".jar",
    ".class",
    ".pyd",
    ".bin",
)
"""Files that run, or that something runs. A binary counts: a package holding only a native addon
is not empty, it is a package whose payload the binary rules read."""

NOT_CODE_SUFFIXES: Final = (".d.ts", ".d.mts", ".d.cts")
"""Type declarations: TypeScript reads them, nothing executes them."""

CONSUMER_HOOKS: Final = frozenset({"preinstall", "install", "postinstall"})


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    """What a published package says about itself, and how much there is in it."""

    ecosystem: str
    name: str
    version: str
    description: str
    has_source: bool
    """A repository or homepage is named. Either is somewhere a reader can go and look."""
    hooks: tuple[tuple[str, str], ...]
    """`(lifecycle name, command)` for each install-time hook the consumer's installer runs."""
    code_files: int
    """Files under the package root that run (see `CODE_SUFFIXES`). For a Python package the root
    `setup.py` and every `__init__.py` are not counted: an sdist always has the first, and the
    second is how a directory becomes a package. What they contain is read by the content rules."""
    hook_runs_file: bool
    """An install hook names a file in the package to run."""
    dependencies: int = 0
    """Runtime dependencies declared. A package that is only a list of dependencies is a
    meta-package: what it installs is its payload, and it is not empty."""
    placeholder: bool = False
    """npm's own `0.0.1-security` stand-in for a removed package. Never reported here: there is
    nothing in it, and the engine answers the name from the malicious-package records."""


@dataclass(frozen=True, slots=True)
class Signal:
    """One piece of evidence and its weight in `NameRisk.WEIGHTS`."""

    id: str
    kind: str
    """`name`, `content` or `provenance`."""
    weight: int
    reason: str


@dataclass(frozen=True, slots=True)
class Assessment:
    signals: tuple[Signal, ...]
    blocks: bool

    @property
    def score(self) -> int:
        return sum(s.weight for s in self.signals)

    @property
    def name_weight(self) -> int:
        return sum(s.weight for s in self.signals if s.kind == "name")


class PackageIdentities:
    """Reading a published package's own metadata into a `PackageIdentity`."""

    #: A Python sdist's root directory, `<name>-<version>`, the convention `Engine` also keys on.
    _VERSIONED_DIRECTORY: ClassVar[re.Pattern[str]] = re.compile(r"-\d")

    @staticmethod
    def own_metadata(unit: FileUnit, ctx: ScanContext) -> str | None:
        """`npm` or `pypi` when this file is a published package's own metadata, else None."""
        if ctx.repository is not None and ctx.repository.scanned_repository_root:
            # A working tree: its manifest is the project's, and an empty project is a new one.
            return None
        member = unit.path.rpartition("!")[2]
        if "node_modules/" in f"/{member}" or "site-packages/" in member:
            return None
        parts = member.split("/")
        if member.lower().endswith(".nuspec") and len(parts) == 1:
            # A .nupkg's own `<id>.nuspec`, at the package root.
            return "nuget"
        if member == "metadata.gz" and unit.path.rpartition("!")[0].lower().endswith(".gem"):
            # A .gem's gemspec, gzipped YAML beside `data.tar.gz`.
            return "rubygems"
        if len(parts) < 2:
            return None
        parent, name = parts[-2], parts[-1]
        if name == "package.json" and parent == "package":
            return "npm"
        if (
            name == "PKG-INFO"
            and not parent.endswith(".egg-info")
            and PackageIdentities._VERSIONED_DIRECTORY.search(parent)
        ) or (name == "METADATA" and parent.endswith(".dist-info")):
            return "pypi"
        return None

    @staticmethod
    def _root(unit: FileUnit) -> str:
        """The directory the package's files sit under: the manifest's own for npm and an sdist,
        the `.dist-info`'s parent for a wheel."""
        directory = posixpath.dirname(unit.path)
        if directory.endswith(".dist-info"):
            directory = posixpath.dirname(directory)
            # DataDog's exploded wheels repeat the member as a directory
            # (`x-1.0.dist-info/METADATA/x-1.0.dist-info/METADATA`): the root is above the first.
            while ".dist-info/" in directory + "/":
                directory = directory[: directory.index(".dist-info")].rpartition("/")[0]
        return directory

    @staticmethod
    def _code_files(unit: FileUnit, ctx: ScanContext, python: bool) -> int:
        root = PackageIdentities._root(unit)
        prefix = f"{root}/" if root else ""
        count = 0
        for path in ctx.tree_paths:
            if not path.startswith(prefix) or path == unit.path:
                continue
            relative = path[len(prefix) :]
            lowered = relative.lower()
            if "node_modules/" in f"/{lowered}" or lowered.endswith(NOT_CODE_SUFFIXES):
                continue
            if not lowered.endswith(CODE_SUFFIXES):
                continue
            if python and (posixpath.basename(lowered) == "__init__.py" or lowered == "setup.py"):
                continue
            count += 1
        return count

    @classmethod
    def read(cls, unit: FileUnit, ctx: ScanContext) -> PackageIdentity | None:
        kind = cls.own_metadata(unit, ctx)
        if kind == "npm":
            return cls._npm(unit, ctx)
        if kind == "pypi":
            return cls._pypi(unit, ctx)
        if kind == "nuget":
            return cls._nuget(unit, ctx)
        if kind == "rubygems":
            return cls._rubygems(unit, ctx)
        return None

    @staticmethod
    def _xml_text(text: str, tag: str) -> str:
        found = re.search(rf"<(?:\w+:)?{tag}\b[^>]*>([^<]{{0,4000}})</(?:\w+:)?{tag}>", text)
        return html.unescape(found.group(1).strip()) if found else ""

    @classmethod
    def _nuget(cls, unit: FileUnit, ctx: ScanContext) -> PackageIdentity | None:
        text = unit.content.text[:200_000]
        name = cls._xml_text(text, "id")
        if not name:
            return None
        repository = re.search(r"<(?:\w+:)?repository\b[^>]*\burl=\"([^\"]+)\"", text)
        project = cls._xml_text(text, "projectUrl")
        root = cls._root(unit)
        prefix = f"{root}/" if root else ""
        # What NuGet runs on the consumer's side: Visual Studio's `tools/install.ps1`/`init.ps1`,
        # and the `build/` `.targets` and `.props` every referencing project imports.
        runs = any(
            path.startswith(prefix)
            and re.match(
                r"(?i)^(?:tools/(?:init|install)\.ps1|build(?:transitive|multitargeting)?/.+\.(?:targets|props))$",
                path[len(prefix) :],
            )
            for path in ctx.tree_paths
        )
        return PackageIdentity(
            ecosystem="nuget",
            name=name.strip().lower(),
            version=cls._xml_text(text, "version"),
            description=cls._xml_text(text, "description") or cls._xml_text(text, "summary"),
            has_source=bool(repository or project),
            hooks=(),
            code_files=cls._code_files(unit, ctx, python=False),
            hook_runs_file=runs,
            dependencies=len(re.findall(r"<(?:\w+:)?dependency\b", text)),
        )

    @classmethod
    def _rubygems(cls, unit: FileUnit, ctx: ScanContext) -> PackageIdentity | None:
        import gzip
        import zlib

        try:
            with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw[:2_000_000])) as handle:
                text = handle.read(1_000_000).decode("utf-8", "replace")
        except (OSError, EOFError, zlib.error):
            return None
        name = re.search(r"(?m)^name:[ \t]*(\S+)", text)
        if name is None:
            return None
        version = re.search(
            r"(?m)^version:\s*!ruby/object:Gem::Version\s*\n\s+version:\s*['\"]?([^'\"\s]+)", text
        )
        # `[ \t]*`, never `\s*`: an empty field must not read the next line as its value.
        description = re.search(r"(?m)^(?:summary|description):[ \t]*(\S.*)$", text)
        homepage = re.search(r"(?m)^homepage:[ \t]*(\S+)", text)
        source = re.search(r"(?m)^[ \t]+(?:source_code_uri|homepage_uri):[ \t]*(\S+)", text)
        extensions = re.search(r"(?m)^extensions:\s*\n\s*-\s*\S", text)
        runtime = re.findall(r"(?m)^\s+type:\s*:runtime\b", text)
        value = description.group(1).strip().strip("'\"") if description else ""
        return PackageIdentity(
            ecosystem="rubygems",
            name=name.group(1).strip("'\"").lower(),
            version=version.group(1) if version else "",
            description="" if value in ("", "null", "~") else value,
            has_source=bool((homepage and homepage.group(1) not in ("null", "~", "''")) or source),
            hooks=(),
            code_files=cls._code_files(unit, ctx, python=False),
            # A native extension is built, by running its extconf, on the installing machine.
            hook_runs_file=bool(extensions),
            dependencies=len(runtime),
        )

    @classmethod
    def _npm(cls, unit: FileUnit, ctx: ScanContext) -> PackageIdentity | None:
        try:
            data = json.loads(unit.content.text)
        except ValueError:
            return None
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            return None
        raw_scripts = data.get("scripts")
        scripts: dict[str, object] = raw_scripts if isinstance(raw_scripts, dict) else {}
        hooks = tuple(
            (key, value)
            for key, value in sorted(scripts.items())
            if key in CONSUMER_HOOKS and isinstance(value, str) and value.strip()
        )
        version = str(data.get("version", ""))
        description = data.get("description")
        root = cls._root(unit)
        prefix = f"{root}/" if root else ""
        tokens = {
            re.sub(r"^(?:\./)+", "", token.strip("\"'`()"))
            for _, command in hooks
            for token in re.split(r"[\s;|&]+", command)
            if token.strip()
        }
        runs_file = any(
            path.startswith(prefix) and re.sub(r"^(?:\./)+", "", path[len(prefix) :]) in tokens
            for path in ctx.tree_paths
        )
        return PackageIdentity(
            ecosystem="npm",
            name=data["name"].strip().lower(),
            version=version,
            description=description.strip() if isinstance(description, str) else "",
            has_source=bool(data.get("repository") or data.get("homepage")),
            hooks=hooks,
            code_files=cls._code_files(unit, ctx, python=False),
            hook_runs_file=runs_file,
            dependencies=sum(
                len(data[field])
                for field in ("dependencies", "optionalDependencies")
                if isinstance(data.get(field), dict)
            ),
            placeholder=version.endswith("-security")
            and isinstance(description, str)
            and description.strip().lower() == "security holding package",
        )

    @classmethod
    def _pypi(cls, unit: FileUnit, ctx: ScanContext) -> PackageIdentity | None:
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        head = unit.content.text[:20000].split("\n\n", 1)[0]
        fields: dict[str, list[str]] = {}
        for line in head.splitlines():
            key, sep, value = line.partition(":")
            if sep and not line[:1].isspace():
                fields.setdefault(key.strip().lower(), []).append(value.strip())
        name = (fields.get("name") or [""])[0]
        if not name:
            return None
        ecosystem = EcosystemRegistry.get("pypi")
        urls = [u for u in fields.get("home-page", []) if u and u.upper() != "UNKNOWN"]
        urls += fields.get("project-url", []) + [
            u for u in fields.get("download-url", []) if u and u.upper() != "UNKNOWN"
        ]
        summary = (fields.get("summary") or [""])[0]
        return PackageIdentity(
            ecosystem="pypi",
            name=ecosystem.normalize_name(name) if ecosystem else name.lower(),
            version=(fields.get("version") or [""])[0],
            description="" if summary.upper() == "UNKNOWN" else summary,
            has_source=bool(urls),
            hooks=(),
            code_files=cls._code_files(unit, ctx, python=True),
            hook_runs_file=False,
            dependencies=len(
                [
                    r
                    for r in fields.get("requires-dist", [])
                    if "extra ==" not in r.replace("'", '"')
                ]
            ),
        )


class NameSignals:
    """Each signal on its own, so each can be tested and measured on its own."""

    #: Says, in its own description or install output, that it is a probe. A defensive claim
    #: ("reserved to prevent dependency confusion") says it too, and is `HOLDING` below.
    RESEARCH: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\bpoc\b|proof[ -]of[ -]concept|dependency[ -]confusion|bug[ -]?bount|hackerone"
        r"|bugcrowd|intigriti|yeswehack|security research|research purpose|\bpentest|hijack"
        r"|(?:injection|rce|takeover|poc) (?:is )?possible|\boast(?:ify)?\b|interactsh|burp ?collab"
    )
    #: A name claimed so nobody else can claim it. Empty by design, so empty is not evidence.
    HOLDING: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\b(?:reserved|placeholder|prevent(?:s|ing)?|protect(?:s|ing)?|mitigat\w*|defensive"
        r"|squat\w*|claim(?:ed)?|namespace|dummy|stub|holding"
        # A name its owner has retired or moved: the tombstone, the migration stub that tells
        # the installer where the package went, the release pulled for being published in error.
        r"|tombstone|withdrawn|deprecated|no longer (?:maintained|supported)|migrat\w*"
        r"|published in error|private registry)\b"
        # The owner's security contact, given in place of a description.
        r"|\bsecurity@[\w-]+\.[\w.-]+"
    )
    #: Words that name something as a company's own and not for publication.
    INTERNAL: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|[-_./@])(?:internal|private|corp|intranet|inhouse|confidential|nonprod)(?:$|[-_./])"
    )
    #: The kinds of slip nobody makes by accident (see `DependencyDetector._slip_kind`).
    DELIBERATE_SLIPS: ClassVar[frozenset[str]] = frozenset(
        {"transposition", "doubled", "homoglyph"}
    )

    @staticmethod
    def mixed_script(name: str) -> str | None:
        """The other script when a name mixes Latin letters with Cyrillic or Greek ones.

        `Micr\u043esoft.EntetyFrameworkCore` on NuGet spells its `o` as Cyrillic U+043E: it reads as
        Microsoft's and sorts beside it, and no one types it by accident (review 98). A name
        written wholly in another script is that script's, and is not this."""
        latin = other = False
        found = ""
        for char in name:
            if not char.isalpha():
                continue
            script = unicodedata.name(char, "").split(" ", 1)[0]
            if script == "LATIN":
                latin = True
            elif script in ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"):
                other, found = True, script.capitalize()
        return found if latin and other else None

    @staticmethod
    def confusion_version(version: str) -> str | None:
        """Why this version looks chosen to outrank a private registry's, or None.

        A dependency-confusion probe has to win the resolver's comparison against the internal
        package it imitates, whose version it does not know, so it picks one nobody reaches:
        99.0.0, 999.9.9, 1000.0.0, or a run of one digit (7.7.7, 11.11.11). Calendar versions
        (2024.1.0, 202606.4.3555) are high for a different reason and are not counted.
        """
        found = re.match(r"^v?(\d{1,12})\.(\d{1,12})\.(\d{1,12})", version.strip())
        if found is None:
            return None
        major, minor, patch = (int(x) for x in found.groups())
        calendar = 1990 <= major <= 2100 or major >= 199000
        if major >= 90 and not calendar:
            return f"major version {major}"
        if major == minor == patch and major >= 4:
            return f"version {major}.{major}.{major}"
        if major in (9, 99, 999) and minor in (9, 99, 999):
            return f"version {found.group(0)}"
        return None

    @staticmethod
    def typosquat(identity: PackageIdentity) -> tuple[str, bool] | None:
        """`(popular name, deliberate)` when the name is a slip of a popular package's."""
        from cordon_scanner.detect.supply.dependency import DependencyDetector

        if identity.name in NameSignals._known(identity.ecosystem):
            return None
        target = DependencyDetector._typosquat_target(identity.ecosystem, identity.name)
        if target is None:
            return None
        deliberate = not identity.name.isascii() or (
            DependencyDetector._slip_kind(identity.name, target) in NameSignals.DELIBERATE_SLIPS
        )
        return target, deliberate

    @staticmethod
    def organisation(identity: PackageIdentity) -> str | None:
        """The npm organisation an unscoped name borrows, when the name is not itself known.

        On npm an organisation publishes under its scope (`@adobe/alloy`), which nobody else can
        publish to. The same words without the scope (`adobe-alloy`, `airbnb-types`) are open to
        anyone, and are what a brand-squat or a confusion probe for that company's internal
        packages registers. The scopes are those of the established packages the scanner ships.
        """
        if identity.ecosystem != "npm" or identity.name.startswith("@"):
            return None
        if identity.name in NameSignals._known("npm"):
            return None
        scopes = NameSignals._npm_scopes()
        leading = re.split(r"[-_.]", identity.name, maxsplit=1)[0]
        if leading != identity.name and leading in scopes:
            return leading
        return None

    @staticmethod
    def foreign(identity: PackageIdentity) -> str | None:
        """Another registry where this name is an established package, when it is not one here.

        `nokogiri`, `wasm-bindgen` and `pyrefly` published empty to npm; `musl-dev` and `libc-dev`
        to PyPI. A name that means something elsewhere and nothing here is what a cross-ecosystem
        confusion probe looks like.
        """
        if identity.name.startswith("@") or len(identity.name) < 4:
            return None
        if identity.name in NameSignals._known(identity.ecosystem):
            return None
        others = ("pypi", "rubygems", "cargo") if identity.ecosystem == "npm" else ("npm", "cargo")
        for other in others:
            if identity.name in NameSignals._known(other):
                return other
        return None

    @staticmethod
    def prints_only(identity: PackageIdentity) -> bool:
        """Every install hook only prints or exits: the PoC that proves it ran and does nothing."""
        from cordon_scanner.detect.supply.manifest import ManifestScripts

        if not identity.hooks:
            return False
        for _, command in identity.hooks:
            parts = [p.strip() for p in re.split(r"&&|\|\||;|\n", command) if p.strip()]
            if not parts or not all(
                ManifestScripts._only_prints(p) or p in ("true", ":", "exit 0") for p in parts
            ):
                return False
        return True

    CONVENTION: ClassVar[int] = 3
    """Established unscoped packages sharing a scope's name as their prefix, from which the
    prefix is a convention rather than a brand."""
    _SCOPES: ClassVar[frozenset[str] | None] = None
    _KNOWN: ClassVar[dict[str, frozenset[str]]] = {}

    @classmethod
    def _npm_scopes(cls) -> frozenset[str]:
        if cls._SCOPES is None:
            known = NameSignals._known("npm")
            # Four characters or more: `@ai`, `@cf` and `@nx` are words more than they are brands.
            scopes = {
                name[1:].split("/", 1)[0]
                for name in known
                if name.startswith("@") and len(name[1:].split("/", 1)[0]) >= 4
            }
            # And not a naming convention. `babel-preset-*`, `eslint-config-*`, `expo-*`,
            # `next-*` and `parcel-*` are how an ecosystem names its plugins, so established
            # unscoped packages already carry the prefix; `adobe-*` and `airbnb-*` are not. Of
            # the long tail's 76 blocks before this, 20 were such conventional names.
            prefixed: dict[str, int] = {}
            for name in known:
                if not name.startswith("@"):
                    leading = re.split(r"[-_.]", name, maxsplit=1)[0]
                    if leading != name:
                        prefixed[leading] = prefixed.get(leading, 0) + 1
            cls._SCOPES = frozenset(
                s for s in scopes if prefixed.get(s, 0) < NameSignals.CONVENTION
            )
        return cls._SCOPES

    @classmethod
    def _known(cls, ecosystem: str) -> frozenset[str]:
        """Every name `PackageIntel.is_known_package` accepts, normalised once per process.

        The same three sources (popular set, shipped allowlist, curated neighbours); asking
        `is_known_package` instead re-normalises its whole allowlist for every name it does not
        find, which is most of the names this module asks about."""
        cached = cls._KNOWN.get(ecosystem)
        if cached is None:
            from cordon_scanner.ecosystems.registry import EcosystemRegistry
            from cordon_scanner.intel.registries.popular import PackageIntel
            from cordon_scanner.intel.registries.real import RealPackages

            implementation = EcosystemRegistry.get(ecosystem)
            names = (
                RealPackages.real_packages(ecosystem)
                | PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset())
                | PackageIntel._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())
            )
            cached = frozenset(
                implementation.normalize_name(n) if implementation else n.lower() for n in names
            )
            cls._KNOWN[ecosystem] = cached
        return cached


class NameRisk:
    """The weighted table, and the decision."""

    WEIGHTS: ClassVar[dict[str, int]] = {
        # name: how the name was chosen. 3 is strong, 2 is medium.
        "typosquat-deliberate": 3,
        "mixed-script": 3,
        "confusion-version": 3,
        "says-research": 3,
        "hook-only-prints": 3,
        "typosquat": 2,
        "organisation-name": 2,
        "foreign-name": 2,
        "internal-name": 2,
        "says-holding": 1,
        # content: is there anything to run
        "empty": 2,
        "one-file": 1,
        # provenance: who stands behind it
        "no-source": 1,
        "no-description": 1,
    }
    """Hand-set from what each signal costs and buys, measured on every long-tail unit and every
    no-payload DataDog and malregistry sample (review 98, REC-4), not fitted.

    Strong (3): in a sourceless package with almost nothing in it, each is a few in ten thousand
    long-tail releases (a confusion version 27 of 162,499, a self-declared probe 9, an install
    hook that only prints 5) and each is a probe's whole method. Medium (2): an organisation's
    name outside its scope, another registry's established name, an internal-looking name, an
    accidental-looking slip -- each a few hundred long-tail releases, nearly all of them someone's
    first package, so they block only with no code and no description as well. `says-holding` is
    a claim to be a defensive placeholder: 1, and it vetoes the block, because those are what an
    organisation publishes to protect its names (2,218 long-tail npm releases describe themselves
    that way). Content and provenance alone are common -- 2.6% of the long tail is empty and names
    no source -- and are reported, below the gate, only when they add up to `WARN_SCORE`."""

    WARN_SCORE: ClassVar[int] = 4
    """Recorded at LOW from here, or from 3 when any name signal is among the evidence."""
    STRONG: ClassVar[int] = 3
    MAX_CODE_FILES_TO_BLOCK: ClassVar[int] = 3
    """"Nothing to run", as far as a reader of paths can tell: at most three code files, no
    dependency and no install hook that runs a file. The files themselves are read by the content
    rules, which grade whatever is in them on its own merits."""

    @classmethod
    def signals(cls, identity: PackageIdentity) -> tuple[Signal, ...]:
        out: list[Signal] = []

        def add(signal: str, kind: str, reason: str) -> None:
            out.append(Signal(signal, kind, cls.WEIGHTS[signal], reason))

        squat = NameSignals.typosquat(identity)
        if squat is not None:
            target, deliberate = squat
            add(
                "typosquat-deliberate" if deliberate else "typosquat",
                "name",
                f"one slip from the popular {target!r}",
            )
        scripts = NameSignals.mixed_script(identity.name)
        if scripts is not None:
            add("mixed-script", "name", f"spells its name with {scripts} letters among Latin ones")
        version = NameSignals.confusion_version(identity.version)
        if version is not None:
            add("confusion-version", "name", f"{version}, a dependency-confusion version")
        said = " ".join([identity.description, *(command for _, command in identity.hooks)])
        holding = bool(NameSignals.HOLDING.search(identity.description))
        # The claim is also made where the owner sends the installer elsewhere ("please use the
        # private registry" in the install output) or in the name itself
        # (`@corp-internal/placeholder`). Only the description outranks a probe's own words.
        retired = bool(
            NameSignals.HOLDING.search(
                " ".join(
                    [
                        *(command for _, command in identity.hooks),
                        re.sub(r"[-_./@]", " ", identity.name),
                    ]
                )
            )
        )
        if NameSignals.RESEARCH.search(said) and not holding:
            add("says-research", "name", "describes itself as a proof of concept or a probe")
        elif holding or retired:
            add("says-holding", "name", "describes itself as a reserved or placeholder name")
        organisation = NameSignals.organisation(identity)
        if organisation is not None:
            add("organisation-name", "name", f"borrows the npm organisation @{organisation}")
        foreign = NameSignals.foreign(identity)
        if foreign is not None:
            add("foreign-name", "name", f"an established {foreign} package's name")
        if NameSignals.INTERNAL.search(identity.name):
            add("internal-name", "name", "named as a company's internal package")
        if NameSignals.prints_only(identity):
            add("hook-only-prints", "name", "its install hook only prints")
        if not identity.dependencies and not identity.hook_runs_file:
            if identity.code_files == 0:
                add("empty", "content", "contains no code")
            elif identity.code_files == 1:
                add("one-file", "content", "contains a single code file")
        if not identity.has_source:
            add("no-source", "provenance", "names no repository or homepage")
        if not identity.description or identity.description.lower() == identity.name:
            add("no-description", "provenance", "has no description")
        return tuple(out)

    @classmethod
    def assess(cls, identity: PackageIdentity) -> Assessment | None:
        """The verdict, or None when the package does not reach the warning threshold."""
        if identity.placeholder:
            return None
        signals = cls.signals(identity)
        assessment = Assessment(signals=signals, blocks=False)
        ids = {s.id for s in signals}
        name = assessment.name_weight
        if assessment.score < cls.WARN_SCORE and not (name and assessment.score >= 3):
            return None
        strongest = max((s.weight for s in signals if s.kind == "name"), default=0)
        nothing_to_run = (
            identity.code_files <= cls.MAX_CODE_FILES_TO_BLOCK
            and not identity.dependencies
            and not identity.hook_runs_file
        )
        blocks = (
            nothing_to_run
            and "no-source" in ids
            and "says-holding" not in ids
            and (
                strongest >= cls.STRONG
                or (strongest == 2 and "empty" in ids and "no-description" in ids)
            )
        )
        return Assessment(signals=signals, blocks=blocks)


__all__ = [
    "RULE",
    "Assessment",
    "NameRisk",
    "NameSignals",
    "PackageIdentities",
    "PackageIdentity",
    "Signal",
]
