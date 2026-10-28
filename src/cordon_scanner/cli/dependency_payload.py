"""A package whose payload is in a dependency it declares (review 98, class 2).

A delivery vehicle is a package with nothing to catch in its own files: it declares a dependency,
and the dependency carries the payload, so installing the vehicle installs the malware. Scanning the
vehicle alone can never see it. With a dependency source, each dependency the npm package declares
(`dependencies`, `optionalDependencies`) is resolved to the highest version its range accepts,
scanned with the same detectors, and when that scan calls the dependency's own content malicious
the vehicle is blocked too, naming the dependency:

```
   vehicle.tgz ── package.json declares ──► dep@range
                                              │ resolve: --dependency-store DIR (offline)
                                              │          or the registry (--online, sha512-checked)
                                              ▼
                                         scan dep.tgz ── malicious by its content? ──► MALWARE.DEPENDENCY.PAYLOAD.001
```

One level only: a dependency's own dependencies are not followed, and its known-malware intel and
policy findings do not count, so the rule measures content, never a label. A dependency that cannot
be resolved is skipped, never treated as clean or as malware.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import re
import tarfile
import urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    import argparse

    from cordon_scanner.foundation.models import Finding, ScanResult

RULE_ID = "MALWARE.DEPENDENCY.PAYLOAD.001"
#: Declared with the manifest rules (`ManifestDetector`), as the release-comparison rules are.
DETECTOR = "manifest"
#: More than this many declared dependencies are not all resolved: a vehicle declares a handful.
MAX_DEPENDENCIES = 32
MAX_MANIFEST_BYTES = 1 << 20
#: Findings that describe something other than the dependency's own bytes.
NOT_CONTENT = ("SECRET.", "POLICY.", "VULNERABLE.", "OPERATIONAL.", "SUSPECT.RELEASE.", RULE_ID)


class NpmRange:
    """npm's version-range grammar, the subset published manifests use: exact, `^`, `~`, the
    comparators, x-ranges, hyphen ranges, `||` and space-joined sets. Anything else (a git URL, a
    file path, an `npm:` alias, a tag other than `latest`) is not a registry range: None."""

    _VERSION = re.compile(
        r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$"
    )

    @classmethod
    def satisfies(cls, version: str, spec: str) -> bool | None:
        spec = spec.strip()
        if spec in ("", "*", "latest", "x", "X"):
            return "-" not in version
        if re.search(r"[:/#]", spec) or spec.startswith(
            ("file", "git", "http", "link", "workspace")
        ):
            return None
        alternatives = []
        for alternative in spec.split("||"):
            comparators = cls._comparators(alternative.strip())
            if comparators is None:
                return None
            alternatives.append(comparators)
        exact = any(any(op == "=" for op, _ in c) for c in alternatives)
        if "-" in version.split("+")[0] and not exact:
            return False
        return any(all(cls._holds(version, op, bound) for op, bound in c) for c in alternatives)

    @classmethod
    def _comparators(cls, text: str) -> list[tuple[str, str]] | None:
        hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", text)
        if hyphen:
            low, high = cls._parts(hyphen.group(1)), cls._parts(hyphen.group(2))
            if low is None or high is None:
                return None
            return [(">=", cls._floor(low)), *cls._upper(high, inclusive=True)]
        out: list[tuple[str, str]] = []
        for token in re.findall(r"(?:[<>]=?|=|\^|~>?)?\s*[^\s<>=^~]+", text) or [""]:
            match = re.fullmatch(r"([<>]=?|=|\^|~>?)?\s*(\S*)", token.strip())
            if match is None:
                return None
            op, raw = match.group(1) or "", match.group(2)
            parts = cls._parts(raw)
            if parts is None:
                return None
            out.extend(cls._expand(op, parts, raw))
        return out

    @classmethod
    def _parts(cls, raw: str) -> tuple[int | None, int | None, int | None, str] | None:
        match = cls._VERSION.match(raw)
        if match is None:
            return None
        nums = [None if g is None or g in "xX*" else int(g) for g in match.groups()[:3]]
        return nums[0], nums[1], nums[2], match.group(4) or ""

    @staticmethod
    def _floor(parts: tuple[int | None, int | None, int | None, str]) -> str:
        major, minor, patch, pre = parts
        text = f"{major or 0}.{minor or 0}.{patch or 0}"
        return f"{text}-{pre}" if pre else text

    @classmethod
    def _upper(
        cls, parts: tuple[int | None, int | None, int | None, str], *, inclusive: bool
    ) -> list[tuple[str, str]]:
        major, minor, patch, _ = parts
        if major is None:
            return []
        if minor is None:
            return [("<", f"{major + 1}.0.0-0")]
        if patch is None:
            return [("<", f"{major}.{minor + 1}.0-0")]
        return [("<=" if inclusive else "<", cls._floor(parts))]

    @classmethod
    def _expand(
        cls, op: str, parts: tuple[int | None, int | None, int | None, str], raw: str
    ) -> list[tuple[str, str]]:
        major, minor, patch, _ = parts
        floor = cls._floor(parts)
        if major is None:
            return []
        if op == "^":
            if major > 0 or minor is None:
                return [(">=", floor), ("<", f"{major + 1}.0.0-0")]
            if minor > 0 or patch is None:
                return [(">=", floor), ("<", f"0.{minor + 1}.0-0")]
            return [(">=", floor), ("<", f"0.0.{patch + 1}-0")]
        if op in ("~", "~>"):
            if minor is None:
                return [(">=", floor), ("<", f"{major + 1}.0.0-0")]
            return [(">=", floor), ("<", f"{major}.{minor + 1}.0-0")]
        if op in ("", "="):
            if minor is None or patch is None:
                return [(">=", floor), *cls._upper(parts, inclusive=True)]
            return [("=", floor)]
        if op in (">", "<="):
            if minor is None or patch is None:
                upper = cls._upper(parts, inclusive=True)
                return [(">=" if op == ">" else "<", upper[0][1])] if upper else []
            return [(op, floor)]
        return [(op, floor)]

    @staticmethod
    def _holds(version: str, op: str, bound: str) -> bool:
        from cordon_scanner.intel.advisories.versions import Versions

        order = Versions.compare("npm", version, bound)
        return {
            "=": order == 0,
            ">": order > 0,
            ">=": order >= 0,
            "<": order < 0,
            "<=": order <= 0,
        }[op]


@dataclass(frozen=True)
class Resolved:
    name: str
    version: str
    path: Path


class DependencyPayload:
    """Resolves and scans the dependencies one npm archive declares."""

    @staticmethod
    def add_argument(group: Any) -> None:
        group.add_argument(
            "--dependency-store",
            metavar="DIR",
            help=(
                "a directory of npm archives (npm/<name>@<version>.tgz, a scope's / written _) to "
                "resolve the scanned package's declared dependencies from; each is scanned, and "
                "one whose own content is malicious blocks this package "
                "(MALWARE.DEPENDENCY.PAYLOAD.001). With --online the registry is asked instead"
            ),
        )

    @staticmethod
    def declared(target: Path) -> dict[str, str]:
        """`{name: range}` from an npm archive's own top-level package.json."""
        try:
            with tarfile.open(target) as archive:
                for entry in archive:
                    parts = entry.name.split("/")
                    if entry.isfile() and len(parts) == 2 and parts[1] == "package.json":
                        if entry.size > MAX_MANIFEST_BYTES:
                            return {}
                        handle = archive.extractfile(entry)
                        manifest = json.loads(handle.read() if handle else b"{}")
                        break
                else:
                    return {}
        except (OSError, tarfile.TarError, ValueError, UnicodeDecodeError):
            return {}
        out: dict[str, str] = {}
        for key in ("dependencies", "optionalDependencies"):
            section = manifest.get(key) if isinstance(manifest, dict) else None
            if isinstance(section, dict):
                out.update({str(n): str(r) for n, r in section.items() if isinstance(r, str)})
        if isinstance(manifest, dict) and manifest.get("name") in out:
            out.pop(str(manifest["name"]))
        return dict(sorted(out.items())[:MAX_DEPENDENCIES])

    @staticmethod
    @functools.lru_cache(maxsize=4)
    def _held(store: Path) -> dict[str, dict[str, Path]]:
        """`{archive stem: {version: path}}` for a store, listed once: a store holds tens of
        thousands of archives, and listing it per dependency made one scan take minutes."""
        held: dict[str, dict[str, Path]] = {}
        for path in (store / "npm").iterdir() if (store / "npm").is_dir() else ():
            if not path.name.endswith(".tgz"):
                continue
            stem = path.name[: -len(".tgz")]
            for sep in ("@", "-"):
                # Every place the name could end: `a-b-1.0.0.tgz` is `a-b` at 1.0.0, never `a` at
                # `b-1.0.0`, which is not a version and is dropped below.
                start = 1 if stem.startswith("@") else 0
                index = stem.find(sep, start)
                while index > 0:
                    version = stem[index + 1 :]
                    if NpmRange._parts(version) is not None:
                        held.setdefault(stem[:index], {}).setdefault(version, path)
                    index = stem.find(sep, index + 1)
        return held

    @staticmethod
    def from_store(store: Path, name: str, spec: str) -> Resolved | None:
        """The highest held version the range accepts."""
        from cordon_scanner.intel.advisories.versions import Versions

        held = {
            v: p
            for v, p in DependencyPayload._held(store).get(name.replace("/", "_"), {}).items()
            if NpmRange.satisfies(v, spec)
        }
        if not held:
            return None
        best = max(held, key=lambda v: Versions.sort_key("npm", v))
        return Resolved(name, best, held[best])

    @staticmethod
    def from_registry(name: str, spec: str, into: Path) -> Resolved | None:
        """The highest published version the range accepts, sha512-checked."""
        from cordon_scanner.intel.advisories.versions import Versions
        from cordon_scanner.sources.previous import PreviousRelease

        document = PreviousRelease._document(
            f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"
        )
        versions = document.get("versions") or {}
        if spec.strip() == "latest":
            spec = str((document.get("dist-tags") or {}).get("latest") or "")
        accepted = [
            v for v in versions if NpmRange._parts(v) is not None and NpmRange.satisfies(v, spec)
        ]
        if not accepted:
            return None
        version = max(accepted, key=lambda v: Versions.sort_key("npm", v))
        dist = versions[version].get("dist") or {}
        integrity = str(dist.get("integrity") or "")
        if not integrity.startswith("sha512-"):
            return None
        blob = PreviousRelease._artefact(str(dist.get("tarball") or ""), "npm")
        if base64.b64encode(hashlib.sha512(blob).digest()).decode() != integrity[7:]:
            return None
        path = into / PreviousRelease._safe(f"{name.replace('/', '__')}-{version}.tgz")
        path.write_bytes(blob)
        return Resolved(name, version, path)

    @staticmethod
    def blocking(result: ScanResult, config: Any) -> list[Finding]:
        """The dependency's findings that call its own content malicious and trip the gate.

        Malicious only, never a suspicious heuristic: what a dependency's verdict does to the
        package declaring it, it does to every package that declares it. `vite` warns of an
        unexplained effect, and passing that on blocked a package of nothing but a tsconfig for
        depending on it (review 98); a suspicious finding stays the dependency's own to explain."""
        from cordon_scanner.decide.policy import PolicyGate

        return [
            f
            for f in result.findings
            if f.category is Category.MALICIOUS
            and PolicyGate._fails(f, config.policy)
            and not f.rule_id.startswith(NOT_CONTENT)
            and ".KNOWN" not in f.rule_id
        ]

    @staticmethod
    def finding(archive: str, dependency: Resolved, spec: str, cause: Finding) -> Finding:
        from cordon_scanner.engine.pipeline.operational import OperationalFinding

        path = f"{archive}!package/package.json" if archive else "package.json"
        base = OperationalFinding.build(
            path=path,
            rule_id=RULE_ID,
            message=(
                f"Declares the dependency {dependency.name} ({spec!r}, resolved to "
                f"{dependency.version}), whose own content is malicious: {cause.rule_id} in "
                f"{cause.location.path.rpartition('!')[2]}. Installing this package installs it."
            ),
            remediation=(
                "Do not install this package. Its own files may be harmless; what it installs is not. "
                "Read the named dependency's finding before allowing either."
            ),
            category=Category.MALICIOUS,
            severity=Severity.CRITICAL,
        )
        return replace(base, confidence=Confidence.HIGH, always_report=False, detector=DETECTOR)

    @classmethod
    def applied(
        cls, args: argparse.Namespace, target: Path, result: ScanResult, config: Any, selected: Any
    ) -> ScanResult:
        """The scan result, plus a block for each declared dependency blocked by its content."""
        import tempfile

        from cordon_scanner import Scanner
        from cordon_scanner.intel.malware.feed import FeedClient

        store = getattr(args, "dependency_store", None)
        online = bool(args.online) and not args.offline and not FeedClient.offline_requested()
        if (
            not target.is_file()
            or not (store or online)
            or not target.name.endswith((".tgz", ".tar.gz"))
        ):
            return result
        declared = cls.declared(target)
        if not declared:
            return result
        archive = next(
            (f.location.path.partition("!")[0] for f in result.findings if "!" in f.location.path),
            "",
        )
        added: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="cordon-deps-") as work:
            for name, spec in declared.items():
                try:
                    found = (
                        cls.from_store(Path(store), name, spec)
                        if store
                        else cls.from_registry(name, spec, Path(work))
                    )
                except (OSError, ValueError, KeyError):
                    found = None
                if found is None:
                    continue
                causes = cls.blocking(Scanner(config, detectors=selected).scan(found.path), config)
                if causes:
                    added.append(cls.finding(archive, found, spec, causes[0]))
        if not added:
            return result
        return replace(
            result,
            findings=tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value)),
        )
