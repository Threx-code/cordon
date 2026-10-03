"""Moving one dependency to a safe version in a repository's lockfile and manifest (G18 fix pull requests).

The runner does this inside the customer's network; Cordon Cloud only names the change and opens the
pull request afterwards. Nothing is executed: no package manager, no install script, no code from the
package. The new lockfile entry is written from values the cloud took from the public registry, and
every one of them is checked here first - an npm `resolved` URL must be the registry's own tarball for
exactly this package and version, an `integrity` must be a sha512, PyPI hashes must be sha256 - so a
compromised control plane cannot point a lockfile anywhere else.

Changes it makes, and only these:

* npm (lockfile v2 or v3): every `node_modules/<name>` entry at the old version gets the new version,
  resolved URL and integrity, in `package-lock.json` or `npm-shrinkwrap.json` (and the v2 legacy
  `dependencies` tree). A manifest that pins the old version exactly, or with `^`/`~`, moves with it.
  Refused when the new version's own dependencies differ from the old one's: that needs npm to
  resolve again, which this does not do.
* PyPI: requirements files pinning `name==old` move to `name==new`; a pin carrying `--hash` lines gets
  the new version's hashes.

Anything else (an npm v1 lockfile, a poetry or uv lock, no matching entry) is refused with the
command a person would run instead.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from cordon_scanner.cloud.runner import JobRefused

_NPM_NAME: Final = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_!-]{0,63}$")
_BRANCH: Final = re.compile(r"^cordon/fix-[A-Za-z0-9._-]{1,140}$")
_INTEGRITY: Final = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
#: Lockfiles and requirements are looked for this deep, never inside these.
MAX_DEPTH: Final = 4
SKIP_DIRS: Final = frozenset(
    {"node_modules", ".git", ".venv", "venv", "env", "__pycache__", "vendor", "dist", "build"}
)
MAX_FILES: Final = 200


class FixRefused(JobRefused):
    """This change cannot be made safely here; the message says what to do instead."""


@dataclass(frozen=True)
class FixSpec:
    ecosystem: str
    name: str
    from_version: str
    to_version: str
    branch: str
    commit_message: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_options(cls, options: dict[str, Any]) -> FixSpec:
        """The job's options, every field checked. A value that is not exactly what it should be is
        a refusal, before anything is cloned."""
        ecosystem = str(options.get("ecosystem", ""))
        name = str(options.get("name", ""))
        old, new = str(options.get("from_version", "")), str(options.get("to_version", ""))
        branch = str(options.get("branch", ""))
        message = str(options.get("commit_message", ""))[:200].replace("\n", " ").strip()
        raw_payload = options.get("payload")
        payload: dict[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}
        if ecosystem not in ("npm", "pypi"):
            raise FixRefused(f"this runner makes fixes for npm and PyPI, not {ecosystem!r}")
        if not (_NPM_NAME if ecosystem == "npm" else _PYPI_NAME).match(name):
            raise FixRefused("the fix names a package this runner will not write into a lockfile")
        if not _VERSION.match(old) or not _VERSION.match(new) or old == new:
            raise FixRefused("the fix's versions are not two different versions")
        if not _BRANCH.match(branch) or ".." in branch:
            raise FixRefused("the fix's branch is not a cordon/fix-* branch")
        if not message:
            raise FixRefused("the fix has no commit message")
        if ecosystem == "npm":
            resolved, integrity = (
                str(payload.get("resolved", "")),
                str(payload.get("integrity", "")),
            )
            bare = name.split("/")[-1]
            parts = urlsplit(resolved)
            if (
                parts.scheme != "https"
                or parts.hostname != "registry.npmjs.org"
                or parts.query
                or parts.fragment
                or parts.path != f"/{name}/-/{bare}-{new}.tgz"
            ):
                raise FixRefused(
                    "the fix's resolved URL is not the registry's tarball for this version"
                )
            if not _INTEGRITY.match(integrity):
                raise FixRefused("the fix's integrity is not a sha512")
            for key in ("dependencies_from", "dependencies_to"):
                value = payload.get(key)
                if value is not None and not (
                    isinstance(value, dict)
                    and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
                ):
                    raise FixRefused("the fix's dependency lists are malformed")
        else:
            hashes = payload.get("hashes")
            if (
                not isinstance(hashes, list)
                or not 1 <= len(hashes) <= 200
                or not all(isinstance(h, str) and _SHA256.match(h) for h in hashes)
            ):
                raise FixRefused("the fix's file hashes are not sha256 digests")
        return cls(ecosystem, name, old, new, branch, message, dict(payload))


class DependencyFixer:
    """Apply a `FixSpec` to a checked-out repository. Returns the files changed, relative to it."""

    @staticmethod
    def _files(
        repo: Path, names: tuple[str, ...], pattern: re.Pattern[str] | None = None
    ) -> list[Path]:
        found: list[Path] = []
        stack = [(repo, 0)]
        while stack and len(found) < MAX_FILES:
            directory, depth = stack.pop()
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_symlink():
                    continue  # never follow a link out of the clone
                if entry.is_dir():
                    if depth < MAX_DEPTH and entry.name not in SKIP_DIRS:
                        stack.append((entry, depth + 1))
                elif entry.name in names or (pattern is not None and pattern.match(entry.name)):
                    found.append(entry)
        return sorted(found)

    @staticmethod
    def _dump(original: str, document: Any) -> str:
        """JSON written back with the file's own indentation and trailing newline."""
        match = re.search(r"\n([ \t]+)\"", original)
        text = json.dumps(document, indent=match.group(1) if match else "  ", ensure_ascii=False)
        return text + ("\n" if original.endswith("\n") else "")

    # -- npm -----------------------------------------------------------------------------

    @staticmethod
    def _npm_entry(entry: Any, spec: FixSpec) -> bool:
        if not isinstance(entry, dict) or entry.get("version") != spec.from_version:
            return False
        entry["version"] = spec.to_version
        entry["resolved"] = spec.payload["resolved"]
        entry["integrity"] = spec.payload["integrity"]
        return True

    @staticmethod
    def _npm_legacy(tree: Any, spec: FixSpec) -> int:
        """The lockfile v2 `dependencies` tree, walked without recursion."""
        changed = 0
        stack = [tree]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for key, entry in node.items():
                if not isinstance(entry, dict):
                    continue
                if key == spec.name and DependencyFixer._npm_entry(entry, spec):
                    changed += 1
                if isinstance(entry.get("dependencies"), dict):
                    stack.append(entry["dependencies"])
        return changed

    @staticmethod
    def _npm_manifest(path: Path, spec: FixSpec) -> bool:
        original = path.read_text(encoding="utf-8")
        try:
            document = json.loads(original)
        except ValueError:
            return False
        if not isinstance(document, dict):
            return False
        changed = False
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            block = document.get(section)
            if not isinstance(block, dict) or not isinstance(block.get(spec.name), str):
                continue
            current = block[spec.name].strip()
            for prefix in ("", "=", "^", "~"):
                if current == f"{prefix}{spec.from_version}":
                    # An exact pin stays exact; a caret or tilde range keeps its intent from the new floor.
                    block[spec.name] = f"{'' if prefix == '=' else prefix}{spec.to_version}"
                    changed = True
        if changed:
            path.write_text(DependencyFixer._dump(original, document), encoding="utf-8")
        return changed

    @staticmethod
    def npm(repo: Path, spec: FixSpec) -> list[Path]:
        before, after = spec.payload.get("dependencies_from"), spec.payload.get("dependencies_to")
        if before is not None and after is not None and before != after:
            raise FixRefused(
                f"{spec.name} {spec.to_version} changes its own dependencies, so npm must resolve the tree again: "
                f"run `npm install {spec.name}@{spec.to_version}` and commit the lockfile"
            )
        changed: list[Path] = []
        locks = DependencyFixer._files(repo, ("package-lock.json", "npm-shrinkwrap.json"))
        for lock in locks:
            original = lock.read_text(encoding="utf-8")
            try:
                document = json.loads(original)
            except ValueError:
                continue
            if not isinstance(document, dict):
                continue
            version = document.get("lockfileVersion")
            if version not in (2, 3):
                raise FixRefused(
                    f"{lock.relative_to(repo)} is a lockfile v{version}; only v2 and v3 are edited. "
                    f"Run `npm install {spec.name}@{spec.to_version}` with npm 7 or later"
                )
            count = 0
            packages = document.get("packages")
            if isinstance(packages, dict):
                for key, entry in packages.items():
                    if (
                        key == f"node_modules/{spec.name}"
                        or key.endswith(f"/node_modules/{spec.name}")
                    ) and DependencyFixer._npm_entry(entry, spec):
                        count += 1
            count += DependencyFixer._npm_legacy(document.get("dependencies"), spec)
            if count:
                lock.write_text(DependencyFixer._dump(original, document), encoding="utf-8")
                changed.append(lock)
        if not changed:
            raise FixRefused(f"no npm lockfile here records {spec.name}@{spec.from_version}")
        for manifest in DependencyFixer._files(repo, ("package.json",)):
            if DependencyFixer._npm_manifest(manifest, spec):
                changed.append(manifest)
        return changed

    # -- PyPI ----------------------------------------------------------------------------

    @staticmethod
    def _normalise(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    @staticmethod
    def pypi(repo: Path, spec: FixSpec) -> list[Path]:
        wanted = DependencyFixer._normalise(spec.name)
        pin = re.compile(
            r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*==\s*(?P<version>[^\s;\\#]+)(?P<rest>.*)$"
        )
        hash_line = re.compile(r"^\s*--hash=sha256:[0-9a-f]{64}\s*\\?\s*$")
        changed: list[Path] = []
        files = DependencyFixer._files(
            repo, (), re.compile(r"^requirements.*\.(txt|in)$|^constraints.*\.txt$")
        )
        for path in files:
            # newline="" keeps the file's own line endings (CRLF stays CRLF) on read and write.
            with path.open(encoding="utf-8", newline="") as handle:
                lines = handle.read().splitlines(keepends=True)
            out: list[str] = []
            touched = False
            i = 0
            while i < len(lines):
                line = lines[i]
                match = pin.match(line.rstrip("\r\n"))
                if (
                    not match
                    or DependencyFixer._normalise(match.group("name")) != wanted
                    or match.group("version") != spec.from_version
                ):
                    out.append(line)
                    i += 1
                    continue
                touched = True
                ending = "\r\n" if line.endswith("\r\n") else "\n"
                rest = match.group("rest")
                hashed = rest.rstrip().endswith("\\")
                head = f"{match.group('indent')}{match.group('name')}{match.group('extras') or ''}=={spec.to_version}{rest}"
                i += 1
                if not hashed:
                    out.append(head + ending)
                    continue
                indent = "    "
                while i < len(lines) and hash_line.match(lines[i].rstrip("\r\n")):
                    leading = re.match(r"^\s*", lines[i])
                    indent = (leading.group(0) if leading else "") or indent
                    i += 1
                out.append(head + ending)
                hashes = spec.payload["hashes"]
                for n, digest in enumerate(hashes):
                    continuation = " \\" if n < len(hashes) - 1 else ""
                    out.append(f"{indent}--hash=sha256:{digest}{continuation}{ending}")
            if touched:
                with path.open("w", encoding="utf-8", newline="") as handle:
                    handle.write("".join(out))
                changed.append(path)
        if not changed:
            for lock in ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock"):
                if (repo / lock).exists():
                    raise FixRefused(
                        f"{spec.name} is locked in {lock}, which is regenerated by its own tool: "
                        f"update {spec.name} to {spec.to_version} with that tool and commit the lock"
                    )
            raise FixRefused(f"no requirements file here pins {spec.name}=={spec.from_version}")
        return changed

    @staticmethod
    def apply(repo: Path, spec: FixSpec) -> list[str]:
        changed = (
            DependencyFixer.npm(repo, spec)
            if spec.ecosystem == "npm"
            else DependencyFixer.pypi(repo, spec)
        )
        return sorted({str(p.relative_to(repo)) for p in changed})


__all__ = ["DependencyFixer", "FixRefused", "FixSpec"]
