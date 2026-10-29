"""Which files of a published package run when it is used rather than installed.

Moved out of `engine/engine.py` (0.7.0 layout: a long module only shrinks). The engine records
them as `import_entry_paths`, and, without the command targets, as `library_entry_paths`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.foundation.formats.scanned_json import ScannedJson

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit


class PackageEntries:
    @staticmethod
    def of(units: list[FileUnit], distribution: str, *, with_bin: bool = True) -> frozenset[str]:
        """The files of a published package that run when it is used rather than installed: npm's
        `main` (or `index.js`), `bin` and `exports` targets; a wheel's or sdist's top-level
        `__init__.py`. Their module top level runs on `require()`, `import` or the command, on
        every consumer, with no hook in the manifest (review 98, REC-2)."""
        members: dict[str, str] = {}
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                members[member] = unit.path
        found: set[str] = set()
        if distribution == "npm":
            manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
            try:
                document = ScannedJson.loads(manifest.content.text) if manifest is not None else {}
            except (ValueError, RecursionError):
                document = {}
            if not isinstance(document, dict):
                document = {}
            targets: list[str] = [document.get("main") or "index.js"]

            def strings(value: object) -> None:
                if isinstance(value, str):
                    targets.append(value)
                elif isinstance(value, dict):
                    for nested in value.values():
                        strings(nested)
                elif isinstance(value, list):
                    for nested in value:
                        strings(nested)

            if with_bin:
                strings(document.get("bin"))
            strings(document.get("exports"))
            for target in targets:
                if not isinstance(target, str) or "*" in target:
                    continue
                base = "package/" + target.strip().removeprefix("./").rstrip("/")
                for candidate in (base, f"{base}.js", f"{base}/index.js"):
                    if candidate in members:
                        found.add(members[candidate])
                        break
        elif distribution == "pypi":
            for member, path in members.items():
                parts = member.split("/")
                if parts[-1] != "__init__.py" or any(
                    part in ("tests", "test", "docs", "examples") for part in parts
                ):
                    continue
                # A wheel's `pkg/__init__.py`, an sdist's `name-1.0/pkg/__init__.py` or
                # `name-1.0/src/pkg/__init__.py`: the package itself, not a subpackage.
                if (
                    len(parts) == 2
                    or (len(parts) == 3 and "-" in parts[0])
                    or (len(parts) == 4 and parts[1] == "src")
                ):
                    found.add(path)
        return frozenset(found)

    @staticmethod
    def repository(units: list[FileUnit], distribution: str) -> str:
        """The published npm package's own `repository` URL, or "": a string, or an object's
        `url`, as `package.json` declares it (review 98, FP-2)."""
        if distribution != "npm":
            return ""
        manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
        try:
            document = ScannedJson.loads(manifest.content.text) if manifest is not None else {}
        except (ValueError, RecursionError):
            return ""
        repository = document.get("repository") if isinstance(document, dict) else None
        if isinstance(repository, dict):
            repository = repository.get("url")
        return repository.strip() if isinstance(repository, str) else ""


__all__ = ["PackageEntries"]
