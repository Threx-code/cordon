"""Git submodules: repositories a project builds with, pulled in by commit.

```
  .gitmodules   each submodule's path, URL, and the branch `git submodule update --remote`
                follows. The commit a submodule is pinned at is not in this file: it is the
                parent repository's gitlink, which the engine reads from the index of a checkout
                (`git ls-files --stage`) through the hardened git wrapper.
```

A submodule is recorded under the address OSV's GIT records key repositories by (`host/owner/repo`),
in the `git` ecosystem those records use, so a repository known to be malicious is named as such.
Its branch is not a mutable reference: the gitlink pins the commit, and `--remote` is an update
someone runs and commits. Not a package ecosystem: a repository a project checks out is read here,
beside the graph, and joins it.
"""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent


class GitModules:
    """`.gitmodules`: git-config syntax, one `[submodule "name"]` section per submodule."""

    SECTION: ClassVar[re.Pattern[str]] = re.compile(r'^\[\s*submodule\s+"([^"\n]{0,512})"\s*\]$')
    ENTRY: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$")
    NOTE: ClassVar[str] = (
        "a submodule: its commit is the parent repository's gitlink, which only a checkout's index records"
    )

    @staticmethod
    def sections(text: str) -> tuple[list[tuple[str, int, dict[str, str]]], str | None]:
        """`(name, line, keys)` per submodule, and an error git itself would stop on."""
        out: list[tuple[str, int, dict[str, str]]] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            section = GitModules.SECTION.match(line)
            if section:
                out.append((section.group(1), number, {}))
                continue
            entry = GitModules.ENTRY.match(line)
            if entry is None or not out:
                return out, f"line {number}: {line[:40]!r} is neither a section nor a key = value"
            value = entry.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            out[-1][2].setdefault(entry.group(1).lower(), value)
        return out, None

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        from cordon_scanner.intel.osv_import import OsvImport

        sections, error = GitModules.sections(content.text)
        if error:
            return BaseEcosystem._err(content, ecosystem, error)
        if not sections:
            return BaseEcosystem._err(content, ecosystem, "a .gitmodules without a submodule")
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        for name, line, keys in sections:
            path, url = keys.get("path"), keys.get("url")
            if not path or not url:
                # `git submodule` refuses a section missing either: what a file cut short is.
                return BaseEcosystem._err(
                    content,
                    ecosystem,
                    f"line {line}: submodule {name[:40]!r} has no {'path' if not path else 'url'}",
                )
            if url.startswith(("./", "../")):
                sources.append(
                    f"submodule {path} is at {url}, relative to the repository's own remote"
                )
            key = OsvImport.repository_key(url)
            declared.append(
                DeclaredDependency(
                    name=key or url,
                    spec=f"git+{url}",
                    scope=Scope.BUILD,
                    field_name=f"submodule {path}",
                    alias=name if name != path else None,
                    platform=(f"tracks branch {keys['branch']}",) if keys.get("branch") else (),
                    note=GitModules.NOTE,
                )
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class Submodules:
    """Submodules as dependency records, each at the commit its gitlink pins where the scan has
    the checkout's index to read it from."""

    @staticmethod
    def gitlinks(directory: Path) -> dict[str, str]:
        """`path -> commit` for every gitlink in the index of the checkout at `directory`, through
        the hardened git wrapper. Empty when there is no checkout to ask (an archive, a copy)."""
        if not (directory / ".git").exists():
            return {}
        from cordon_scanner.sources.git import GitRepository

        try:
            output = GitRepository(directory).run(["ls-files", "--stage"], check=False)
        except Exception:
            return {}
        links: dict[str, str] = {}
        for line in output.splitlines():
            meta, _, path = line.partition("\t")
            fields = meta.split()
            if (
                len(fields) == 3
                and fields[0] == "160000"
                and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields[1])
            ):
                links[path] = fields[1]
        return links

    @staticmethod
    def dependencies(
        units: Iterable[Any], root: Path
    ) -> tuple[list[Dependency], list[tuple[str, str]]]:
        """The records, and `(path, problem)` for each `.gitmodules` git would refuse."""
        records: list[Dependency] = []
        problems: list[tuple[str, str]] = []
        for unit in units:
            if unit.path.rpartition("/")[2] != ".gitmodules":
                continue
            manifest = GitModules.parse(unit.content, "git")
            if manifest.parse_error:
                problems.append((unit.path, manifest.parse_error))
                continue
            directory = unit.path.rpartition("/")[0]
            links = Submodules.gitlinks(root / directory if directory else root)
            for declared in manifest.dependencies:
                path = declared.field_name.removeprefix("submodule ")
                commit = links.get(path)
                url = declared.spec.removeprefix("git+")
                vcs = urllib.parse.quote(
                    f"git+{url}" + (f"@{commit}" if commit else ""), safe=":/+@"
                )
                records.append(
                    Dependency(
                        purl=f"pkg:generic/{urllib.parse.quote(declared.name, safe='/')}"
                        + (f"@{commit}" if commit else "")
                        + f"?vcs_url={vcs}",
                        ecosystem="git",
                        name=declared.name,
                        version=commit,
                        direct=True,
                        scope=Scope.BUILD,
                        declared_spec=declared.spec,
                        project=directory or None,
                        declared_in=unit.path,
                        manifest_path=unit.path,
                        resolved_from=f"git+{url}#{commit}" if commit else f"git+{url}",
                        platform=declared.platform,
                        alias=declared.alias,
                        resolution_note=None if commit else GitModules.NOTE,
                    )
                )
        return records, problems


__all__ = ["GitModules", "Submodules"]
