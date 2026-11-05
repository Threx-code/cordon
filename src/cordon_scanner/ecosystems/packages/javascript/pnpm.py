"""pnpm-lock.yaml: its importers, packages and snapshots, read into the dependency graph."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import (
    LockEntry,
    LockGraph,
)
from cordon_scanner.ecosystems.packages.javascript.conditions import NpmConditions
from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.scopes import LockScopes

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class PnpmLock:
    """pnpm's lockfile, versions 5, 6 and 9, read as the YAML document it is.

    Line-matching it kept names and hashes and lost everything else: the edges, which scope
    reached a package (pnpm 9 records no `dev` flag; only the importers say), the platform fields
    (`os`, `cpu`, `libc`), aliases (`chalk-four: {version: chalk@4.1.2}`), links to workspace
    members, and git sources (a key of `is-number@https://codeload.github.com/...` read as the
    package `is-number@https://codeload.github.com/...` and pinned the URL's hash as its version).

    ```
      importers:  <member path> -> dependencies / devDependencies / optionalDependencies
                  -> name -> {specifier, version}        (v6, v9; v5 keeps a bare version)
      packages:   <key> -> resolution {integrity | tarball | type: git, repo, commit},
                  os, cpu, libc, engines, version (for non-registry keys), dev, optional
      snapshots:  <key with peer suffix> -> dependencies, optionalDependencies   (v9 only)
    ```
    """

    @staticmethod
    def split_key(key: str) -> tuple[str, str] | None:
        """A pnpm package key as `(name, version)`, across the formats in use.

        pnpm has written the key three ways. Lockfile 5 separates with a slash
        and leads with one (`/lodash/4.17.21`, `/@babel/core/7.21.0`); 6 and 9
        separate with `@` (`/@babel/core@7.21.0`, `lodash@4.17.21`). Splitting on
        the last `@` alone reads every version-5 key as nameless and dropped the
        whole file, silently, because an empty graph and a project with no
        dependencies looked the same.

        A peer-suffixed key (`foo@1.0.0(bar@2.0.0)`) keeps only its own version:
        the suffix names the peer the entry was resolved against, not part of
        what this entry is.
        """
        text = key.strip().strip("'\"")
        if not text:
            return None

        head = text.split("(", 1)[0]
        scoped = head.startswith(("/@", "@"))
        body = head[1:] if head.startswith("/") else head

        at = body.rfind("@")
        if at > 0:
            name, version = body[:at], body[at + 1 :]
            if name and version and "/" not in version:
                return (name, version)

        # Lockfile 5: the version is the last slash-separated segment, and a
        # scoped name keeps the slash that belongs to its scope.
        cut = body.rfind("/")
        if cut > 0:
            name, version = body[:cut], body[cut + 1 :]
            if name and version and (not scoped or "/" in name):
                return (name, version)
        return None

    SECTIONS: ClassVar[dict[str, Scope]] = {
        "dependencies": Scope.RUNTIME,
        "optionalDependencies": Scope.OPTIONAL,
        "devDependencies": Scope.DEV,
    }

    @staticmethod
    def _identity(key: str, meta: dict[str, Any]) -> tuple[str, str]:
        """`(name, version)` of a package key in any of pnpm's layouts."""
        text = key.strip().strip("'\"").split("(", 1)[0]
        body = text[1:] if text.startswith("/") else text
        at = body.find("@", 1 if body.startswith("@") else 0)
        if at > 0:
            remainder = body[at + 1 :]
            if "://" in remainder or remainder.startswith(("link:", "file:", "git+", "github:")):
                name = body[:at]
                version = str(meta.get("version") or remainder)
                return str(meta.get("name") or name), version
        split = PnpmLock.split_key(text)
        if split is not None:
            name, version = split
            return str(meta.get("name") or name), str(meta.get("version") or version)
        return str(meta.get("name") or body), str(meta.get("version") or "")

    @staticmethod
    def _candidates(name: str, reference: str) -> list[str]:
        bare = reference.split("(", 1)[0]
        return [
            f"{name}@{reference}",
            f"{name}@{bare}",
            f"/{name}@{reference}",
            f"/{name}@{bare}",
            f"/{name}/{reference}",
            f"/{name}/{bare}",
            # The reference already a key: `registry.npmjs.org/@types/estree@1.0.0`.
            bare,
            f"/{bare}",
        ]

    @staticmethod
    def _target(name: str, reference: str) -> tuple[str, str, str | None]:
        """`(real name, reference, alias)` for a dependency written `name: reference`.

        `chalk-four: chalk@4.1.2` is an alias: the package is `chalk`, at 4.1.2."""
        reference = reference.strip()
        if reference.startswith(("link:", "file:", "http:", "https:", "git+", "github:")):
            return name, reference, None
        head = reference.split("(", 1)[0]
        # A package from a non-default registry is keyed with the registry's host:
        # `'@types/estree': registry.npmjs.org/@types/estree@1.0.0`. That is the package's key, not
        # an alias -- read as one, every such dependency was named `registry.npmjs.org/`, and two
        # of them at one version read as one package locked with two hashes (review 98).
        if re.match(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/", head):
            return name, reference, None
        at = head.find("@", 1 if head.startswith("@") else 0)
        if at > 0 and not head[:at].replace(".", "").isdigit():
            return head[:at], reference[at + 1 :], name
        return name, reference, None

    DOCUMENT_BREAK: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^---[ \t]*\r?$")

    @classmethod
    def _project_document(cls, content: FileContent) -> Any:
        """The lockfile as one mapping. pnpm 10 writes two YAML documents into `pnpm-lock.yaml`:
        first the package manager's own environment (`packageManagerDependencies`: pnpm and its
        `@pnpm/exe` builds), then, after `---`, the project. Read as one document the second was
        dropped, and the project's whole dependency tree with it. Each document is read, and the
        ones whose importers declare dependencies are merged; the environment is the tool that
        installs, not a dependency of the project."""
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        pieces = [p for p in cls.DOCUMENT_BREAK.split(content.text) if p.strip()]
        if len(pieces) <= 1:
            return DataYaml.load(content.text, source=content.path)
        documents = [
            d
            for d in (DataYaml.load(p, source=content.path) for p in pieces)
            if isinstance(d, dict)
        ]
        projects = [
            d
            for d in documents
            if isinstance(d.get("importers"), dict)
            and any(
                isinstance(i, dict) and any(i.get(s) for s in cls.SECTIONS)
                for i in d["importers"].values()
            )
        ] or documents
        merged: dict[str, Any] = dict(projects[0])
        for document in projects[1:]:
            for key in ("importers", "packages", "snapshots"):
                if isinstance(document.get(key), dict):
                    merged[key] = {**document[key], **(merged.get(key) or {})}
        return merged

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        from cordon_scanner.foundation.formats.datayaml import DataYamlError

        try:
            data = cls._project_document(content)
        except DataYamlError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid YAML: {exc}"
            )
        if not isinstance(data, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="top level is not a mapping"
            )
        raw_importers = data.get("importers")
        importers: dict[str, Any] = (
            raw_importers
            if isinstance(raw_importers, dict)
            else {".": {k: data.get(k) for k in (*cls.SECTIONS, "specifiers")}}
        )
        raw_packages, raw_snapshots = data.get("packages"), data.get("snapshots")
        packages: dict[str, Any] = raw_packages if isinstance(raw_packages, dict) else {}
        snapshots: dict[str, Any] = raw_snapshots if isinstance(raw_snapshots, dict) else {}

        metas: dict[str, dict[str, Any]] = {}
        for key, meta in packages.items():
            metas[str(key).split("(", 1)[0]] = meta if isinstance(meta, dict) else {}
        for key in snapshots:
            metas.setdefault(str(key).split("(", 1)[0], {})

        edges, names, aliases = cls._edges(packages, snapshots, metas)

        roots, direct, local, members = cls._importer_roots(importers, metas, names, aliases)

        scopes = LockScopes.propagate(roots, edges)
        entries: list[LockEntry] = list(local)
        unreadable = cls._entries(
            metas, names, scopes, roots, snapshots, entries, edges, direct, aliases
        )
        if not entries and (unreadable or packages):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"the lockfile declares packages and none could be read ({unreadable} unreadable key(s))",
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            workspaces=tuple(members),
        )

    @classmethod
    def _edges(
        cls, packages: dict[str, Any], snapshots: dict[str, Any], metas: dict[str, dict[str, Any]]
    ) -> tuple[dict[str, set[str]], dict[str, str], dict[str, str]]:
        """Each package's edges to the packages it depends on, with their real names and aliases."""
        edges: dict[str, set[str]] = {}
        names: dict[str, str] = {}
        aliases: dict[str, str] = {}
        for key, meta in [*packages.items(), *snapshots.items()]:
            base = str(key).split("(", 1)[0]
            if not isinstance(meta, dict):
                continue
            for field in ("dependencies", "optionalDependencies"):
                section = meta.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, reference in section.items():
                    target, alias, real = cls._resolve(metas, str(dep), str(reference))
                    if target is not None:
                        edges.setdefault(base, set()).add(target)
                        names[target] = real
                        if alias:
                            aliases.setdefault(target, alias)
        return edges, names, aliases

    @classmethod
    def _importer_roots(
        cls,
        importers: dict[str, Any],
        metas: dict[str, dict[str, Any]],
        names: dict[str, str],
        aliases: dict[str, str],
    ) -> tuple[dict[str, set[Scope]], set[str], list[LockEntry], list[str]]:
        """What each importer declares: the root dependencies and their scopes, and the workspace members it links."""
        roots: dict[str, set[Scope]] = {}
        direct: set[str] = set()
        local: list[LockEntry] = []
        members = sorted(str(k) for k in importers if str(k) not in (".", ""))
        for sections in importers.values():
            if not isinstance(sections, dict):
                continue
            for field, scope in cls.SECTIONS.items():
                section = sections.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, value in section.items():
                    reference = str(value.get("version") if isinstance(value, dict) else value)
                    target, alias, real = cls._resolve(metas, str(dep), reference)
                    if target is None:
                        if reference.startswith("link:"):
                            local.append(
                                LockEntry(
                                    name=real,
                                    version="",
                                    resolved_from=reference,
                                    scope=scope,
                                    direct=True,
                                    local=True,
                                    alias=alias,
                                )
                            )
                        continue
                    roots.setdefault(target, set()).add(scope)
                    direct.add(target)
                    names[target] = real
                    if alias:
                        aliases.setdefault(target, alias)
        return roots, direct, local, members

    @classmethod
    def _resolve(
        cls, metas: dict[str, dict[str, Any]], name: str, reference: str
    ) -> tuple[str | None, str | None, str]:
        """`(package key, alias, real name)` a reference lands on, or no key for a link."""
        real, ref, alias = cls._target(name, reference)
        if ref.startswith("link:"):
            return None, alias, real
        for candidate in cls._candidates(real, ref):
            base = candidate.split("(", 1)[0]
            if base in metas:
                return base, alias, real
        return None, alias, real

    @classmethod
    def _entries(
        cls,
        metas: dict[str, dict[str, Any]],
        names: dict[str, str],
        scopes: dict[str, Scope],
        roots: dict[str, set[Scope]],
        snapshots: dict[str, Any],
        entries: list[LockEntry],
        edges: dict[str, set[str]],
        direct: set[str],
        aliases: dict[str, str],
    ) -> int:
        """One entry per resolved package, with its scope, integrity and source, and how many could not be read."""
        unreadable = 0
        for key, meta in sorted(metas.items()):
            name, version = cls._identity(key, meta)
            name = names.get(key, name)
            if not version:
                unreadable += 1
                continue
            raw_resolution = meta.get("resolution")
            resolution: dict[str, Any] = raw_resolution if isinstance(raw_resolution, dict) else {}
            integrity = (
                resolution.get("integrity")
                if isinstance(resolution.get("integrity"), str)
                else None
            )
            resolved = (
                resolution.get("tarball") if isinstance(resolution.get("tarball"), str) else None
            )
            if resolution.get("type") == "git" and resolution.get("repo"):
                resolved = f"git+{resolution['repo']}#{resolution.get('commit', '')}"
            scope = scopes.get(key, Scope.RUNTIME)
            if meta.get("dev") is True:
                scope = Scope.DEV
            elif meta.get("optional") is True and scope is Scope.RUNTIME and key not in roots:
                scope = Scope.OPTIONAL
            snapshot = snapshots.get(key)
            if isinstance(snapshot, dict) and snapshot.get("optional") is True and key not in roots:
                scope = Scope.OPTIONAL
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=integrity,
                    resolved_from=resolved,
                    scope=scope,
                    dependencies=tuple(
                        sorted(
                            {
                                names.get(t, cls._identity(t, metas.get(t, {}))[0])
                                for t in edges.get(key, ())
                            }
                        )
                    ),
                    direct=key in direct,
                    local=str(resolved or "").startswith(("link:", "file:"))
                    or resolution.get("type") == "directory",
                    platform=NpmConditions.platform(meta),
                    alias=aliases.get(key),
                )
            )
        return unreadable


__all__ = ["PnpmLock"]
