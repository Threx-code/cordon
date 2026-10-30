"""opam / OCaml: opam files, opam lock files, and dune's package declarations and lock.

```
  app.opam, opam       a package: depends / depopts formulas (`"fmt" {>= "0.9" & with-test}`,
                       alternatives with `|`, groups), depexts (system packages, filtered by
                       os-family), pin-depends (a package fetched from git or an archive), build /
                       install commands, available, dev-repo
  app.opam.locked      `opam lock`: every package of the installed solution with `{= "version"}`,
                       test and doc ones flagged, pins kept as pin-depends
  dune-project         `(package (name ..) (depends ..))`, from which dune generates the opam
                       files when `(generate_opam_files true)`
  dune-workspace       contexts and the opam switches they build in
  dune.lock/           `dune pkg lock`: lock.dune (the repositories, at a commit, the solution was
                       made from) and one <name>.<version>.pkg per package: version, depends,
                       and the archive with its checksum
```

The OCaml compiler and the virtual packages describing it (`ocaml`, `ocaml-base-compiler`,
`base-unix`, `ocaml-options-vanilla`, ...) are the switch, not something fetched for the project:
recorded as platform requirements.

opam-repository holds package definitions, not archives: every package's archive comes from its
upstream (a GitHub release, the author's site). That is the registry working as designed, and a
locked archive URL is not a departure from it -- only a pin is.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.packages.ocaml.opam_syntax import (
    COMPILER_PACKAGES,
    Formula,
    Node,
    OpamDocument,
    OpamError,
    OpamLexer,
    OpamParser,
    Switch,
)
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cordon_scanner.foundation.content import FileContent


class OpamFile:
    """An opam package file (`app.opam`, `opam`)."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            document = OpamDocument.load(content)
        except OpamError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable opam file: {exc}")
        if "opam-version" not in document.fields and "depends" not in document.fields:
            return BaseEcosystem._err(
                content, ecosystem, "an opam file with neither opam-version nor depends"
            )
        pins = document.pins()
        declared: list[DeclaredDependency] = []
        for field_name, default in (("depends", Scope.RUNTIME), ("depopts", Scope.OPTIONAL)):
            for node in document.fields.get(field_name, []):
                for name, options, alternative in Formula.packages(node):
                    filtered = Formula.options(options)
                    scope = (
                        Scope.PLATFORM if Switch.is_compiler(name) else filtered.scope or default
                    )
                    pinned = pins.get(name)
                    note = None
                    if alternative:
                        note = "one of alternatives (`|`): resolved only if the solver chooses it"
                    elif filtered.flag in ("with-test", "with-doc", "with-dev-setup", "dev"):
                        note = f"a {filtered.flag} dependency: installed, and locked, only when opam is asked for {filtered.flag}"
                    declared.append(
                        DeclaredDependency(
                            name=name,
                            spec=pinned if pinned else filtered.constraint,
                            scope=scope,
                            field_name=field_name,
                            platform=filtered.conditions,
                            note=note,
                        )
                    )
        for node in document.fields.get("depexts", []):
            for system, conditions in OpamFile.depexts(node):
                declared.append(
                    DeclaredDependency(
                        name=f"depext:{system}",
                        spec="*",
                        scope=Scope.PLATFORM,
                        field_name="depexts",
                        platform=conditions,
                    )
                )
        sources: list[str] = []
        available = document.first("available")
        if available is not None:
            sources.append(f"available: {Formula.render(available).replace(chr(34), '')}")
        basename = content.basename
        package_name = document.string("name") or (
            basename.removesuffix(".opam") if basename != "opam" else None
        )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=package_name,
            version=document.string("version"),
            dependencies=tuple(declared),
            hooks=document.hooks(content.path, ecosystem),
            sources=tuple(sources),
            source_patterns=pins,
            repository=document.string("dev-repo"),
        )

    @staticmethod
    def depexts(node: Node) -> Iterator[tuple[str, tuple[str, ...]]]:
        """opam 2's `depexts: [["pkg" ...] {filter} ...]` (or a single such list)."""
        groups = (
            node.items
            if node.kind == "list" and node.items and node.items[0].kind == "list"
            else [node]
        )
        for group in groups:
            conditions = Formula.options(group.options).conditions
            for item in group.items:
                if item.kind == "str":
                    yield item.text, conditions


class OpamLock:
    """`*.opam.locked`: the solution `opam lock` recorded, one exact version per package."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            document = OpamDocument.load(content)
        except OpamError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable opam lock file: {exc}",
            )
        depends = document.fields.get("depends")
        if not depends:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an opam lock file without depends",
            )
        pins = document.pins()
        entries: list[LockEntry] = []
        for node in depends:
            for name, options, _alternative in Formula.packages(node):
                filtered = Formula.options(options)
                exact, flagged, conditions = filtered.exact, filtered.scope, filtered.conditions
                if exact is None:
                    return LockGraph(
                        path=content.path,
                        ecosystem=ecosystem,
                        parse_error="a locked dependency without an exact version",
                    )
                pinned = pins.get(name)
                entries.append(
                    LockEntry(
                        name=name,
                        version=exact,
                        scope=Scope.PLATFORM
                        if Switch.is_compiler(name, exact)
                        else flagged or Scope.RUNTIME,
                        # A pin's source; anything else comes through opam-repository.
                        resolved_from=pinned
                        if pinned and not Switch.is_compiler(name, exact)
                        else None,
                        local=bool(pinned and pinned.startswith("path:")),
                        platform=conditions,
                    )
                )
        if not content.text.rstrip().endswith("]"):
            # `opam lock` ends the file with a closing bracket (depends, pin-depends, ...).
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an opam lock file that does not end where opam lock ends it",
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


# -- dune ------------------------------------------------------------------------------------


class OpamEcosystem(BaseEcosystem):
    """OCaml packages through opam and dune."""

    id = "opam"
    purl_type = "opam"
    manifest_globs: tuple[str, ...] = (
        "**/*.opam",
        "**/opam",
        "**/dune-project",
        "**/dune-workspace",
        "**/dune.lock/lock.dune",
    )
    lockfile_globs: tuple[str, ...] = ("**/*.opam.locked", "**/dune.lock/*.pkg")
    registry_hosts: frozenset[str] = frozenset(
        {"opam.ocaml.org", "github.com/ocaml/opam-repository"}
    )
    records_integrity = False
    """`opam lock` records no hashes: opam checks every archive against the checksum in
    opam-repository's own definition of the package. dune's lock does record each archive's
    checksum, and those are kept and judged (a malformed one is reported); a missing one is the
    format, not a gap."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        """A dune project inside a dune workspace is resolved by the workspace root's lock: dune
        builds every project under the dune-workspace as one, from one dune.lock/."""
        manifest = self.parse_manifest(content)
        if content.basename != "dune-project" and not content.basename.endswith(".opam"):
            return manifest
        directory = content.path.rpartition("/")[0]
        ancestor = directory
        while ancestor:
            ancestor = ancestor.rpartition("/")[0]
            prefix = f"{ancestor}/" if ancestor else ""
            if f"{prefix}dune-workspace" in files and any(
                p.startswith(f"{prefix}dune.lock/") for p in files
            ):
                if manifest.parse_error is None:
                    return dataclasses.replace(manifest, locked_by=ancestor)
                return manifest
        return manifest

    def parse_manifest(self, content: FileContent) -> Manifest:
        from cordon_scanner.ecosystems.packages.ocaml.dune import (
            DuneLock,
            DuneProject,
            DuneWorkspace,
        )

        basename = content.basename
        if basename == "dune-project":
            return DuneProject.parse(content, self.id)
        if basename == "dune-workspace":
            return DuneWorkspace.parse(content, self.id)
        if basename == "lock.dune":
            return DuneLock.repositories(content, self.id)
        return OpamFile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        from cordon_scanner.ecosystems.packages.ocaml.dune import DuneLock

        if content.basename.endswith(".pkg"):
            return DuneLock.package(content, self.id)
        return OpamLock.parse(content, self.id)


__all__ = [
    "COMPILER_PACKAGES",
    "Formula",
    "OpamEcosystem",
    "OpamFile",
    "OpamLexer",
    "OpamLock",
    "OpamParser",
    "Switch",
]
