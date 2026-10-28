"""cabal.project and cabal.project.freeze: the packages a project builds and the versions it freezes."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.packages.hackage import (
    GHC_PACKAGES,
    CabalDeps,
    CabalLayout,
    CabalNode,
)
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class CabalProject:
    """cabal.project: Cabal's project configuration."""

    @staticmethod
    def git_source(children: list[CabalNode]) -> tuple[list[str], str] | None:
        location = CabalLayout.first(children, "location")
        if not location:
            return None
        tag = CabalLayout.first(children, "tag") or CabalLayout.first(children, "branch") or ""
        kind = (CabalLayout.first(children, "type") or "git").lower()
        subdirs = " ".join(CabalLayout.fields(children, "subdir")).split()
        repo = location.rstrip("/").rpartition("/")[2].removesuffix(".git")
        names = [s.rstrip("/").rpartition("/")[2] or repo for s in subdirs] or [repo]
        prefix = "git+" if kind == "git" else f"{kind}+"
        return names, f"{prefix}{location}" + (f"#{tag}" if tag else "")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            nodes = CabalLayout.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable cabal.project: {exc}")
        overrides: dict[str, str] = {}
        sources: list[str] = []
        routed: dict[str, str] = {}
        declared: list[DeclaredDependency] = []
        for value in CabalLayout.fields(nodes, "constraints"):
            for chunk in CabalDeps.split(value):
                found = re.match(r"^(?:any\.)?([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s+(.+)$", chunk)
                if not found:
                    continue
                package, rule = found.group(1), found.group(2).strip()
                if re.fullmatch(r"(?:[+-][\w-]+\s*)+", rule):
                    sources.append(f"flags {package}: {rule}")
                elif rule not in ("installed", "source"):
                    overrides[package] = rule
        for node in nodes:
            if node.is_field:
                continue
            head = node.head.lower()
            if head == "source-repository-package":
                found_source = CabalProject.git_source(node.children)
                if found_source:
                    for name in found_source[0]:
                        routed[name] = found_source[1]
            elif head.startswith("repository "):
                url = CabalLayout.first(node.children, "url")
                sources.append(
                    f"repository {node.head.split(None, 1)[1].strip()} {url or ''}".strip()
                )
            elif head.startswith("package ") and len(head.split()) > 1:
                flag_value = CabalLayout.first(node.children, "flags")
                if flag_value:
                    sources.append(f"flags {node.head.split(None, 1)[1].strip()}: {flag_value}")
        compiler = CabalLayout.first(nodes, "with-compiler")
        if compiler:
            found_compiler = re.match(r"^(?:.*/)?(ghc|ghcjs)-?([0-9][0-9.]*)?$", compiler)
            declared.append(
                DeclaredDependency(
                    name=found_compiler.group(1) if found_compiler else "ghc",
                    spec=(
                        found_compiler.group(2)
                        if found_compiler and found_compiler.group(2)
                        else compiler
                    ),
                    scope=Scope.PLATFORM,
                    field_name="with-compiler",
                )
            )
        for value in CabalLayout.fields(nodes, "extra-packages"):
            for name, spec in CabalDeps.entries(value):
                declared.append(
                    DeclaredDependency(name=name, spec=spec, field_name="extra-packages")
                )
        index = CabalLayout.first(nodes, "index-state")
        if index:
            sources.append(f"index-state {index}")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            overrides=overrides,
            sources=tuple(sources),
            source_patterns=routed,
        )


class CabalFreeze:
    """cabal.project.freeze: every package of Cabal's install plan, pinned."""

    PIN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:(any|setup|[A-Za-z0-9-]+:setup|[A-Za-z0-9-]+:exe)\.)?([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s*==\s*([0-9]+(?:\.[0-9]+)*)$"
    )
    FLAGS: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:any\.)?([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)\s+((?:[+-][\w-]+\s*)+)$"
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            nodes = CabalLayout.parse(content.text)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable freeze file: {exc}",
            )
        values = CabalLayout.fields(nodes, "constraints")
        if not values and CabalLayout.fields(nodes, "index-state"):
            # Only the package index pinned (`index-state: hackage.haskell.org 2026-08-10T...`),
            # PostgREST's way: every version is resolved from that snapshot when it builds, so none
            # is locked -- which is a lock that pins nothing, not one that could not be read.
            return LockGraph(path=content.path, ecosystem=ecosystem)
        if not values:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a freeze file with no `constraints`",
            )
        if not content.text.endswith("\n"):
            # `cabal freeze` ends the file with a newline after `index-state`; a file cut short is
            # missing pins nobody can tell were there.
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a freeze file that does not end where cabal freeze ends it",
            )
        entries: dict[tuple[str, Scope], LockEntry] = {}
        for value in values:
            for chunk in CabalDeps.split(value):
                pinned = CabalFreeze.PIN.match(chunk)
                if pinned:
                    qualifier, name, version = pinned.groups()
                    scope = (
                        Scope.PLATFORM
                        if name in GHC_PACKAGES
                        else Scope.BUILD
                        if qualifier and "setup" in qualifier
                        else Scope.TOOL
                        if qualifier and qualifier.endswith(":exe")
                        else Scope.RUNTIME
                    )
                    entries.setdefault(
                        (name, scope), LockEntry(name=name, version=version, scope=scope)
                    )
                    continue
                if CabalFreeze.FLAGS.match(chunk) or re.match(
                    r"^(?:any\.)?[\w-]+\s+(installed|source)$", chunk
                ):
                    continue
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a freeze constraint is neither a pin nor a flag assignment",
                )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries.values()))


__all__ = ["CabalFreeze", "CabalProject"]
