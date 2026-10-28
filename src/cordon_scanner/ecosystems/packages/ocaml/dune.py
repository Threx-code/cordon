"""Dune: dune-project's package dependencies, dune-workspace's contexts, and dune.lock's pinned packages."""

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
from cordon_scanner.ecosystems.packages.ocaml.opam import OpamDocument, Switch
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.foundation.content import FileContent


class Sexp:
    """S-expressions as dune writes them: atoms, "strings", `;` line comments, `#| |#` blocks
    and `#;` datum comments."""

    MAX_DEPTH: ClassVar[int] = 64
    ATOM: ClassVar[re.Pattern[str]] = re.compile(r'[^\s()";]+')

    @staticmethod
    def parse(text: str) -> list[object]:
        stack: list[list[object]] = [[]]
        skip_next: list[int] = []
        index, length = 0, len(text)
        while index < length:
            char = text[index]
            if char.isspace():
                index += 1
            elif char == ";":
                end = text.find("\n", index)
                index = length if end < 0 else end
            elif text.startswith("#|", index):
                end = text.find("|#", index + 2)
                if end < 0:
                    raise ValueError("an unterminated block comment")
                index = end + 2
            elif text.startswith("#;", index):
                skip_next.append(len(stack))
                index += 2
            elif char == "(":
                if len(stack) > Sexp.MAX_DEPTH:
                    raise ValueError("nested too deeply")
                stack.append([])
                index += 1
            elif char == ")":
                if len(stack) == 1:
                    raise ValueError("a closing parenthesis with nothing open")
                done = stack.pop()
                Sexp._add(stack, skip_next, done)
                index += 1
            elif char == '"':
                index += 1
                buffer: list[str] = []
                while index < length and text[index] != '"':
                    if text[index] == "\\" and index + 1 < length:
                        buffer.append(text[index + 1])
                        index += 2
                        continue
                    buffer.append(text[index])
                    index += 1
                if index >= length:
                    raise ValueError("an unterminated string")
                index += 1
                Sexp._add(stack, skip_next, "".join(buffer))
            else:
                found = Sexp.ATOM.match(text, index)
                if not found:
                    raise ValueError("an unreadable character")
                Sexp._add(stack, skip_next, found.group(0))
                index = found.end()
        if len(stack) != 1:
            raise ValueError("a parenthesis that does not close")
        return stack[0]

    @staticmethod
    def _add(stack: list[list[object]], skip_next: list[int], value: object) -> None:
        if skip_next and skip_next[-1] == len(stack):
            skip_next.pop()
            return
        stack[-1].append(value)

    @staticmethod
    def field(form: list[object], name: str) -> list[object] | None:
        for item in form:
            if isinstance(item, list) and item and item[0] == name:
                return item
        return None


class DuneProject:
    FLAGS: ClassVar[dict[str, Scope]] = {
        ":with-test": Scope.TEST,
        ":with-doc": Scope.DEV,
        ":with-dev-setup": Scope.DEV,
        ":build": Scope.BUILD,
        ":dev": Scope.DEV,
        ":post": Scope.RUNTIME,
    }

    @staticmethod
    def constraint(form: object) -> tuple[list[str], Scope | None, list[str]]:
        """`(constraints, scope, conditions)` of a dune dependency constraint."""
        if isinstance(form, str):
            return ([], DuneProject.FLAGS.get(form), [])
        if not isinstance(form, list) or not form:
            return ([], None, [])
        head = form[0]
        if head in ("and", "or"):
            constraints: list[str] = []
            scope: Scope | None = None
            conditions: list[str] = []
            for part in form[1:]:
                c, s, k = DuneProject.constraint(part)
                constraints += c
                scope = scope or s
                conditions += k
            joiner = " & " if head == "and" else " | "
            return ([joiner.join(constraints)] if constraints else [], scope, conditions)
        if (
            head in ("=", "<>", "<", ">", "<=", ">=")
            and len(form) == 3
            and isinstance(form[1], str)
            and form[1].startswith(":")
        ):
            # `(= :os linux)`: a variable filter.
            return ([], None, [f"{form[1][1:]} {head} {form[2]}"])
        if head in ("=", "<>", "<", ">", "<=", ">=") and len(form) == 2:
            operator = "!=" if head == "<>" else head
            return ([f"{operator} {form[1]}"], None, [])
        return ([], None, [])

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable dune-project: {exc}")
        if not any(isinstance(f, list) and f[:1] == ["lang"] for f in forms):
            return BaseEcosystem._err(
                content, ecosystem, "a dune-project without its `(lang dune ...)` line"
            )
        generated = any(
            isinstance(f, list) and f[:2] == ["generate_opam_files", "true"] for f in forms
        )
        declared: list[DeclaredDependency] = []
        names: list[str] = []
        for form in forms:
            if not (isinstance(form, list) and form[:1] == ["package"]):
                continue
            name_form = Sexp.field(form, "name")
            if name_form and len(name_form) > 1 and isinstance(name_form[1], str):
                names.append(name_form[1])
            for field_name, default in (("depends", Scope.RUNTIME), ("depopts", Scope.OPTIONAL)):
                listed = Sexp.field(form, field_name) or []
                for item in listed[1:]:
                    package = (
                        item
                        if isinstance(item, str)
                        else item[0]
                        if isinstance(item, list) and item and isinstance(item[0], str)
                        else None
                    )
                    if package is None:
                        continue
                    constraints: list[str] = []
                    scope: Scope | None = None
                    conditions: list[str] = []
                    for part in item[1:] if isinstance(item, list) else []:
                        c, s, k = DuneProject.constraint(part)
                        constraints += c
                        scope = scope or s
                        conditions += k
                    flags = [
                        p
                        for p in (item[1:] if isinstance(item, list) else [])
                        if isinstance(p, str) and p.startswith(":")
                    ]
                    note = None
                    if package == "dune":
                        note = "dune itself, which runs the build: dune's own lock leaves it out"
                    elif any(f in (":with-test", ":with-doc", ":with-dev-setup") for f in flags):
                        flag = next(
                            f for f in flags if f in (":with-test", ":with-doc", ":with-dev-setup")
                        )[1:]
                        note = f"a {flag} dependency: installed, and locked, only when asked for {flag}"
                    declared.append(
                        DeclaredDependency(
                            name=package,
                            spec=" & ".join(constraints) or "*",
                            scope=Scope.PLATFORM
                            if Switch.is_compiler(package)
                            else scope or default,
                            field_name=f"dune-project {field_name}",
                            platform=tuple(conditions),
                            note=note,
                        )
                    )
        sources = (
            [f"dune generates {', '.join(n + '.opam' for n in names)} (generate_opam_files)"]
            if generated and names
            else []
        )
        routed: dict[str, str] = {}
        for form in forms:
            if isinstance(form, list) and form[:1] == ["pin"]:
                url = Sexp.field(form, "url")
                pinned_package = Sexp.field(form, "package")
                name_form = Sexp.field(pinned_package, "name") if pinned_package else None
                if url and len(url) > 1 and name_form and len(name_form) > 1:
                    routed[str(name_form[1])] = OpamDocument.source(str(url[1]))
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=names[0] if len(names) == 1 else None,
            dependencies=tuple(declared),
            sources=tuple(sources),
            source_patterns=routed,
        )


class DuneWorkspace:
    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable dune-workspace: {exc}")
        sources: list[str] = []
        for form in forms:
            if isinstance(form, list) and form[:1] == ["context"] and len(form) > 1:
                body = form[1]
                if isinstance(body, list) and body[:1] == ["opam"]:
                    switch = Sexp.field(body, "switch")
                    sources.append(
                        f"context on opam switch {switch[1]}"
                        if switch and len(switch) > 1
                        else "context on an opam switch"
                    )
                elif body == "default" or (isinstance(body, list) and body[:1] == ["default"]):
                    sources.append("context default")
            elif isinstance(form, list) and form[:1] == ["repository"]:
                url = Sexp.field(form, "url") or Sexp.field(form, "source")
                name = Sexp.field(form, "name")
                if url and len(url) > 1:
                    sources.append(
                        f"repository {name[1] if name and len(name) > 1 else ''} {url[1]}".replace(
                            "  ", " "
                        )
                    )
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class DuneLock:
    """`dune.lock/`: lock.dune and a <name>.<version>.pkg per package."""

    @staticmethod
    def repositories(content: FileContent, ecosystem: str) -> Manifest:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable lock.dune: {exc}")
        sources: list[str] = []
        repositories = Sexp.field(forms, "repositories")
        used = Sexp.field(repositories, "used") if repositories else None
        for entry in (used or [])[1:]:
            source = Sexp.field(entry, "source") if isinstance(entry, list) else None
            if source and len(source) > 1:
                sources.append(f"repository {source[1]}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))

    @staticmethod
    def names(form: object) -> Iterator[str]:
        """Package names in a depends form: `(all_platforms (a b))` or a per-platform choice."""
        if isinstance(form, str):
            if not form.startswith(("all_platforms", "choice", ":", "(")):
                yield form
            return
        if isinstance(form, list):
            for item in form:
                if isinstance(item, list) and item[:1] in (
                    ["os"],
                    ["arch"],
                    ["os-family"],
                    ["os-distribution"],
                ):
                    continue
                yield from DuneLock.names(item)

    @staticmethod
    def package(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            forms = Sexp.parse(content.text)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable dune lock package: {exc}",
                owner_levels=1,
            )
        version_form = Sexp.field(forms, "version")
        if not version_form or len(version_form) < 2 or not isinstance(version_form[1], str):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a dune lock package without its version",
                owner_levels=1,
            )
        version = version_form[1]
        stem = content.basename.removesuffix(".pkg")
        name = (
            stem[: -(len(version) + 1)] if stem.endswith("." + version) else stem.partition(".")[0]
        )
        depends = Sexp.field(forms, "depends")
        children = tuple(dict.fromkeys(DuneLock.names(depends[1:]))) if depends else ()
        source = Sexp.field(forms, "source")
        fetch = Sexp.field(source, "fetch") if source else None
        url = Sexp.field(fetch, "url") if fetch else None
        checksum = Sexp.field(fetch, "checksum") if fetch else None
        digest = str(checksum[1]).replace("=", ":", 1) if checksum and len(checksum) > 1 else None
        pinned = Sexp.field(forms, "dev") is not None
        location = str(url[1]) if url and len(url) > 1 else None
        compiler = Switch.is_compiler(name, version)
        entry = LockEntry(
            name=name,
            version=version,
            integrity=digest,
            # Only a pin (`(dev)`) departs from opam-repository; an archive URL is the registry's.
            resolved_from=OpamDocument.source(location) if pinned and location else None,
            scope=Scope.PLATFORM if compiler else Scope.RUNTIME,
            dependencies=children,
        )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=(entry,), owner_levels=1)


__all__ = ["DuneLock", "DuneProject", "DuneWorkspace", "Sexp"]
