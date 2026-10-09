"""Bazel: Bzlmod modules, repository rules, and the legacy WORKSPACE.

```
  MODULE.bazel        bazel_dep (version, dev_dependency, repo_name); single_version_override,
                      multiple_version_override, archive_override (urls, integrity),
                      git_override (remote, commit / tag / branch), local_path_override;
                      use_extension and its tags -- maven.install's artifacts are Maven packages;
                      use_repo_rule'd repository rules (http_archive, git_repository)
  MODULE.bazel.lock   Bazel 7.2+: the registry files resolution read, with their SHA-256 -- a
                      module whose source.json was fetched is one the graph selected; earlier
                      locks: the module graph itself, with each module's archive and integrity
  WORKSPACE[.bazel]   http_archive / http_file / http_jar (urls, sha256 or integrity),
                      git_repository / new_git_repository (remote, commit / tag / branch),
                      local_repository, maven_install. A macro called here expands to more, which
                      only evaluation shows: reported as such, never guessed
  BUILD.bazel         the external repositories its targets use (`@repo//...`)
```

Starlark is a programming language; nothing here evaluates it. Statements are tokenised and only
literal arguments of calls are read.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent


class StarlarkError(ValueError):
    """Not Starlark this reader can tokenise. The message never repeats the file's content."""


@dataclass
class Call:
    """One call statement: `name(arg, key = value)`, or `receiver.name(...)` for a tag."""

    receiver: str | None
    name: str
    positional: list[Any] = field(default_factory=list)
    keywords: dict[str, Any] = field(default_factory=dict)
    target: str | None = None  # `x = use_extension(...)` assigns to x


class Unread:
    """An argument that is not a literal."""


UNREAD = Unread()


class Starlark:
    TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?P<space>[ \t\r]+)|(?P<newline>\n)|(?P<comment>\#[^\n]*)"""
        r'''|(?P<string>[rRbB]{0,2}(?:"""(?:\\.|[^\\])*?"""|\'\'\'(?:\\.|[^\\])*?\'\'\'|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'))'''
        r"""|(?P<number>\d+(?:\.\d+)?)|(?P<name>[A-Za-z_][A-Za-z0-9_]*)"""
        r"""|(?P<punct>\*\*|==|!=|<=|>=|//|[()\[\]{},:=.+\-*/%<>|&^~])"""
    )

    @staticmethod
    def tokens(text: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        index = 0
        while index < len(text):
            found = Starlark.TOKEN.match(text, index)
            if not found:
                raise StarlarkError("a character that is not part of Starlark")
            kind = found.lastgroup or ""
            if kind not in ("space", "comment"):
                out.append((kind, found.group(0)))
            index = found.end()
        return out

    @staticmethod
    def literal_string(token: str) -> str:
        body = token.lstrip("rRbB")
        quote = body[:3] if body[:3] in ('"""', "'''") else body[0]
        inner = body[len(quote) : -len(quote)]
        return (
            inner
            if token[:1] in "rR"
            else re.sub(
                r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), inner
            )
        )

    @staticmethod
    def calls(text: str) -> list[Call]:
        """Top-level call statements, with their literal arguments."""
        tokens = Starlark.tokens(text)
        depth = 0
        for _kind, value in tokens:
            if value in ("(", "[", "{"):
                depth += 1
            elif value in (")", "]", "}"):
                depth -= 1
                if depth < 0:
                    raise StarlarkError("a closing bracket with nothing open")
        if depth:
            raise StarlarkError("a bracket that does not close")
        out: list[Call] = []
        index = 0
        while index < len(tokens):
            if tokens[index][0] == "newline":
                index += 1
                continue
            start = index
            target = None
            if (
                index + 2 < len(tokens)
                and tokens[index][0] == "name"
                and tokens[index + 1] == ("punct", "=")
                and tokens[index + 2][0] == "name"
            ):
                target = tokens[index][1]
                index += 2
            receiver = None
            if (
                index + 2 < len(tokens)
                and tokens[index][0] == "name"
                and tokens[index + 1] == ("punct", ".")
            ):
                receiver = tokens[index][1]
                index += 2
            if (
                index + 1 < len(tokens)
                and tokens[index][0] == "name"
                and tokens[index + 1] == ("punct", "(")
            ):
                call = Call(receiver, tokens[index][1], target=target)
                index = Starlark.arguments(tokens, index + 2, call)
                out.append(call)
                continue
            # Anything else (a load(), an if, an expression): passed over to the end of the line.
            index = start + 1
            nesting = 0
            while index < len(tokens) and not (tokens[index][0] == "newline" and nesting == 0):
                if tokens[index][1] in ("(", "[", "{"):
                    nesting += 1
                elif tokens[index][1] in (")", "]", "}"):
                    nesting -= 1
                index += 1
        return out

    @staticmethod
    def arguments(tokens: list[tuple[str, str]], index: int, call: Call) -> int:
        """Read `(... )` from just after the parenthesis; returns the index after it."""
        while index < len(tokens):
            kind, value = tokens[index]
            if value == ")":
                return index + 1
            if kind == "newline" or value == ",":
                index += 1
                continue
            key = None
            if kind == "name" and index + 1 < len(tokens) and tokens[index + 1] == ("punct", "="):
                key = value
                index += 2
            index, argument = Starlark.value(tokens, index)
            if key is None:
                call.positional.append(argument)
            else:
                call.keywords[key] = argument
        raise StarlarkError("a call that does not close")

    @staticmethod
    def value(tokens: list[tuple[str, str]], index: int) -> tuple[int, Any]:
        """A literal (string, number, bool, list, dict) or UNREAD, up to the `,` or `)` ending it."""
        start = index
        result: Any = UNREAD
        kind, value = tokens[index]
        if kind == "string":
            result = Starlark.literal_string(value)
            index += 1
            # Adjacent strings and `+` concatenations of literals stay literal.
            while (
                index + 1 < len(tokens)
                and tokens[index] == ("punct", "+")
                and tokens[index + 1][0] == "string"
            ):
                result += Starlark.literal_string(tokens[index + 1][1])
                index += 2
        elif kind == "number":
            result, index = value, index + 1
        elif kind == "name" and value in ("True", "False", "None"):
            result, index = {"True": True, "False": False, "None": None}[value], index + 1
        elif value == "[":
            items: list[Any] = []
            index += 1
            while tokens[index][1] != "]":
                if tokens[index][0] == "newline" or tokens[index][1] == ",":
                    index += 1
                    continue
                index, item = Starlark.value(tokens, index)
                items.append(item)
            result, index = items, index + 1
        elif value == "{":
            mapping: dict[str, Any] = {}
            index += 1
            while tokens[index][1] != "}":
                if tokens[index][0] == "newline" or tokens[index][1] == ",":
                    index += 1
                    continue
                index, key = Starlark.value(tokens, index)
                if tokens[index][1] == ":":
                    index, item = Starlark.value(tokens, index + 1)
                    if isinstance(key, str):
                        mapping[key] = item
            result, index = mapping, index + 1
        # Anything further before the separator (an operator, a call) makes it unread.
        nesting = 0
        while index < len(tokens):
            text = tokens[index][1]
            if nesting == 0 and text in (",", ")", "]", "}", ":"):
                break
            if text in ("(", "[", "{"):
                nesting += 1
            elif text in (")", "]", "}"):
                nesting -= 1
            if tokens[index][0] != "newline":
                result = UNREAD
            index += 1
        if index == start:
            raise StarlarkError("an argument with no value")
        return index, result


class RepositoryRule:
    """http_archive / git_repository and friends, wherever they are declared."""

    ARCHIVES: ClassVar[frozenset[str]] = frozenset({"http_archive", "http_file", "http_jar"})
    GITS: ClassVar[frozenset[str]] = frozenset({"git_repository", "new_git_repository"})
    LOCALS: ClassVar[frozenset[str]] = frozenset({"local_repository", "new_local_repository"})

    @staticmethod
    def declare(call: Call, field_name: str) -> DeclaredDependency | None:
        name = call.keywords.get("name")
        if not isinstance(name, str):
            return None
        if call.name in RepositoryRule.ARCHIVES:
            urls = call.keywords.get("urls") or (
                [call.keywords["url"]] if isinstance(call.keywords.get("url"), str) else []
            )
            url = (
                next((u for u in urls if isinstance(u, str)), None)
                if isinstance(urls, list)
                else None
            )
            digest = call.keywords.get("sha256")
            integrity = call.keywords.get("integrity")
            recorded = (
                f"sha256:{digest}"
                if isinstance(digest, str) and digest
                else integrity
                if isinstance(integrity, str) and integrity
                else None
            )
            return DeclaredDependency(
                name=name,
                spec=url or "*",
                scope=Scope.BUILD,
                field_name=f"{field_name}{call.name}",
                integrity=recorded,
                note=(
                    "a repository rule: the lock records modules, not repositories; this one is pinned by its checksum"
                    if recorded
                    else "an archive fetched with no checksum: whatever the URL serves is used"
                ),
            )
        if call.name in RepositoryRule.GITS:
            remote = call.keywords.get("remote")
            if not isinstance(remote, str):
                return None
            pin = next(
                (
                    call.keywords[k]
                    for k in ("commit", "tag", "branch")
                    if isinstance(call.keywords.get(k), str)
                ),
                "",
            )
            return DeclaredDependency(
                name=name,
                spec=f"git+{remote}" + (f"#{pin}" if pin else ""),
                scope=Scope.BUILD,
                field_name=f"{field_name}{call.name}",
            )
        if call.name in RepositoryRule.LOCALS:
            path = call.keywords.get("path")
            return DeclaredDependency(
                name=name,
                spec=f"path:{path}" if isinstance(path, str) else "*",
                scope=Scope.BUILD,
                field_name=f"{field_name}{call.name}",
            )
        return None


class Maven:
    """rules_jvm_external's `maven.install(artifacts = [...])` and `maven_install(...)`:
    Maven packages, in the Maven ecosystem."""

    @staticmethod
    def artifacts(call: Call) -> list[DeclaredDependency]:
        out: list[DeclaredDependency] = []
        listed = call.keywords.get("artifacts")
        for artifact in listed if isinstance(listed, list) else []:
            if not isinstance(artifact, str):
                continue
            parts = artifact.split(":")
            if len(parts) >= 3:
                out.append(
                    DeclaredDependency(
                        name=f"{parts[0]}:{parts[1]}",
                        spec=parts[-1],
                        field_name=f"{call.receiver + '.' if call.receiver else ''}{call.name}",
                        ecosystem="maven",
                    )
                )
        return out


class ModuleFile:
    """MODULE.bazel."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            calls = Starlark.calls(content.text)
        except StarlarkError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not readable Starlark: {exc}")
        overrides: dict[str, tuple[str, str | None, str]] = {}
        version_overrides: dict[str, str] = {}
        sources: list[str] = []
        extensions: dict[str, str] = {}
        repo_rules: dict[str, str] = {}
        module_name = module_version = None
        hooks: list[Hook] = []
        for call in calls:
            kw = call.keywords
            if call.name == "module":
                module_name = kw.get("name") if isinstance(kw.get("name"), str) else None
                module_version = kw.get("version") if isinstance(kw.get("version"), str) else None
            elif (
                call.name == "git_override"
                and isinstance(kw.get("module_name"), str)
                and isinstance(kw.get("remote"), str)
            ):
                pin = next(
                    (kw[k] for k in ("commit", "tag", "branch") if isinstance(kw.get(k), str)), ""
                )
                overrides[kw["module_name"]] = (
                    f"git+{kw['remote']}" + (f"#{pin}" if pin else ""),
                    None,
                    "git_override",
                )
            elif call.name == "archive_override" and isinstance(kw.get("module_name"), str):
                urls = kw.get("urls") or ([kw["url"]] if isinstance(kw.get("url"), str) else [])
                url = (
                    next((u for u in urls if isinstance(u, str)), "*")
                    if isinstance(urls, list)
                    else "*"
                )
                integrity = kw.get("integrity") if isinstance(kw.get("integrity"), str) else None
                overrides[kw["module_name"]] = (url, integrity, "archive_override")
            elif call.name == "local_path_override" and isinstance(kw.get("module_name"), str):
                overrides[kw["module_name"]] = (
                    f"path:{kw.get('path')}",
                    None,
                    "local_path_override",
                )
            elif call.name == "single_version_override" and isinstance(kw.get("module_name"), str):
                if isinstance(kw.get("version"), str) and kw["version"]:
                    version_overrides[kw["module_name"]] = kw["version"]
                if isinstance(kw.get("registry"), str):
                    sources.append(f"registry for {kw['module_name']}: {kw['registry']}")
            elif call.name == "multiple_version_override" and isinstance(
                kw.get("module_name"), str
            ):
                versions = kw.get("versions")
                sources.append(
                    f"multiple versions of {kw['module_name']}: {', '.join(v for v in versions if isinstance(v, str)) if isinstance(versions, list) else '?'}"
                )
            elif call.name == "use_extension" and call.target and len(call.positional) >= 2:
                extensions[call.target] = (
                    f"{call.positional[0]}%{call.positional[1]}"
                    if all(isinstance(p, str) for p in call.positional[:2])
                    else "an extension"
                )
                label = call.positional[0]
                if isinstance(label, str) and not label.startswith("@bazel_tools//"):
                    # A module extension's implementation runs during resolution, with network and
                    # filesystem access: code of the module's own, run for every build.
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"module extension {extensions[call.target]}",
                            command=label,
                            ecosystem=ecosystem,
                        )
                    )
            elif (
                call.name == "use_repo_rule"
                and call.target
                and len(call.positional) >= 2
                and isinstance(call.positional[1], str)
            ):
                repo_rules[call.target] = call.positional[1]
                label = call.positional[0]
                if isinstance(label, str) and not label.startswith("@bazel_tools//"):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"repository rule {call.positional[1]}",
                            command=label,
                            ecosystem=ecosystem,
                        )
                    )
        declared: list[DeclaredDependency] = []
        for call in calls:
            kw = call.keywords
            if call.name == "bazel_dep" and call.receiver is None:
                name = kw.get("name")
                if not isinstance(name, str):
                    return BaseEcosystem._err(content, ecosystem, "a bazel_dep without its name")
                version = kw.get("version") if isinstance(kw.get("version"), str) else ""
                override = overrides.get(name)
                spec = override[0] if override else version or "*"
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec=spec,
                        scope=Scope.DEV if kw.get("dev_dependency") is True else Scope.RUNTIME,
                        field_name=f"bazel_dep ({override[2]})" if override else "bazel_dep",
                        alias=kw.get("repo_name") if isinstance(kw.get("repo_name"), str) else None,
                        integrity=override[1] if override else None,
                        note=(
                            f"overridden ({override[2]}): fetched from where the override says, which the lock does not record"
                            if override
                            else None
                            if version
                            else "a bazel_dep with no version: whatever the registry's resolution picks"
                        ),
                    )
                )
            elif call.receiver in extensions:
                if call.name == "install" and "artifacts" in kw:
                    declared.extend(Maven.artifacts(call))
                else:
                    sources.append(f"extension {extensions[call.receiver]} tag {call.name}")
            elif call.receiver is None and call.name in repo_rules:
                rule = Call(None, repo_rules[call.name], call.positional, call.keywords)
                repository = RepositoryRule.declare(rule, "use_repo_rule ")
                if repository is not None:
                    declared.append(repository)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=module_name,
            version=module_version,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            overrides=version_overrides,
            sources=tuple(sources),
        )


class Workspace:
    """WORKSPACE / WORKSPACE.bazel: repository rules called directly."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            calls = Starlark.calls(content.text)
        except StarlarkError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not readable Starlark: {exc}")
        declared: list[DeclaredDependency] = []
        macros: list[str] = []
        for call in calls:
            repository = RepositoryRule.declare(call, "")
            if repository is not None:
                declared.append(repository)
            elif call.name in ("maven_install",):
                declared.extend(Maven.artifacts(call))
            elif call.name not in (
                "workspace",
                "load",
                "register_toolchains",
                "register_execution_platforms",
                "bind",
            ):
                macros.append(call.name)
        sources = [
            f"macro {name}() expands to more repositories, which only evaluating the workspace shows"
            for name in dict.fromkeys(macros)
        ]
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class BuildFile:
    """BUILD.bazel: which external repositories its targets use."""

    LABEL: ClassVar[re.Pattern[str]] = re.compile(r"^@@?([A-Za-z0-9_.~+\-]+)//")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            tokens = Starlark.tokens(content.text)
        except StarlarkError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not readable Starlark: {exc}")
        used = sorted(
            {
                found.group(1)
                for kind, text in tokens
                if kind == "string"
                and (found := BuildFile.LABEL.match(Starlark.literal_string(text)))
            }
        )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            sources=(f"uses external repositories {', '.join(used)}",) if used else (),
        )


class ModuleLock:
    """MODULE.bazel.lock."""

    FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"/modules/(?P<name>[^/]+)/(?P<version>[^/]+)/source\.json$"
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        if "lockFileVersion" not in data:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a MODULE.bazel.lock without its lockFileVersion",
            )
        graph = data.get("moduleDepGraph")
        if isinstance(graph, dict):
            return ModuleLock.graph(content, ecosystem, graph)
        hashes = data.get("registryFileHashes")
        if not isinstance(hashes, dict):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a MODULE.bazel.lock with neither a module graph nor registry file hashes",
            )
        entries: list[LockEntry] = []
        for url, digest in sorted(hashes.items()):
            found = ModuleLock.FILE.search(str(url))
            if found is None:
                continue
            # A module whose source.json resolution fetched is one the graph selected; the
            # hash is of that file, which names the module's archive and its integrity.
            registry = str(url)[: found.start()]
            entries.append(
                LockEntry(
                    name=found.group("name"),
                    version=found.group("version"),
                    integrity=f"sha256:{digest}" if isinstance(digest, str) and digest else None,
                    resolved_from=None
                    if registry.startswith("https://bcr.bazel.build")
                    else registry or None,
                )
            )
        yanked = data.get("selectedYankedVersions")
        entries = [
            LockEntry(
                name=e.name,
                version=e.version,
                integrity=e.integrity,
                resolved_from=e.resolved_from,
                deprecated="selected though yanked",
            )
            if isinstance(yanked, dict) and f"{e.name}@{e.version}" in yanked
            else e
            for e in entries
        ]
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def graph(content: FileContent, ecosystem: str, graph: dict[str, Any]) -> LockGraph:
        """The lock of Bazel 7.0-7.1: the module graph with each module's repo spec."""
        entries: list[LockEntry] = []
        names: dict[str, str] = {}
        for key, node in graph.items():
            if isinstance(node, dict) and key != "<root>":
                names[key] = (
                    f"{node.get('name') or key.split('@')[0]}@{node.get('version') or key.partition('@')[2]}"
                )
        root = graph.get("<root>") if isinstance(graph.get("<root>"), dict) else {}
        direct = (
            set((root or {}).get("deps", {}).values())
            if isinstance((root or {}).get("deps"), dict)
            else set()
        )
        for key, node in sorted(graph.items()):
            if key == "<root>" or not isinstance(node, dict):
                continue
            name, _, version = names[key].partition("@")
            spec = node.get("repoSpec") if isinstance(node.get("repoSpec"), dict) else {}
            attributes = (
                (spec or {}).get("attributes")
                if isinstance((spec or {}).get("attributes"), dict)
                else {}
            )
            integrity = (attributes or {}).get("integrity")
            urls = (attributes or {}).get("urls")
            deps = node.get("deps") if isinstance(node.get("deps"), dict) else {}
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=integrity if isinstance(integrity, str) else None,
                    resolved_from=urls[0]
                    if isinstance(urls, list)
                    and urls
                    and isinstance(urls[0], str)
                    and "bcr.bazel.build" not in urls[0]
                    and "github.com" not in urls[0]
                    else None,
                    dependencies=tuple(names[k] for k in (deps or {}).values() if k in names),
                    direct=key in direct,
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class BazelEcosystem(BaseEcosystem):
    """Bazel modules and external repositories."""

    id = "bazel"
    purl_type = "bazel"
    manifest_globs: tuple[str, ...] = (
        "**/MODULE.bazel",
        "**/WORKSPACE",
        "**/WORKSPACE.bazel",
        "**/WORKSPACE.bzlmod",
        "**/BUILD.bazel",
    )
    lockfile_globs: tuple[str, ...] = ("**/MODULE.bazel.lock",)
    registry_hosts: frozenset[str] = frozenset({"bcr.bazel.build", "registry.bazel.build"})

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        basename = content.basename
        if basename == "MODULE.bazel":
            return ModuleFile.parse(content, self.id)
        if basename == "BUILD.bazel":
            return BuildFile.parse(content, self.id)
        return Workspace.parse(content, self.id)

    def parse_in_tree(self, content: FileContent, files: Mapping[str, Any]) -> Manifest:
        """A repository part way through the move to Bzlmod keeps its WORKSPACE beside MODULE.bazel,
        and whether Bazel still reads it depends on the files around it, so each of its
        dependencies says so: with WORKSPACE.bzlmod present, Bzlmod reads that file instead, and
        Bazel 8 reads no WORKSPACE without --enable_workspace. They stay in the inventory --
        Bzlmod can be turned off -- but are not presented as what a build fetches."""
        manifest = self.parse_manifest(content)
        if content.basename not in ("WORKSPACE", "WORKSPACE.bazel") or manifest.parse_error:
            return manifest
        reason = Migration.superseded(content.path, files)
        if reason is None:
            return manifest
        return dataclasses.replace(
            manifest,
            dependencies=tuple(
                dataclasses.replace(d, note=f"{reason}{'; ' + d.note if d.note else ''}")
                for d in manifest.dependencies
            ),
            sources=(*manifest.sources, f"legacy WORKSPACE: {reason}"),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return ModuleLock.parse(content, self.id)


class Migration:
    """Whether a WORKSPACE is still read, in a repository moving to Bzlmod."""

    @staticmethod
    def _text(files: Mapping[str, Any], path: str) -> str | None:
        found = files.get(path)
        if found is None:
            return None
        return getattr(found, "text", None) if not isinstance(found, str) else found

    @staticmethod
    def superseded(path: str, files: Mapping[str, Any]) -> str | None:
        directory = path.rpartition("/")[0]
        prefix = f"{directory}/" if directory else ""
        if f"{prefix}WORKSPACE.bzlmod" in files:
            return "not read while Bzlmod is enabled: WORKSPACE.bzlmod replaces it"
        if f"{prefix}MODULE.bazel" not in files:
            return None
        version = (Migration._text(files, f"{prefix}.bazelversion") or "").strip()
        major = version.split(".", 1)[0]
        rc = Migration._text(files, f"{prefix}.bazelrc") or ""
        if major.isdigit() and int(major) >= 8 and "--enable_workspace" not in rc:
            return (
                f"not read by Bazel {version}, which reads no WORKSPACE without --enable_workspace"
            )
        return None


__all__ = [
    "BazelEcosystem",
    "BuildFile",
    "Maven",
    "ModuleFile",
    "ModuleLock",
    "RepositoryRule",
    "Starlark",
    "Workspace",
]
