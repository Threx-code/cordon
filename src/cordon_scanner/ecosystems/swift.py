"""Swift Package Manager.

```
  Package.swift      .package(url:|path:|id:, from:|exact:|.upTo...(from:)|"a"..<"b"|branch:|
                     revision:), .binaryTarget(url:checksum:|path:), .plugin(...), platforms,
                     // swift-tools-version
  Package.resolved   version 1 ({"object": {"pins": [...]}}), 2 and 3 ({"pins": [...]}): each
                     pin's identity, location, and state (version and revision, or branch and
                     revision, or revision alone)
```

`Package.swift` is a Swift program; its `.package(...)` calls are read as the declarations they
are, never compiled or run. SwiftPM has no central registry -- a package is a git repository
fetched over HTTPS, or a Swift package registry identity -- so a git source is its ordinary
distribution, not a departure from one.
"""

from __future__ import annotations

import json
import re
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


class SwiftIdentity:
    """A Swift package's name for advisories and the rest of the inventory: `owner/repo` from its
    location (`https://github.com/apple/swift-log.git` -> `apple/swift-log`), the form the Swift
    advisories in OSV and the popular-package lists use. SwiftPM's own identity is the last path
    component alone, which two forks share; `owner/repo` tells them apart. A local path keeps its
    directory name."""

    @staticmethod
    def of(location: str) -> str:
        text = location.strip().rstrip("/").removesuffix(".git")
        if "://" in text:
            path = (
                text.split("://", 1)[1].split("/", 1)[1] if "/" in text.split("://", 1)[1] else ""
            )
        elif re.match(r"^[\w.\-]+@[\w.\-]+:", text):
            path = text.split(":", 1)[1]
        else:
            return text.rpartition("/")[2].lower()
        parts = [p for p in path.split("/") if p]
        return (
            "/".join(parts[-2:]).lower()
            if len(parts) >= 2
            else (parts[0].lower() if parts else text.lower())
        )


class SwiftManifest:
    STRING: ClassVar[re.Pattern[str]] = re.compile(r'"((?:[^"\\\n]|\\.){0,1024})"')

    @staticmethod
    def code(text: str) -> str:
        """Comments removed, strings kept (`//` inside a URL string is not a comment)."""
        out: list[str] = []
        index = 0
        while index < len(text):
            if text.startswith('"', index):
                end = index + 1
                while end < len(text) and text[end] != '"' and text[end] != "\n":
                    end += 2 if text[end] == "\\" else 1
                out.append(text[index : end + 1])
                index = end + 1
            elif text.startswith("//", index):
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                index = len(text) if end < 0 else end + 2
            else:
                out.append(text[index])
                index += 1
        return "".join(out)

    @staticmethod
    def calls(code: str, name: str) -> list[str]:
        """The argument text of each `.<name>(...)` call, parentheses balanced."""
        out: list[str] = []
        for found in re.finditer(rf"\.{name}\s*\(", code):
            depth, index = 1, found.end()
            while index < len(code) and depth:
                character = code[index]
                if character == '"':
                    end = code.find('"', index + 1)
                    index = len(code) if end < 0 else end + 1
                    continue
                depth += character == "("
                depth -= character == ")"
                index += 1
            if depth:
                raise ValueError("a call is never closed")
            out.append(code[found.end() : index - 1])
        return out

    @staticmethod
    def argument(arguments: str, label: str) -> str | None:
        found = re.search(rf"\b{label}\s*:\s*\"((?:[^\"\\\n]|\\.){{0,1024}})\"", arguments)
        return found.group(1) if found else None

    @staticmethod
    def requirement(arguments: str) -> str:
        """The version requirement of a `.package(...)` call, written as the range it means."""
        found = re.search(r"\.upToNextMajor\s*\(\s*from\s*:\s*\"([^\"]+)\"", arguments)
        if found:
            return f">= {found.group(1)}, < next major"
        found = re.search(r"\.upToNextMinor\s*\(\s*from\s*:\s*\"([^\"]+)\"", arguments)
        if found:
            return f">= {found.group(1)}, < next minor"
        found = re.search(r'"([^"]+)"\s*(\.\.<|\.\.\.)\s*"([^"]+)"', arguments)
        if found:
            upper = "<" if found.group(2) == "..<" else "<="
            return f">= {found.group(1)}, {upper} {found.group(3)}"
        for label, form in (("from", ">= {} , < next major"), ("exact", "{}")):
            value = SwiftManifest.argument(arguments, label)
            if value is not None:
                return form.format(value).replace(" , ", ", ")
        found = re.search(r"\.exact\s*\(\s*\"([^\"]+)\"\s*\)", arguments)
        if found:
            return found.group(1)
        return "*"

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        tools = re.match(r"\s*//\s*swift-tools-version\s*:\s*([\d.]+)", content.text)
        if tools is None:
            return BaseEcosystem._err(
                content, ecosystem, "no `// swift-tools-version:` line: not a Package.swift"
            )
        try:
            code = SwiftManifest.code(content.text)
            packages = SwiftManifest.calls(code, "package")
            binaries = SwiftManifest.calls(code, "binaryTarget")
            plugins = SwiftManifest.calls(code, "plugin")
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable Package.swift: {exc}")
        if "Package(" not in code:
            return BaseEcosystem._err(content, ecosystem, "no `Package(...)`: not a Package.swift")
        declared: list[DeclaredDependency] = []
        for arguments in packages:
            url = SwiftManifest.argument(arguments, "url")
            path = SwiftManifest.argument(arguments, "path")
            registry = SwiftManifest.argument(arguments, "id")
            if path is not None:
                declared.append(
                    DeclaredDependency(
                        name=SwiftIdentity.of(path), spec=f"path:{path}", field_name="dependencies"
                    )
                )
                continue
            if registry is not None:
                # A Swift package registry identity: `scope.name`.
                declared.append(
                    DeclaredDependency(
                        name=registry.lower(),
                        spec=SwiftManifest.requirement(arguments),
                        field_name="dependencies",
                    )
                )
                continue
            if url is None:
                continue
            branch = SwiftManifest.argument(arguments, "branch")
            revision = SwiftManifest.argument(arguments, "revision")
            if branch is not None or revision is not None:
                spec = f"git+{url}#{branch or revision}"
            else:
                spec = SwiftManifest.requirement(arguments)
            declared.append(
                DeclaredDependency(
                    name=SwiftIdentity.of(url),
                    spec=spec,
                    field_name="dependencies",
                    source=url if not spec.startswith("git+") else None,
                )
            )
        hooks: list[Hook] = []
        for arguments in binaries:
            name = SwiftManifest.argument(arguments, "name") or "binary"
            url = SwiftManifest.argument(arguments, "url")
            path = SwiftManifest.argument(arguments, "path")
            checksum = SwiftManifest.argument(arguments, "checksum")
            # A prebuilt binary linked into the product: code nobody reviews as source. SwiftPM
            # verifies a remote one against `checksum:` and refuses one without -- so with a
            # checksum it is a pinned artefact, and without one it is reported.
            if path:
                spec, note = f"path:{path}", "a prebuilt binary target committed to the repository"
            elif url and checksum and re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
                spec, note = (
                    "*",
                    f"a prebuilt binary target from {url}, pinned by its SHA-256 checksum in Package.swift",
                )
            else:
                spec, note = (
                    url or "*",
                    "a prebuilt binary target with no checksum: SwiftPM refuses to fetch it",
                )
            declared.append(
                DeclaredDependency(
                    name=name.lower(),
                    spec=spec,
                    scope=Scope.RUNTIME,
                    field_name="binaryTarget",
                    platform=("binary target",),
                    source=url if spec == "*" else None,
                    note=note,
                )
            )
        for arguments in plugins:
            if "capability" in arguments:
                name = SwiftManifest.argument(arguments, "name") or "plugin"
                command = "build tool" if "buildTool" in arguments else "command"
                hooks.append(
                    Hook(
                        kind="build",
                        path=content.path,
                        name=f"plugin {name}",
                        command=command,
                        ecosystem=ecosystem,
                    )
                )
        for found in re.finditer(
            r"\.(macOS|iOS|tvOS|watchOS|visionOS|macCatalyst|driverKit)\s*\(\s*(?:\.v([\d_]+)|\"([\d.]+)\")",
            code,
        ):
            version = (found.group(2) or found.group(3) or "").replace("_", ".")
            declared.append(
                DeclaredDependency(
                    name=found.group(1).lower(),
                    spec=f">= {version}",
                    scope=Scope.PLATFORM,
                    field_name="platforms",
                )
            )
        declared.append(
            DeclaredDependency(
                name="swift",
                spec=f">= {tools.group(1)}",
                scope=Scope.PLATFORM,
                field_name="swift-tools-version",
            )
        )
        package_name = re.search(r"Package\s*\(\s*name\s*:\s*\"([^\"]+)\"", code)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=package_name.group(1).lower() if package_name else None,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
        )


class SwiftResolved:
    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        version = data.get("version")
        holder = data.get("object") if version == 1 else data
        pins = holder.get("pins") if isinstance(holder, dict) else None
        if not isinstance(pins, list):
            return LockGraph(path=content.path, ecosystem=ecosystem, parse_error="no `pins` list")
        entries: list[LockEntry] = []
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            location = str(pin.get("location") or pin.get("repositoryURL") or "")
            identity = (
                SwiftIdentity.of(location)
                if location
                else str(pin.get("identity") or pin.get("package") or "")
            ).lower()
            raw_state = pin.get("state")
            state: dict[str, Any] = raw_state if isinstance(raw_state, dict) else {}
            kind = str(pin.get("kind", "remoteSourceControl"))
            revision = str(state.get("revision") or "")
            pinned = state.get("version")
            branch = state.get("branch")
            local = kind == "localSourceControl" or location.startswith(("/", "file:"))
            # Every pin records the commit it checked out: a version's tag is resolved to that
            # revision, which is what the next resolution uses.
            resolved_version = pinned if isinstance(pinned, str) and pinned else revision
            resolved_from = (
                f"git+{location}#{revision}"
                if location and revision and not local
                else location or None
            )
            entries.append(
                LockEntry(
                    name=identity,
                    version=resolved_version,
                    resolved_from=resolved_from,
                    local=local,
                    platform=(f"branch {branch}",) if isinstance(branch, str) and branch else (),
                )
            )
        return LockGraph(
            path=content.path, ecosystem=ecosystem, entries=tuple(entries), integrity_elsewhere=True
        )


class SwiftEcosystem(BaseEcosystem):
    id = "swift"
    purl_type = "swift"
    manifest_globs: tuple[str, ...] = ("**/Package.swift",)
    lockfile_globs: tuple[str, ...] = ("**/Package.resolved",)
    registry_hosts: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})
    records_integrity = False
    """A pin records the commit, which is what a git source's integrity is; Package.resolved has
    no archive hash (a binary target's checksum lives in Package.swift)."""
    git_distribution = True
    """Git over HTTPS is how SwiftPM distributes every package: a git source is the ordinary case,
    and only what can move (a branch) is worth reporting."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        """SwiftPM's distribution is a git repository over HTTPS: that is the ordinary source, so
        any HTTPS location -- pinned to its commit or not -- is "the registry" for the source
        rules. A branch moves, and the manifest rule for mutable references reports it."""
        if url:
            lowered = url.lower().removeprefix("git+")
            archive = lowered.split("#", 1)[0].endswith(
                (".zip", ".tar.gz", ".tgz", ".artifactbundle")
            )
            if lowered.startswith("https://") and not archive:
                return True
        return super().is_registry_host(url)

    def parse_manifest(self, content: FileContent) -> Manifest:
        return SwiftManifest.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return SwiftResolved.parse(content, self.id)


__all__ = ["SwiftEcosystem", "SwiftIdentity", "SwiftManifest", "SwiftResolved"]
