"""Go: go.mod and go.sum, go.work, and the toolchain and module requirements they declare."""

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

# Each `*Ecosystem` imported below from its own module (GitHub Actions, Bazel, CocoaPods, Composer,
# Conan, Conda, CRAN, Gradle, Hex, NuGet, Pub, RubyGems, Swift) is re-exported where it always lived.
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class GoModFile:
    """One `go.mod`, read once for both of the questions asked of it.

    From Go 1.17 a module's `go.mod` lists every module its build needs, each at the version
    minimal version selection chose, with `// indirect` on the ones no package of the module
    imports directly. That is the resolution: `go.sum` is not -- it keeps hashes for versions the
    build no longer selects, and for module files only -- so `go.mod` is read as the lockfile and
    `go.sum` completes it with integrity (see `LockGraph.companion`).
    """

    _REQUIRE: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*([^\s()]+)\s+(v[^\s/]+)(\s*//\s*indirect)?"
    )
    _REPLACE: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:replace\s+)?(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?\s*$"
    )
    """`replace old [vX] => new [vY]`, on one line or inside a `replace ( ... )` block."""
    _EXCLUDE: ClassVar[re.Pattern[str]] = re.compile(r"^\s*(?:exclude\s+)?(\S+)\s+(v\S+)\s*$")
    _GO_DIRECTIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(go|toolchain)\s+(?:go)?(\d{1,4}(?:\.\d{1,6}){1,2})\s*$"
    )
    _TOOL: ClassVar[re.Pattern[str]] = re.compile(r"^\s*(?:tool\s+)?([^\s()]+)\s*$")

    #: Every directive `go.mod` and `go.work` allow. The go command refuses anything else, and so
    #: does this reader: a line it skipped silently was a file it reported as read.
    BLOCKS: ClassVar[frozenset[str]] = frozenset(
        {"require", "replace", "exclude", "retract", "tool", "godebug", "ignore", "use"}
    )

    def __init__(self, text: str) -> None:
        self.module: str | None = None
        self.requires: list[tuple[str, str, bool]] = []
        self.replaces: dict[str, tuple[str, str | None]] = {}
        self.excludes: set[tuple[str, str]] = set()
        self.tools: list[str] = []
        self.language: str | None = None
        self.toolchain: str | None = None
        self.errors: list[str] = []
        block: str | None = None
        block_line = 0
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.rstrip()
            stripped = line.split("//", 1)[0].strip() if "indirect" not in line else line.strip()
            if not stripped:
                continue
            plain = stripped.split("//", 1)[0].strip()
            if block is None and plain.startswith("module "):
                self.module = plain.split(None, 1)[1].strip().strip('"')
                continue
            directive = self._GO_DIRECTIVE.match(plain)
            if directive and block is None:
                if directive.group(1) == "toolchain":
                    self.toolchain = directive.group(2)
                else:
                    self.language = directive.group(2)
                continue
            if block is None and re.match(r"^toolchain\s+(?:default|go\S+)$", plain):
                continue
            opened = re.match(r"^(\w+)\s*\(\s*$", plain)
            if opened and block is None:
                # Errors name the line and never repeat its text: a go.mod is attacker-shaped
                # input, and whatever sits on a malformed line (a token pasted by mistake) would
                # otherwise travel into every report format.
                if opened.group(1) not in self.BLOCKS:
                    self.errors.append(f"line {number}: a block opened by an unknown directive")
                block, block_line = opened.group(1), number
                continue
            if block is not None and plain == ")":
                block = None
                continue
            kind = block
            body = stripped
            if block is None:
                word = plain.split(None, 1)[0]
                if word not in self.BLOCKS or len(plain.split(None, 1)) < 2:
                    self.errors.append(f"line {number}: not a go.mod directive")
                    continue
                kind, body = word, stripped[len(word) :].strip()
            matched = True
            if kind == "require":
                found = self._REQUIRE.match(body)
                matched = found is not None
                if found:
                    self.requires.append((found.group(1), found.group(2), bool(found.group(3))))
            elif kind == "replace":
                found = self._REPLACE.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.replaces[found.group(1)] = (found.group(3), found.group(4))
            elif kind == "exclude":
                found = self._EXCLUDE.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.excludes.add((found.group(1), found.group(2)))
            elif kind == "tool":
                found = self._TOOL.match(body.split("//", 1)[0])
                matched = found is not None
                if found:
                    self.tools.append(found.group(1))
            elif kind == "retract":
                matched = bool(
                    re.match(
                        r"^(?:v\S+|\[\s*v\S+\s*,\s*v\S+\s*\])$", body.split("//", 1)[0].strip()
                    )
                )
            elif kind == "godebug":
                matched = bool(re.match(r"^[\w.-]+=\S+$", body.split("//", 1)[0].strip()))
            elif kind in ("use", "ignore"):
                matched = bool(body.split("//", 1)[0].strip())
            if not matched:
                self.errors.append(f"line {number}: malformed {kind} entry")
        if block is not None:
            self.errors.append(f"line {block_line}: {block} block is never closed")

    @property
    def stdlib(self) -> str | None:
        """The standard library's version: the toolchain directive's, or failing that the `go`
        directive's -- the reading govulncheck and OSV-Scanner apply."""
        version = self.toolchain or self.language
        if not version:
            return None
        parts = version.split(".")
        return "v" + ".".join(parts + ["0"] * (3 - len(parts)))

    @staticmethod
    def lists_direct_only(language: str | None) -> bool:
        """Whether a `go.mod` at this `go` version leaves its indirect modules out: before 1.17
        (and with no `go` line, which the go command reads as 1.16) only `go.sum` names them."""
        if not language:
            return True
        parts = language.split(".")
        try:
            return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0) < (1, 17)
        except ValueError:
            return False

    def untidied(self) -> bool:
        """A 1.17-or-later `go.mod` that requires modules but marks none `// indirect` was not
        tidied under 1.17's rules (its `go` line was raised by hand, or `go mod tidy` never ran),
        so it too names only what it imports. `go.sum` then completes it: a module whose
        requirements really have no dependencies of their own adds nothing from it."""
        return bool(self.requires) and not any(indirect for _, _, indirect in self.requires)

    def tool_modules(self) -> set[str]:
        """Modules that provide a `tool` directive's package (the longest required prefix)."""
        provided: set[str] = set()
        for tool in self.tools:
            owners = [
                name for name, _, _ in self.requires if tool == name or tool.startswith(name + "/")
            ]
            if owners:
                provided.add(max(owners, key=len))
        return provided


class GoEcosystem(BaseEcosystem):
    id = "gomod"

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.rsplit("/", 1)[0] if "/" in name else None

    def is_builtin(self, name: str) -> bool:
        return name == "stdlib"

    purl_type = "golang"
    manifest_globs: tuple[str, ...] = ("**/go.mod", "**/go.work")
    lockfile_globs: tuple[str, ...] = (
        "**/go.mod",
        "**/go.sum",
        "**/go.work.sum",
        "**/vendor/modules.txt",
    )
    registry_hosts: frozenset[str] = frozenset({"proxy.golang.org", "sum.golang.org"})

    def normalize_name(self, name: str) -> str:
        """Go module paths are case-sensitive but case-encoded in the proxy.

        Lowercased for comparison only. Two paths differing solely in case are a
        classic confusion vector, so they must compare equal for typosquat
        purposes even though they are distinct modules.
        """
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        """What a `go.mod` declares: the modules it requires directly (not `// indirect`, which
        the go command records for the build and nobody wrote), replacement targets, tools, the
        Go version, and the standard library the toolchain compiles in. A `go.work` declares the
        modules of a workspace, which are read as projects of their own."""
        if content.basename == "go.work":
            return GoWork.parse(content, self.id)
        mod = GoModFile(content.text)
        if mod.errors:
            return BaseEcosystem._err(content, self.id, "; ".join(mod.errors[:3]))
        declared: list[DeclaredDependency] = []
        tools = mod.tool_modules()
        for name, version, indirect in mod.requires:
            if indirect and name not in tools:
                continue
            if (name, version) in mod.excludes:
                continue
            target, target_version = mod.replaces.get(name, (None, None))
            if target is not None and target.startswith((".", "/")):
                declared.append(
                    DeclaredDependency(
                        name=name, spec=target, scope=Scope.RUNTIME, field_name="replace"
                    )
                )
                continue
            if target is not None and target_version:
                declared.append(
                    DeclaredDependency(
                        name=target,
                        spec=target_version,
                        scope=Scope.RUNTIME,
                        field_name="replace",
                        alias=name,
                    )
                )
                continue
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=version,
                    scope=Scope.TOOL if name in tools else Scope.RUNTIME,
                    field_name="tool" if name in tools else "require",
                )
            )
        if mod.stdlib:
            # The standard library is compiled into every binary at the toolchain's version; Go's
            # advisories file it under the module `stdlib`, and without it a `net/http` or
            # `crypto/tls` advisory matched no module in the graph.
            declared.append(
                DeclaredDependency(
                    name="stdlib", spec=mod.stdlib, scope=Scope.RUNTIME, field_name="toolchain"
                )
            )
        if mod.language:
            declared.append(
                DeclaredDependency(
                    name="go", spec=f">={mod.language}", scope=Scope.PLATFORM, field_name="go"
                )
            )
        return Manifest(
            path=content.path, ecosystem=self.id, name=mod.module, dependencies=tuple(declared)
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name in ("go.sum", "go.work.sum"):
            return self._parse_sum(content)
        if name == "modules.txt":
            return self._parse_vendor(content)
        return self._parse_build_list(content)

    def _parse_build_list(self, content: FileContent) -> LockGraph:
        """`go.mod`'s requirements as the resolution: every module at the selected version, direct
        unless `// indirect`, replacements applied, exclusions honoured."""
        mod = GoModFile(content.text)
        if mod.errors:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error="; ".join(mod.errors[:3])
            )
        tools = mod.tool_modules()
        entries: list[LockEntry] = []
        for name, version, indirect in mod.requires:
            if (name, version) in mod.excludes:
                continue
            target, target_version = mod.replaces.get(name, (None, None))
            if target is not None and target.startswith((".", "/")):
                # A local replacement: the module's code is the directory, read as source here.
                entries.append(
                    LockEntry(
                        name=name, version="", resolved_from=target, direct=not indirect, local=True
                    )
                )
                continue
            if target is not None and target_version:
                entries.append(
                    LockEntry(name=target, version=target_version, direct=not indirect, alias=name)
                )
                continue
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    direct=not indirect or name in tools,
                    scope=Scope.TOOL if name in tools else Scope.RUNTIME,
                )
            )
        if mod.stdlib:
            # BSD-3-Clause: the Go project's own licence for the standard library.
            entries.append(
                LockEntry(name="stdlib", version=mod.stdlib, direct=True, license="BSD-3-Clause")
            )
        return LockGraph(
            path=content.path,
            ecosystem=self.id,
            entries=tuple(entries),
            integrity_elsewhere=True,
            completed_by_companion=GoModFile.lists_direct_only(mod.language) or mod.untidied(),
        )

    def _parse_sum(self, content: FileContent) -> LockGraph:
        """`go.sum`: a hash of each module zip (`h1:`) and of each `go.mod` it read. Only zip
        hashes are integrity for a module's code; a `/go.mod` line hashes a file the build read
        to plan, not the code it compiled. A companion: it completes `go.mod`'s entries."""
        seen: dict[tuple[str, str], str] = {}
        for raw in content.text.splitlines():
            parts = raw.split()
            if len(parts) != 3 or parts[1].endswith("/go.mod"):
                continue
            seen.setdefault((parts[0], parts[1]), parts[2])
        entries = [LockEntry(name=n, version=v, integrity=d) for (n, v), d in sorted(seen.items())]
        return LockGraph(
            path=content.path, ecosystem=self.id, entries=tuple(entries), companion=True
        )

    def _parse_vendor(self, content: FileContent) -> LockGraph:
        """`vendor/modules.txt`: `# module version [=> replacement]` per vendored module, `##
        explicit` when go.mod requires it directly. A companion: the modules `go.mod` selects are
        built from the copies in `vendor/`."""
        entries: list[LockEntry] = []
        for raw in content.text.splitlines():
            if not raw.startswith("# "):
                continue
            parts = raw[2:].split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                entries.append(
                    LockEntry(
                        name=parts[0], version=parts[1], resolved_from=f"vendored:{content.path}"
                    )
                )
            elif len(parts) >= 3 and parts[1] == "=>":
                entries.append(
                    LockEntry(name=parts[0], version="", resolved_from=f"vendored:{content.path}")
                )
        return LockGraph(
            path=content.path, ecosystem=self.id, entries=tuple(entries), companion=True
        )


class GoWork:
    """`go.work`: the modules a workspace builds together (`use`), its Go version, and
    workspace-wide replacements. Each used module is a project with its own `go.mod`."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        mod = GoModFile(content.text)
        if mod.errors:
            return BaseEcosystem._err(content, ecosystem, "; ".join(mod.errors[:3]))
        uses: list[str] = []
        block = False
        for raw in content.text.splitlines():
            stripped = raw.split("//", 1)[0].strip()
            if stripped.startswith("use ("):
                block = True
                continue
            if block and stripped == ")":
                block = False
                continue
            if stripped.startswith("use "):
                uses.append(stripped[4:].strip())
            elif block and stripped:
                uses.append(stripped)
        declared: list[DeclaredDependency] = []
        if mod.language:
            declared.append(
                DeclaredDependency(
                    name="go", spec=f">={mod.language}", scope=Scope.PLATFORM, field_name="go"
                )
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            includes=tuple(("workspace", u) for u in uses),
        )


__all__ = ["GoEcosystem", "GoModFile", "GoWork"]
