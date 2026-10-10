"""Homebrew: Brewfiles, and the formulae and casks a tap is made of.

```
  Brewfile            tap (with a custom remote), brew (with args and options, tap-qualified
                      names), cask, mas (with its App Store id), vscode, whalebrew -- what
                      `brew bundle` installs, at whatever version is current: a Brewfile pins
                      nothing
  Brewfile.lock.json  the versions (and bottle checksums) `brew bundle` recorded, in releases
                      that wrote one
  Formula/*.rb        a formula: its source url and sha256 (in `stable do` or at the top), head,
                      depends_on (with => :build / :test / :optional / :recommended), on_macos /
                      on_linux / on_arm / on_intel blocks, uses_from_macos, resources and patches
                      with their checksums, bottle checksums, and `def install`
  Cellar/<name>/<version>/INSTALL_RECEIPT.json
                      an installed keg: whether it was installed on request or as a dependency,
                      its tap, and its runtime dependencies at the versions installed (the
                      closure; `declared_directly` marks the formula's own)
  Casks/*.rb          a cask: version, sha256 (or :no_check), url, depends_on formula / cask,
                      and the preflight / postflight / installer scripts it runs
```

Formulae and casks are Ruby; nothing here evaluates them. They are read line by line for the
declarations above, which is the form Homebrew's own style requires them to be written in.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.content import FileContent


STRING = r'"((?:[^"\\]|\\.)*)"'


class Ruby:
    """The few Ruby forms Homebrew's DSL is written in."""

    BLOCK_OPEN: ClassVar[re.Pattern[str]] = re.compile(r"\bdo(?:\s*\|[^|]*\|)?\s*(?:#.*)?$")

    @staticmethod
    def lines(text: str) -> Iterator[tuple[int, str]]:
        """`(number, code)`, comments dropped -- a `#` outside a string -- and a single-quoted
        literal written as the double-quoted one it equals (`brew 'jq'` is `brew "jq"`)."""
        for number, raw in enumerate(text.splitlines(), start=1):
            code = Ruby.strip_comment(raw).rstrip()
            if code.strip():
                yield number, Ruby.double_quoted(code)

    @staticmethod
    def double_quoted(code: str) -> str:
        """Each single-quoted literal outside a double-quoted one, double-quoted."""
        out: list[str] = []
        quote = ""
        for char in code:
            if quote == '"':
                if char == '"' and not (out and out[-1] == "\\"):
                    quote = ""
            elif quote == "'":
                if char == "'":
                    quote, char = "", '"'
                elif char == '"':
                    char = '\\"'
            elif char == '"':
                quote = '"'
            elif char == "'":
                quote, char = "'", '"'
            out.append(char)
        return "".join(out)

    @staticmethod
    def strip_comment(line: str) -> str:
        quote = ""
        for index, char in enumerate(line):
            if quote:
                if char == "\\":
                    continue
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == "#" and not line[index:].startswith("#{"):
                return line[:index]
        return line

    @staticmethod
    def balanced(text: str) -> bool:
        """`do` / `end` (and `class` / `def` / `if` openers ending with `end`) close: a Ruby file
        cut short does not."""
        depth = 0
        for _number, line in Ruby.lines(text):
            stripped = line.strip()
            # A keyword opener starts its line; a trailing `if` / `unless` modifier opens nothing.
            keyword = re.match(
                r"^(?:class|module|def|if|unless|case|begin|while|until)\b", stripped
            ) and not re.search(r"\bend$", stripped)
            if Ruby.BLOCK_OPEN.search(stripped) or keyword:
                depth += 1
            if re.match(r"^end\b", stripped):
                depth -= 1
        return depth == 0


class Formula:
    """Formula/<name>.rb."""

    DEPENDS: ClassVar[re.Pattern[str]] = re.compile(
        rf"^\s*depends_on\s+{STRING}(?:\s*=>\s*(?P<tags>\[[^\]]*\]|:\w+))?"
    )
    USES: ClassVar[re.Pattern[str]] = re.compile(
        rf"^\s*uses_from_macos\s+{STRING}(?:\s*=>\s*(?P<tags>\[[^\]]*\]|:\w+))?"
    )
    FIELD: ClassVar[re.Pattern[str]] = re.compile(rf"^\s*(url|sha256|version|mirror)\s+{STRING}")
    SCOPES: ClassVar[dict[str, Scope]] = {
        ":build": Scope.BUILD,
        ":test": Scope.TEST,
        ":optional": Scope.OPTIONAL,
        ":recommended": Scope.RUNTIME,
    }
    CONDITIONS: ClassVar[dict[str, str]] = {
        "on_macos": "macos",
        "on_linux": "linux",
        "on_arm": "arm",
        "on_intel": "intel",
        "head": "head build",
    }

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        text = content.text
        declared_class = re.search(r"^class\s+(\w+)\s*<\s*Formula\b", text, re.MULTILINE)
        if declared_class is None:
            return BaseEcosystem._err(
                content, ecosystem, "a formula without its `class ... < Formula`"
            )
        if not Ruby.balanced(text):
            return BaseEcosystem._err(content, ecosystem, "a formula whose blocks do not close")
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        hooks: list[Hook] = []
        stack: list[str] = []
        pending: dict[str, str] = {}
        version: str | None = None
        for _number, line in Ruby.lines(text):
            stripped = line.strip()
            opener = re.match(
                r"^(on_\w+|head|stable|resource|patch|bottle|livecheck|test|def|service)\b(?:\s+(?:\"([^\"]*)\"|:?\w+))?",
                stripped,
            )
            if opener and (Ruby.BLOCK_OPEN.search(stripped) or stripped.startswith("def ")):
                kind = opener.group(1)
                stack.append(
                    f"{kind}:{opener.group(2) or ''}" if kind in ("resource", "patch") else kind
                )
                if kind == "def" and re.match(r"^def\s+(install|post_install)\b", stripped):
                    hooks.append(
                        Hook(
                            kind="build",
                            path=content.path,
                            name=f"formula {stripped.split()[1]}",
                            command=f"def {stripped.split()[1]}",
                            ecosystem=ecosystem,
                        )
                    )
                pending = {}
                continue
            if re.match(r"^end\b", stripped):
                if stack:
                    closed = stack.pop()
                    if closed.startswith(("resource:", "patch:")) and pending.get("url"):
                        kind, _, name = closed.partition(":")
                        # A resource by its name; a patch, which has none, by the file it fetches.
                        label = name or pending["url"].rstrip("/").rsplit("/", 1)[-1]
                        declared.append(
                            DeclaredDependency(
                                name=label,
                                spec=pending["url"],
                                scope=Scope.BUILD,
                                field_name=kind,
                                integrity=f"sha256:{pending['sha256']}"
                                if pending.get("sha256")
                                else None,
                                platform=Formula.conditions(stack),
                            )
                        )
                    pending = {}
                continue
            if any(s in ("test", "livecheck", "def", "service") for s in stack):
                continue
            head = re.match(rf"^head\s+{STRING}", stripped) if not stack else None
            if head:
                # The one-line form of `head do ... end`.
                branch = re.search(r'branch:\s*"([^"]+)"', stripped)
                sources.append(
                    f"head {head.group(1)}" + (f" ({branch.group(1)})" if branch else "")
                )
                continue
            field = Formula.FIELD.match(stripped)
            if field and stack and stack[-1].startswith(("resource:", "patch:")):
                pending[field.group(1)] = field.group(2)
                continue
            if field and "bottle" not in stack:
                if "head" in stack and field.group(1) == "url":
                    branch = re.search(r'branch:\s*"([^"]+)"', stripped)
                    sources.append(
                        f"head {field.group(2)}" + (f" ({branch.group(1)})" if branch else "")
                    )
                elif field.group(1) == "url":
                    sources.append(f"source {field.group(2)}")
                elif field.group(1) == "sha256":
                    sources.append(f"source sha256 {field.group(2)}")
                elif field.group(1) == "version":
                    version = field.group(2)
                continue
            depends = Formula.DEPENDS.match(stripped) or Formula.USES.match(stripped)
            if depends:
                tags = depends.group("tags") or ""
                scope = next((s for t, s in Formula.SCOPES.items() if t in tags), Scope.RUNTIME)
                conditions = Formula.conditions(stack)
                if stripped.lstrip().startswith("uses_from_macos"):
                    # On macOS the system provides it; elsewhere Homebrew installs it.
                    conditions = (*conditions, "linux (macOS provides it)")
                trailing = re.search(r"\bif\s+(.+)$", stripped)
                if trailing:
                    conditions = (*conditions, trailing.group(1).strip())
                declared.append(
                    DeclaredDependency(
                        name=depends.group(1),
                        spec="*",
                        scope=scope,
                        field_name="uses_from_macos"
                        if stripped.lstrip().startswith("uses_from_macos")
                        else "depends_on",
                        platform=conditions,
                        note="Homebrew installs the formula's current version: a formula pins nothing it depends on",
                    )
                )
        bottles = len(
            re.findall(
                r'^\s*sha256\s+(?:cellar:\s*\S+\s*,?\s*)?\w+:\s*"[0-9a-f]{64}"', text, re.MULTILINE
            )
        )
        if bottles:
            sources.append(f"bottles for {bottles} platform(s), each with its sha256")
        name = content.basename.removesuffix(".rb")
        if not version:
            found = re.search(
                r'^\s*url\s+"[^"]*?[-_/](?:v)?(\d+(?:\.\d+)+)[^"/]*"', text, re.MULTILINE
            )
            version = found.group(1) if found else None
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=name,
            version=version,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            sources=tuple(sources),
        )

    @staticmethod
    def conditions(stack: list[str]) -> tuple[str, ...]:
        return tuple(Formula.CONDITIONS[s] for s in stack if s in Formula.CONDITIONS)


class Cask:
    """Casks/<token>.rb."""

    SCRIPTS: ClassVar[tuple[str, ...]] = (
        "preflight",
        "postflight",
        "uninstall_preflight",
        "uninstall_postflight",
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        text = content.text
        token = re.search(rf"^cask\s+{STRING}\s+do\b", text, re.MULTILINE)
        if token is None:
            return BaseEcosystem._err(content, ecosystem, 'a cask without its `cask "..." do`')
        if not Ruby.balanced(text):
            return BaseEcosystem._err(content, ecosystem, "a cask whose blocks do not close")
        version = re.search(rf"^\s*version\s+(?:{STRING}|:latest)", text, re.MULTILINE)
        url = re.search(rf"^\s*url\s+{STRING}", text, re.MULTILINE)
        sources: list[str] = []
        if url:
            shown = (
                url.group(1).replace("#{version}", version.group(1))
                if version and version.group(1)
                else url.group(1)
            )
            sources.append(f"download {shown}")
        checksums = re.findall(r'^\s*sha256\s+(?:"([0-9a-f]{64})"|(:no_check))', text, re.MULTILINE)
        if any(no_check for _digest, no_check in checksums):
            sources.append(
                "download with no checksum (sha256 :no_check): whatever the URL serves is installed"
            )
        elif checksums:
            sources.append(f"download sha256 for {len(checksums)} variant(s)")
        declared: list[DeclaredDependency] = []
        for kind, names in re.findall(
            r"^\s*depends_on\s+(formula|cask):\s*(.+)$", text, re.MULTILINE
        ):
            for name in re.findall(STRING, names):
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec="*",
                        field_name=f"depends_on {kind}",
                        note=f"Homebrew installs the {kind}'s current version: a cask pins nothing it depends on",
                    )
                )
        # `depends_on macos: ">= :sonoma"`, or `depends_on :macos` for any release of it.
        macos = re.search(
            r'^\s*depends_on\s+(?:macos:\s*"?([^"\n]+)"?|:macos\b)', text, re.MULTILINE
        )
        if macos:
            declared.append(
                DeclaredDependency(
                    name="macos",
                    spec=(macos.group(1) or "*").strip(),
                    scope=Scope.PLATFORM,
                    field_name="depends_on macos",
                )
            )
        hooks = [
            Hook(
                kind="postinstall" if "post" in script else "preinstall",
                path=content.path,
                name=f"cask {script}",
                command=script,
                ecosystem=ecosystem,
            )
            for script in Cask.SCRIPTS
            if re.search(rf"^\s*{script}\s+do\b", text, re.MULTILINE)
        ]
        installer = re.search(r"^\s*installer\s+script:", text, re.MULTILINE)
        if installer:
            hooks.append(
                Hook(
                    kind="postinstall",
                    path=content.path,
                    name="cask installer script",
                    command="installer script",
                    ecosystem=ecosystem,
                )
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=token.group(1),
            version=version.group(1)
            if version and version.group(1)
            else ("latest" if version else None),
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            sources=tuple(sources),
        )


class Brewfile:
    ENTRY: ClassVar[re.Pattern[str]] = re.compile(
        rf"^\s*(tap|brew|cask|mas|vscode|whalebrew)\s+{STRING}(?P<rest>.*)$"
    )
    CORE_TAPS: ClassVar[frozenset[str]] = frozenset(
        {
            "homebrew/core",
            "homebrew/cask",
            "homebrew/bundle",
            "homebrew/services",
            "homebrew/cask-fonts",
            "homebrew/cask-versions",
        }
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        declared: list[DeclaredDependency] = []
        sources: list[str] = []
        unread = 0
        # `if OS.mac?` ... `else` ... `end` around entries: each entry keeps the conditions it is
        # under, as a trailing `if` / `unless` on its own line does.
        blocks: list[str] = []
        for _number, line in Ruby.lines(content.text):
            entry = Brewfile.ENTRY.match(line)
            if entry is None:
                block = re.match(r"^\s*(if|unless|elsif)\s+(.+)$", line)
                if block:
                    if block.group(1) == "elsif" and blocks:
                        blocks[-1] = f"when {block.group(2).strip()}"
                    else:
                        blocks.append(
                            f"{'when' if block.group(1) == 'if' else 'unless'} {block.group(2).strip()}"
                        )
                elif re.match(r"^\s*else\b", line) and blocks:
                    blocks[-1] = f"not {blocks[-1]}"
                elif re.match(r"^\s*end\b", line) and blocks:
                    blocks.pop()
                elif not re.match(r"^\s*(?:cask_args|require|else|end)\b", line):
                    unread += 1
                continue
            kind, value, rest = entry.group(1), entry.group(2), entry.group("rest")
            trailing = re.search(r"\b(if|unless)\s+(.+)$", rest)
            conditions = (
                *blocks,
                *(
                    [
                        f"{'when' if trailing.group(1) == 'if' else 'unless'} {trailing.group(2).strip()}"
                    ]
                    if trailing
                    else []
                ),
            )
            if kind == "tap":
                custom = re.match(rf"\s*,\s*{STRING}", rest)
                tap = Brewfile.tap_name(value)
                owner, _, repo = tap.partition("/")
                url = custom.group(1) if custom else f"https://github.com/{owner}/homebrew-{repo}"
                if tap.lower() not in Brewfile.CORE_TAPS:
                    declared.append(
                        DeclaredDependency(
                            name=tap,
                            spec=url,
                            scope=Scope.DEV,
                            field_name="tap",
                            platform=conditions,
                            note="a tap: the repository of formulae brew follows at its default branch",
                        )
                    )
            elif kind == "vscode":
                # An editor extension: judged by the extension rules (detect/agents.py), not here.
                sources.append(f"vscode extension {value}")
            elif kind == "whalebrew":
                from cordon_scanner.ecosystems.image import ImageReference

                image = ImageReference.declare(
                    value, scope=Scope.DEV, field_name="whalebrew", platform=conditions
                )
                if image is not None:
                    declared.append(image)
            elif kind == "mas":
                # An App Store app, which `mas` installs: Apple's store, not a Homebrew registry.
                mas_id = re.search(r"id:\s*(\d+)", rest)
                sources.append(
                    f"mas app {value}" + (f" (App Store id {mas_id.group(1)})" if mas_id else "")
                )
            else:
                args = re.search(r"args:\s*\[([^\]]*)\]", rest)
                from_tap, name = Brewfile.qualified(value)
                declared.append(
                    DeclaredDependency(
                        # Formula names are lower case, matched by brew in any case; the spelling
                        # and the tap written stay as the alias.
                        name=name.lower(),
                        spec="*",
                        scope=Scope.DEV,
                        field_name=kind,
                        extras=tuple(re.findall(r'"([^"]+)"', args.group(1))) if args else (),
                        platform=conditions,
                        source=f"registry:{from_tap}" if from_tap else None,
                        alias=value if value != name.lower() else None,
                        note="brew bundle installs the current version: a Brewfile pins nothing",
                    )
                )
        if unread and not declared and not sources:
            return BaseEcosystem._err(
                content, ecosystem, "a Brewfile with no line brew bundle reads"
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )

    @staticmethod
    def tap_name(value: str) -> str:
        """A tap as brew names it: `user/homebrew-repo` and `user/repo` are the same tap, the
        repository github.com/user/homebrew-repo, and brew calls it `user/repo`."""
        owner, slash, repo = value.partition("/")
        return f"{owner}/{repo.removeprefix('homebrew-')}" if slash else value

    @staticmethod
    def qualified(value: str) -> tuple[str | None, str]:
        """`user/repo/name` -> (`user/repo`, `name`): a formula from a named tap. Homebrew's own
        taps are the registry, so theirs is no source."""
        if value.count("/") != 2:
            return None, value
        tap, _, name = value.rpartition("/")
        tap = Brewfile.tap_name(tap)
        return (None if tap.lower() in Brewfile.CORE_TAPS else tap), name


class BrewfileLock:
    """Brewfile.lock.json, as `brew bundle` wrote it before Homebrew 4.4."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        groups = data.get("entries")
        if not isinstance(groups, dict):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a Brewfile.lock.json without its entries",
            )
        entries: list[LockEntry] = []
        # The commit each tap was at: what its formulae were read from.
        taps = groups.get("tap")
        for name, entry in sorted(taps.items()) if isinstance(taps, dict) else []:
            revision = entry.get("revision") if isinstance(entry, dict) else None
            if (
                isinstance(revision, str)
                and re.fullmatch(r"[0-9a-f]{40}", revision)
                and name.lower() not in Brewfile.CORE_TAPS
            ):
                entries.append(LockEntry(name=name, version=revision, scope=Scope.DEV, direct=True))
        # App Store apps, editor extensions and whalebrew images are not Homebrew packages.
        for kind in ("brew", "cask"):
            group = groups.get(kind)
            for name, entry in sorted(group.items()) if isinstance(group, dict) else []:
                if not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                bottle = entry.get("bottle") if isinstance(entry.get("bottle"), dict) else {}
                files = (
                    (bottle or {}).get("files")
                    if isinstance((bottle or {}).get("files"), dict)
                    else {}
                )
                digest = next(
                    (
                        f.get("sha256")
                        for f in (files or {}).values()
                        if isinstance(f, dict) and isinstance(f.get("sha256"), str)
                    ),
                    None,
                )
                tap, short = Brewfile.qualified(name)
                entries.append(
                    LockEntry(
                        name=short,
                        resolved_from=f"registry:{tap}" if tap else None,
                        version=str(version) if version is not None else "",
                        integrity=f"sha256:{digest}" if digest else None,
                        scope=Scope.DEV,
                        direct=True,
                    )
                )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class InstallReceipt:
    """Cellar/<name>/<version>/INSTALL_RECEIPT.json: one installed keg, owned by the Homebrew
    prefix the Cellar is in."""

    OWNER_LEVELS: ClassVar[int] = 3

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        levels = InstallReceipt.OWNER_LEVELS
        parts = content.path.split("/")
        if len(parts) < 4 or parts[-4] != "Cellar":
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an install receipt outside a Cellar/<name>/<version>/ keg",
                owner_levels=levels,
            )
        name, keg = parts[-3], parts[-2]
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid JSON: {exc}",
                owner_levels=levels,
            )
        source = data.get("source")
        if not isinstance(source, dict) or "installed_on_request" not in data:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="an install receipt without its source and how it was installed",
                owner_levels=levels,
            )
        edges = tuple(
            f"{dependency['full_name'].rsplit('/', 1)[-1]}@{dependency.get('pkg_version') or dependency.get('version')}"
            for dependency in data.get("runtime_dependencies") or []
            if isinstance(dependency, dict)
            and isinstance(dependency.get("full_name"), str)
            and dependency.get("declared_directly", True)
        )
        tap = source.get("tap")
        third_party = isinstance(tap, str) and not tap.lower().startswith("homebrew/")
        entry = LockEntry(
            name=name,
            # The keg's directory is the installed version, with its revision (`1.25.0_2`).
            version=keg,
            resolved_from=f"registry:{tap}" if third_party else None,
            scope=Scope.RUNTIME,
            dependencies=edges,
            direct=data.get("installed_on_request") is True,
        )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=(entry,),
            owner_levels=levels,
            fragment=True,
        )


class HomebrewEcosystem(BaseEcosystem):
    """Homebrew bundles, formulae and casks."""

    id = "homebrew"
    purl_type = "brew"
    manifest_globs: tuple[str, ...] = (
        "**/Brewfile",
        # The names Brewfiles go by in real dotfiles: `brew bundle --global` reads ~/.Brewfile, and
        # dotfile managers keep one as Brewfile.symlink or Brewfile.txt, or one per machine as
        # work.Brewfile. (Brewfile.lock.json is the lock, below.)
        "**/.Brewfile",
        "**/Brewfile.txt",
        "**/Brewfile.local",
        "**/Brewfile.symlink",
        "**/*.Brewfile",
        "**/Formula/*.rb",
        "**/Casks/*.rb",
        "**/Formula/*/*.rb",
        "**/Casks/*/*.rb",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/Brewfile.lock.json",
        "**/Cellar/*/*/INSTALL_RECEIPT.json",
    )
    registry_hosts: frozenset[str] = frozenset({"github.com/homebrew", "formulae.brew.sh"})
    records_integrity = False

    # A tap is the index `brew` reads formulae from, following its default branch by design, as a
    # Helm repository or a Conan remote is: a third-party tap is reported as a source, not as a
    # mutable reference.
    index_fields: tuple[str, ...] = ("tap",)
    # A formula or cask in the tree does not take the place of the one a Brewfile names: an
    # unqualified name resolves from Homebrew's own taps first.
    defines_members = False

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        path = f"/{content.path}"
        if "/Casks/" in path:
            return Cask.parse(content, self.id)
        if "/Formula/" in path:
            return Formula.parse(content, self.id)
        return Brewfile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename == "INSTALL_RECEIPT.json":
            return InstallReceipt.parse(content, self.id)
        return BrewfileLock.parse(content, self.id)


__all__ = [
    "Brewfile",
    "BrewfileLock",
    "Cask",
    "Formula",
    "HomebrewEcosystem",
    "InstallReceipt",
    "Ruby",
]
