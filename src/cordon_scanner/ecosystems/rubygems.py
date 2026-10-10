"""RubyGems / Bundler.

```
  Gemfile, gems.rb          gem, group, platforms, source (global and block), git/github/path,
                            gemspec, ruby
  *.gemspec                 add_dependency, add_development_dependency, required_ruby_version,
                            extensions (native code built at install)
  Gemfile.lock, gems.locked GIT / PATH / GEM sections, platform variants, DEPENDENCIES,
                            CHECKSUMS, RUBY VERSION, BUNDLED WITH
  .ruby-version             the Ruby the project runs on
```

A Gemfile and a gemspec are Ruby programs. They are read as the declarations they almost always
are -- statements and `do ... end` blocks -- and never evaluated; what only evaluation could
answer (a version computed in Ruby) is unresolved, with that reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


class RubySource:
    """Ruby source as statements: comments removed, strings respected."""

    STRING: ClassVar[re.Pattern[str]] = re.compile(r"""(["'])((?:(?!\1)[^\\\n]|\\.){0,512})\1""")
    SYMBOL_LIST: ClassVar[re.Pattern[str]] = re.compile(r"%[iw]\[([^\]]{0,512})\]")

    @staticmethod
    def lines(text: str) -> list[tuple[int, str]]:
        """`(line number, code)` with `#` comments removed outside strings and `=begin`/`=end`
        blocks skipped."""
        out: list[tuple[int, str]] = []
        in_doc = False
        for number, raw in enumerate(text.splitlines(), start=1):
            if in_doc:
                if raw.startswith("=end"):
                    in_doc = False
                continue
            if raw.startswith("=begin"):
                in_doc = True
                continue
            code: list[str] = []
            quote = ""
            index = 0
            while index < len(raw):
                character = raw[index]
                if quote:
                    code.append(character)
                    if character == "\\" and index + 1 < len(raw):
                        code.append(raw[index + 1])
                        index += 2
                        continue
                    if character == quote:
                        quote = ""
                elif character in "\"'":
                    quote = character
                    code.append(character)
                elif character == "#":
                    break
                else:
                    code.append(character)
                index += 1
            if quote:
                # A string still open at the end of its line: a declaration file cut short or
                # damaged (Gemfiles do not continue a quoted string onto the next line).
                raise ValueError(f"line {number}: a string is never closed")
            stripped = "".join(code).strip()
            if stripped:
                out.append((number, stripped))
        return out

    #: The keywords that open a block `end` closes, when they begin a statement. Placed after an
    #: expression (`return x if y`) `if`, `unless`, `while` and `until` are modifiers and open
    #: nothing; a line starts with one only as the statement form.
    KEYWORD_BLOCK: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:def|class|module|if|unless|while|until|case|begin|for)\b"
    )
    #: Ruby 3's endless method, `def name = expr` or `def name(args) = expr`, has no `end`. A
    #: setter (`def name=(value)`) and `def ==(other)` are not it.
    ENDLESS_DEF: ClassVar[re.Pattern[str]] = re.compile(
        r"^def\s+[\w.?!]+(?:\([^)]*\)\s*|\s+)=(?![=~>])"
    )

    @staticmethod
    def opens_keyword_block(line: str) -> bool:
        """Whether a statement opens a block with a keyword (`def`, `if`, `unless`, ...) that a
        later `end` closes: not where the same line closes it (`if x then y end`, `def x; end`),
        nor for an endless method. The standard Flutter Podfile opens `def flutter_root` and
        `unless File.exist?(...)`, which the Podfile reader had counted as no block at all."""
        if not RubySource.KEYWORD_BLOCK.match(line) or RubySource.ENDLESS_DEF.match(line):
            return False
        return not re.search(r"(?:^|[\s;])end\s*$", line)

    @staticmethod
    def strings(text: str) -> list[str]:
        return [m.group(2) for m in RubySource.STRING.finditer(text)]

    @staticmethod
    def option(text: str, key: str) -> str | None:
        """`key: "value"` or `:key => "value"` -> value (a string or a symbol)."""
        found = re.search(
            rf"""(?:\b{key}:|:{key}\s*=>)\s*(?:(["'])([^"'\n]{{0,512}})\1|:(\w+))""", text
        )
        if not found:
            return None
        return found.group(2) if found.group(2) is not None else found.group(3)

    @staticmethod
    def symbols(text: str, key: str) -> list[str]:
        """`key: :a`, `key: [:a, :b]`, `key: %i[a b]` -> names."""
        found = re.search(
            rf"""(?:\b{key}:|:{key}\s*=>)\s*(\[[^\]]{{0,512}}\]|%[iw]\[[^\]]{{0,512}}\]|:\w+|["'][^"']{{0,128}}["'])""",
            text,
        )
        if not found:
            return []
        value = found.group(1)
        listed = RubySource.SYMBOL_LIST.match(value)
        if listed:
            return listed.group(1).split()
        return re.findall(r":(\w+)|[\"']([^\"']+)[\"']", value) and [
            a or b for a, b in re.findall(r":(\w+)|[\"']([^\"']+)[\"']", value)
        ]


@dataclass
class GemfileBlock:
    kind: str
    groups: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    source: str | None = None
    git: str | None = None
    path: str | None = None
    condition: str | None = None


@dataclass
class Gemfile:
    """What a Gemfile declares."""

    path: str
    dependencies: list[DeclaredDependency] = field(default_factory=list)
    global_sources: list[str] = field(default_factory=list)
    block_sources: list[str] = field(default_factory=list)
    gemspecs: list[tuple[str, str]] = field(default_factory=list)
    """`(directory, development group)` for each `gemspec` directive."""
    ruby: str | None = None
    errors: list[str] = field(default_factory=list)

    OPENS: ClassVar[re.Pattern[str]] = re.compile(r"\bdo(?:\s*\|[^|]*\|)?\s*$")
    BARE: ClassVar[frozenset[str]] = frozenset(
        {
            "gemspec",
            "else",
            "elsif",
            "rescue",
            "ensure",
            "then",
            "begin",
            "end",
            "retry",
            "next",
            "break",
            "return",
            "nil",
            "true",
            "false",
        }
    )
    CONDITIONAL: ClassVar[re.Pattern[str]] = re.compile(r"^(if|unless|case|while|until|begin)\b")

    @staticmethod
    def scope(groups: tuple[str, ...]) -> tuple[Scope, tuple[str, ...]]:
        if not groups or "default" in groups:
            return Scope.RUNTIME, ()
        known = {"development": Scope.DEV, "test": Scope.TEST}
        scopes = [known[g] for g in groups if g in known]
        if len(scopes) == len(groups):
            from cordon_scanner.ecosystems.npm import LockScopes

            return min(scopes, key=LockScopes.rank), ()
        # A custom group (`:production`, `:assets`) installs by default unless excluded.
        return Scope.RUNTIME, tuple(f"group {g}" for g in groups if g not in known)

    @staticmethod
    def read(content: FileContent) -> Gemfile:
        found = Gemfile(content.path)
        stack: list[GemfileBlock] = []
        try:
            lines = RubySource.lines(content.text)
        except ValueError as exc:
            found.errors.append(str(exc))
            return found
        for number, line in lines:
            if line == "end" or line.startswith("end ") or line.startswith("end."):
                if not stack:
                    found.errors.append(f"line {number}: `end` with no block open")
                    continue
                stack.pop()
                continue
            opens = bool(Gemfile.OPENS.search(line))
            head = re.match(r"^(\w+)", line)
            word = head.group(1) if head else ""
            if RubySource.opens_keyword_block(line) and not opens:
                stack.append(
                    GemfileBlock("condition", condition=line[:80])
                    if Gemfile.CONDITIONAL.match(line)
                    else GemfileBlock("other")
                )
                continue
            if word == "group" and opens:
                stack.append(
                    GemfileBlock("group", groups=tuple(re.findall(r":(\w+)", line.split(" do")[0])))
                )
                continue
            if word in ("platforms", "platform") and opens:
                stack.append(
                    GemfileBlock(
                        "platforms", platforms=tuple(re.findall(r":(\w+)", line.split(" do")[0]))
                    )
                )
                continue
            if word == "source" and opens:
                url = (RubySource.strings(line) or [""])[0]
                found.block_sources.append(url)
                stack.append(GemfileBlock("source", source=url))
                continue
            if word in ("git", "github") and opens:
                url = (RubySource.strings(line) or [""])[0]
                stack.append(
                    GemfileBlock("git", git=Gemfile._github(url) if word == "github" else url)
                )
                continue
            if word == "path" and opens:
                stack.append(GemfileBlock("path", path=(RubySource.strings(line) or [""])[0]))
                continue
            if opens:
                condition = (
                    Gemfile.OPENS.sub("", line).strip()[:80]
                    if word in ("install_if", "env")
                    else None
                )
                stack.append(GemfileBlock("other", condition=condition))
                continue
            if word == "source":
                url = (RubySource.strings(line) or [""])[0]
                if url:
                    found.global_sources.append(url)
                continue
            if word == "ruby":
                version = RubySource.strings(line)
                found.ruby = ", ".join(version) if version and "file:" not in line else None
                continue
            if word == "gemspec":
                directory = RubySource.option(line, "path") or "."
                group = RubySource.option(line, "development_group") or "development"
                found.gemspecs.append((directory, group))
                continue
            if re.fullmatch(r"[a-z_]\w*", line) and line not in Gemfile.BARE:
                # A lone identifier that is no Gemfile keyword: an undefined name Bundler fails
                # on, most often what remains of a line cut short.
                found.errors.append(f"line {number}: an unknown statement")
                continue
            if word == "gem":
                declared = Gemfile._gem(line, stack)
                if declared is not None:
                    found.dependencies.append(declared)
                else:
                    # `gem` with no name is an error Bundler raises on, and a file cut short
                    # most often ends in one.
                    found.errors.append(f"line {number}: `gem` names no gem")
        if stack:
            found.errors.append(f"{len(stack)} block(s) never closed with `end`")
        return found

    @staticmethod
    def _github(repository: str) -> str:
        if "://" in repository:
            return repository
        return f"https://github.com/{repository}.git"

    @staticmethod
    def _gem(line: str, stack: list[GemfileBlock]) -> DeclaredDependency | None:
        literals = RubySource.strings(line.split(",", 1)[0])
        if not literals:
            return None
        name = literals[0]
        rest = line.split(",", 1)[1] if "," in line else ""
        # Version requirements are the positional strings before the first `key:` option.
        positional = re.split(r"\b\w+:\s|:\w+\s*=>", rest, maxsplit=1)[0]
        requirements = RubySource.strings(positional)
        groups = tuple(RubySource.symbols(line, "groups") or RubySource.symbols(line, "group"))
        platforms = tuple(
            RubySource.symbols(line, "platforms") or RubySource.symbols(line, "platform")
        )
        for block in stack:
            groups = groups or block.groups
            platforms = (*platforms, *block.platforms)
        scope, extra = Gemfile.scope(groups)
        conditions = list(extra)
        if platforms:
            conditions.append("platform " + ", ".join(dict.fromkeys(platforms)))
        for block in stack:
            if block.condition:
                conditions.append(f"condition {block.condition}")
        git = RubySource.option(line, "git")
        github = RubySource.option(line, "github")
        path = RubySource.option(line, "path")
        source = RubySource.option(line, "source")
        for block in stack:
            git = git or block.git
            path = path or block.path
            source = source or block.source
        spec = ", ".join(requirements) or "*"
        if github and not git:
            git = Gemfile._github(github)
        if git:
            reference = (
                RubySource.option(line, "ref")
                or RubySource.option(line, "tag")
                or RubySource.option(line, "branch")
            )
            spec = f"git+{git}" + (f"#{reference}" if reference else "")
        elif path:
            spec = f"path:{path}"
        return DeclaredDependency(
            name=name,
            spec=spec,
            scope=scope,
            field_name="gem" + (f" (source {source})" if source else ""),
            platform=tuple(conditions),
            source=f"registry:{source}" if source and not git and not path else None,
            # Bundler locks a platform-restricted gem only when the lock includes one of its
            # platforms: absent from the lock is then expected, not drift.
            note=f"only for platforms {', '.join(dict.fromkeys(platforms))}, which a lockfile resolves only when it includes them"
            if platforms
            else None,
        )


class Gemspec:
    """A gemspec's dependencies and native extensions, read statically."""

    DEPENDENCY: ClassVar[re.Pattern[str]] = re.compile(
        r"""\.add_(runtime_|development_)?dependency\s*\(?\s*(["'])([\w.\-]{1,128})\2(.*)$"""
    )

    @staticmethod
    def read(
        content: FileContent, development_group: str = "development"
    ) -> tuple[list[DeclaredDependency], list[str], str | None]:
        declared: list[DeclaredDependency] = []
        extensions: list[str] = []
        ruby = None
        for _, line in RubySource.lines(content.text):
            found = Gemspec.DEPENDENCY.search(line)
            if found:
                development = found.group(1) == "development_"
                requirements = RubySource.strings(found.group(4))
                scope = Scope.DEV if development else Scope.RUNTIME
                if development and development_group == "test":
                    scope = Scope.TEST
                declared.append(
                    DeclaredDependency(
                        name=found.group(3),
                        spec=", ".join(requirements) or "*",
                        scope=scope,
                        field_name="add_development_dependency"
                        if development
                        else "add_dependency",
                    )
                )
                continue
            if re.search(r"\.extensions\s*(?:=|<<)", line):
                extensions.extend(
                    s
                    for s in RubySource.strings(line)
                    if s.endswith((".rb", "Rakefile", "CMakeLists.txt", "Cargo.toml"))
                )
            if re.search(r"\.required_ruby_version\s*=", line):
                ruby = ", ".join(RubySource.strings(line)) or None
        return declared, extensions, ruby


class BundlerLock:
    """`Gemfile.lock` / `gems.locked`.

    ```
      GIT / PATH / GEM / PLUGIN SOURCE   remote, revision, specs: `    name (version[-platform])`
      PLATFORMS                          the platforms the lock resolved for
      DEPENDENCIES                       what the Gemfile asked for (`!`: from a pinned source)
      CHECKSUMS                          `  name (version[-platform]) sha256=<hex>` (Bundler 2.6+)
      RUBY VERSION / BUNDLED WITH        the Ruby and the Bundler that wrote it
    ```
    """

    SECTIONS: ClassVar[frozenset[str]] = frozenset(
        {
            "GIT",
            "PATH",
            "GEM",
            "PLUGIN SOURCE",
            "PLATFORMS",
            "DEPENDENCIES",
            "CHECKSUMS",
            "RUBY VERSION",
            "BUNDLED WITH",
        }
    )
    SPEC: ClassVar[re.Pattern[str]] = re.compile(r"^    ([\w.\-]{1,128}) \(([^)\s]{1,128})\)$")
    EDGE: ClassVar[re.Pattern[str]] = re.compile(r"^      ([\w.\-]{1,128})(?: \(([^)]{0,256})\))?$")
    # The value is validated as a digest afterwards (`Coordinate.integrity`): one that is not a
    # SHA-256 is recorded as malformed and reported, never silently dropped.
    CHECKSUM: ClassVar[re.Pattern[str]] = re.compile(
        r"^  ([\w.\-]{1,128}) \(([^)\s]{1,128})\)(?: (sha256=\S{1,256}))?$"
    )
    VERSION_PLATFORM: ClassVar[re.Pattern[str]] = re.compile(r"^(\d[\w.]*?)(?:-([a-z][\w\-]*))?$")

    @staticmethod
    def split(version: str) -> tuple[str, str | None]:
        """`1.19.4-x86_64-linux-gnu` -> `("1.19.4", "x86_64-linux-gnu")`."""
        found = BundlerLock.VERSION_PLATFORM.match(version)
        if not found:
            return version, None
        return found.group(1), found.group(2)

    @staticmethod
    def parse(
        content: FileContent, ecosystem: str, own_names: frozenset[str] = frozenset()
    ) -> LockGraph:
        section = ""
        remote = revision = reference = ""
        specs: dict[tuple[str, str], dict[str, object]] = {}
        current: tuple[str, str] | None = None
        direct: set[str] = set()
        checksums: dict[tuple[str, str], dict[str, str]] = {}
        ruby = bundler = None
        unreadable = 0
        for raw in content.text.splitlines():
            if not raw.strip():
                continue
            if not raw.startswith(" "):
                section = raw.strip()
                if section not in BundlerLock.SECTIONS:
                    unreadable += 1
                    section = ""
                remote = revision = reference = ""
                current = None
                continue
            if section in ("GIT", "PATH", "GEM", "PLUGIN SOURCE"):
                setting = re.match(
                    r"^  (remote|revision|tag|branch|ref|glob|submodules): (.{0,512})$", raw
                )
                if setting:
                    key, value = setting.groups()
                    if key == "remote":
                        # Older locks list several remotes in one GEM section (multi-remote
                        # resolution): which one served a gem is then unknown. With rubygems.org
                        # among them the section stays the public registry -- the ambiguity is the
                        # Gemfile's several global sources, reported there -- otherwise the first.
                        if remote and section == "GEM":
                            remote = (
                                remote
                                if "rubygems.org" in remote
                                else value
                                if "rubygems.org" in value
                                else remote
                            )
                        else:
                            remote = value
                    elif key == "revision":
                        revision = value
                    elif key in ("tag", "branch", "ref"):
                        reference = value
                    continue
                if raw == "  specs:":
                    continue
                spec = BundlerLock.SPEC.match(raw)
                if spec:
                    version, platform = BundlerLock.split(spec.group(2))
                    current = (spec.group(1), version)
                    slot = specs.setdefault(
                        current,
                        {
                            "platforms": [],
                            "plain": False,
                            "edges": set(),
                            "section": section,
                            "remote": remote,
                            "revision": revision,
                            "reference": reference,
                        },
                    )
                    if platform:
                        slot["platforms"].append(platform)  # type: ignore[attr-defined]
                    else:
                        slot["plain"] = True
                    continue
                edge = BundlerLock.EDGE.match(raw)
                if edge and current is not None:
                    specs[current]["edges"].add(edge.group(1))  # type: ignore[attr-defined]
                    continue
                unreadable += 1
            elif section == "DEPENDENCIES":
                found = re.match(r"^  ([\w.\-]{1,128})(!)?(?: \(.*\))?(!)?$", raw)
                if found:
                    direct.add(found.group(1).lower())
                else:
                    unreadable += 1
            elif section == "CHECKSUMS":
                found = BundlerLock.CHECKSUM.match(raw)
                if found:
                    version, platform = BundlerLock.split(found.group(2))
                    if found.group(3):
                        checksums.setdefault((found.group(1), version), {})[platform or "ruby"] = (
                            found.group(3).replace("sha256=", "sha256:")
                        )
                else:
                    unreadable += 1
            elif section == "RUBY VERSION":
                found = re.match(r"^\s+ruby (\d[\w.]*?)(?:p\d+)?$", raw)
                ruby = found.group(1) if found else ruby
            elif section == "BUNDLED WITH":
                bundler = raw.strip() or bundler
        if unreadable and not specs:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} line(s) are not Bundler lockfile syntax",
            )
        # The Gemfile's `gemspec` puts the project itself under `PATH remote: .`; what its gemspec
        # requires is listed under it, not in DEPENDENCIES, and is the project's direct dependency.
        for (_, _), slot in specs.items():
            if slot["section"] == "PATH" and slot["remote"] == ".":
                direct.update(str(e).lower() for e in slot["edges"])  # type: ignore[attr-defined]
        entries: list[LockEntry] = []
        for (name, version), slot in sorted(specs.items()):
            if slot["section"] == "PATH" and slot["remote"] == "." and name.lower() in own_names:
                continue  # the project's own gemspec: the project, not a dependency of it
            local = slot["section"] == "PATH"
            resolved_from = None
            if slot["section"] == "GIT":
                resolved_from = f"git+{slot['remote']}#{slot['revision'] or slot['reference']}"
            elif (
                slot["section"] == "GEM"
                and slot["remote"]
                and "rubygems.org" not in str(slot["remote"])
            ):
                resolved_from = str(slot["remote"])
            platforms: list[str] = list(slot["platforms"])  # type: ignore[call-overload]
            conditions = (
                []
                if slot["plain"] or not platforms
                else [
                    "platform " + ", ".join(platforms[:8]) + (", ..." if len(platforms) > 8 else "")
                ]
            )
            sums = checksums.get((name, version), {})
            integrity = sums.get("ruby") or (sums[sorted(sums)[0]] if sums else None)
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=None if local else integrity,
                    resolved_from=resolved_from,
                    direct=name.lower() in direct,
                    local=local,
                    dependencies=tuple(sorted(slot["edges"])),  # type: ignore[call-overload]
                    platform=tuple(conditions),
                )
            )
        if bundler:
            entries.append(
                LockEntry(name="bundler", version=bundler, scope=Scope.TOOL, direct=True)
            )
        if ruby:
            entries.append(LockEntry(name="ruby", version=ruby, scope=Scope.PLATFORM, direct=True))
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            integrity_elsewhere=not checksums,
        )


class RubyGemsEcosystem(BaseEcosystem):
    id = "rubygems"
    purl_type = "gem"
    manifest_globs: tuple[str, ...] = (
        "**/Gemfile",
        "**/gems.rb",
        "**/*.gemspec",
        "**/.ruby-version",
    )
    lockfile_globs: tuple[str, ...] = ("**/Gemfile.lock", "**/gems.locked")
    registry_hosts: frozenset[str] = frozenset({"rubygems.org", "index.rubygems.org"})
    records_integrity = False
    """Bundler writes a CHECKSUMS section only from 2.6, and only when enabled: a lock without one
    is the ordinary case, not hashes gone missing. Checksums that are there are validated and,
    with --online, compared with RubyGems.org's."""
    integrity_companion = True

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    @staticmethod
    def _beside(path: str, name: str) -> str:
        directory = path.rpartition("/")[0]
        return f"{directory}/{name}" if directory else name

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        name = content.basename
        if name == ".ruby-version":
            version = content.text.strip().removeprefix("ruby-")
            if not re.fullmatch(r"\d[\w.\-]{0,32}", version):
                return BaseEcosystem._err(content, self.id, "not a Ruby version")
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                dependencies=(
                    DeclaredDependency(
                        name="ruby", spec=version, scope=Scope.PLATFORM, field_name=".ruby-version"
                    ),
                ),
            )
        if name.endswith(".gemspec"):
            try:
                declared, extensions, ruby = Gemspec.read(content)
            except ValueError as exc:
                return BaseEcosystem._err(content, self.id, f"not a readable gemspec: {exc}")
            if ruby:
                declared.append(
                    DeclaredDependency(
                        name="ruby",
                        spec=ruby,
                        scope=Scope.PLATFORM,
                        field_name="required_ruby_version",
                    )
                )
            hooks = [
                Hook(kind="build", path=content.path, name=content.basename, ecosystem=self.id)
            ]
            # A native extension is compiled -- its extconf.rb run -- on every install from source.
            hooks.extend(
                Hook(
                    kind="install",
                    path=content.path,
                    name=extension,
                    command=f"ruby {extension}",
                    ecosystem=self.id,
                )
                for extension in extensions
            )
            # A gemspec beside a Gemfile is read through the Gemfile's `gemspec` directive.
            if (
                self._beside(content.path, "Gemfile") in files
                or self._beside(content.path, "gems.rb") in files
            ):
                declared = []
            stem = name.removesuffix(".gemspec")
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                name=stem,
                dependencies=tuple(declared),
                hooks=tuple(hooks),
            )
        gemfile = Gemfile.read(content)
        if gemfile.errors and not gemfile.dependencies:
            return BaseEcosystem._err(
                content, self.id, f"not a readable Gemfile: {gemfile.errors[0]}"
            )
        declared = list(gemfile.dependencies)
        directory = content.path.rpartition("/")[0]
        for relative, group in gemfile.gemspecs:
            base = relative.strip("/") if relative not in (".", "") else ""
            prefix = "/".join(p for p in (directory, base) if p)
            for path, other in files.items():
                if path.endswith(".gemspec") and path.rpartition("/")[0] == prefix:
                    try:
                        specs, _, ruby = Gemspec.read(other, group)
                    except ValueError:
                        continue  # reported where the gemspec itself is parsed
                    # Bundler's `gemspec` makes that gem a dependency and adds its development
                    # dependencies to the development group. At `.` the gem is this project, and
                    # its runtime dependencies are the project's own.
                    if base:
                        declared.append(
                            DeclaredDependency(
                                name=other.basename.removesuffix(".gemspec"),
                                spec=f"path:{base}",
                                field_name="gemspec",
                            )
                        )
                    declared.extend(
                        DeclaredDependency(
                            name=d.name,
                            spec=d.spec,
                            scope=d.scope,
                            field_name=f"{d.field_name} ({other.basename})",
                        )
                        for d in specs
                        if not base or d.scope is not Scope.RUNTIME
                    )
                    if ruby and gemfile.ruby is None:
                        declared.append(
                            DeclaredDependency(
                                name="ruby",
                                spec=ruby,
                                scope=Scope.PLATFORM,
                                field_name="required_ruby_version",
                            )
                        )
        if gemfile.ruby:
            declared.append(
                DeclaredDependency(
                    name="ruby", spec=gemfile.ruby, scope=Scope.PLATFORM, field_name="ruby"
                )
            )
        sources = [f"source {url}" for url in gemfile.global_sources] + [
            f"source block {url}" for url in gemfile.block_sources
        ]
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return BundlerLock.parse(content, self.id)


__all__ = ["BundlerLock", "Gemfile", "Gemspec", "RubyGemsEcosystem", "RubySource"]
