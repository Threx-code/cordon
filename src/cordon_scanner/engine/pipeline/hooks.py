"""What a package runs when it is installed or imported, found before any detector reads it: the
lifecycle scripts a manifest declares and the files they reach, a gem's native extensions, a NuGet
package's install scripts, the languages those hooks are written in, the modules a hook imports
and the JavaScript it loads, the lines of a hook that run later, and the scripts a CI or action
file runs.

A file a hook runs is read as install-time code; a test fixture or a vendored example is not.
"""

from __future__ import annotations

import io
import posixpath
import re
from dataclasses import replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.analysis.shared.languages import LanguageRegistry
from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.constants import (
    CI_HOOK_FILENAMES,
    CI_HOOK_PREFIXES,
    DEPENDENCY_BUILD_FILENAMES,
    DEPENDENCY_BUILD_SUFFIXES,
    INLINE_REQUIRE,
    JS_CLOSURE_LIMIT,
    JS_DIRECTORY_VARIABLE,
    JS_JOINED_PATH,
    JS_LOCAL_REFERENCE,
    JS_RUNNERS,
    PACKAGED_BUILD_FILENAMES,
    PRINTING_COMMANDS,
    PROJECT_BUILD_FILENAMES,
)
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import AUTHOR_TIME_HOOKS, Finding, Hook, Severity
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.results import OperationalFinding, Repository

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from cordon_scanner.ecosystems.base import Manifest


class Hooks:
    """The code a package runs at install or import."""

    @staticmethod
    def hook_executes(hook: Hook, package_directories: set[str]) -> bool:
        """Whether a file identified as a hook by its NAME really is one.

        Two filename tests are not specific enough on their own, and both were
        wrong in the direction that matters: they invent an install-time execution
        context, which is the largest multiplier in the risk model and the
        condition every `MALWARE.*` composite hinges on.

        **A `setup.py` inside a package.** `NousResearch/hermes-agent` carries
        `hermes_cli/setup.py` (an interactive setup wizard),
        `hermes_cli/subcommands/setup.py` (the `hermes setup` argument parser) and
        `plugins/memory/hindsight/setup.py`. None is a packaging script, and a
        packaging script cannot be one of these: a file inside a package directory
        is imported as `package.setup`, and `python setup.py` from the
        distribution root would not find it.

        The cost of getting this wrong was not one finding. `_hook_import_closure`
        follows imports out of every hook, and from those three modules it reached
        582 files -- the whole agent. Every credential read beside an HTTPS call in
        any of them became `MALWARE.EXFIL.001` at CRITICAL, in the MALICIOUS
        category, with remediation telling the reader to treat their host as
        compromised and rotate every credential on it. Seventeen of those, plus
        fifteen `MALWARE.DYNAMIC_DISPATCH.001` on ordinary `getattr` calls, on a
        repository whose worst actual finding is a lockfile without hashes.

        **A git sample hook.** `.git/hooks/pre-commit.sample` is shipped by `git
        init` and never runs: git executes `.git/hooks/pre-commit`, and the suffix
        is how it tells the two apart. Fourteen of them were counted as hooks in
        every repository ever scanned.
        """
        name = ContainerPaths.basename(hook.path)
        directory = hook.path.rpartition("/")[0]
        if name in PACKAGED_BUILD_FILENAMES:
            if directory in package_directories:
                return False
            # And a build file the project's own tests build. See
            # `FIXTURE_DIRECTORIES`: this one costs more than the others,
            # because a hook seeds an import closure and a fixture that imports
            # the library puts the whole library in install-time context.
            return not Hooks.under_fixture_directory(hook.path)
        return not name.endswith(".sample")

    @staticmethod
    def outside_extensions(
        units: Sequence[FileUnit],
        hook_paths: set[str],
        entries: frozenset[str],
        consumer_hooks: set[str],
    ) -> tuple[set[str], frozenset[str], set[str]]:
        """The install-time picture of an editor extension: its activation entry, nothing else.

        The editor unpacks an extension and starts the `main` (or `browser`) its manifest names --
        on every start, unasked -- so that file runs as an install hook's does. No package manager
        runs in it, so no lifecycle script a bundled manifest names runs at all: kept, they made
        `node_modules/d3/dist/d3.min.js` inside a data-preview extension "runs during install" and
        its `new Function` beside a `fetch` a critical dropper. The entry alone, not what it
        imports: a bundled library is loaded, and what it does is read with its own context.
        """
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        def keep(path: str) -> bool:
            return not SourcePaths.is_editor_extension(path)

        activation = Hooks.extension_entries(units)
        return (
            {p for p in hook_paths if keep(p)} | activation,
            frozenset(p for p in entries if keep(p)) | activation,
            {p for p in consumer_hooks if keep(p)},
        )

    @staticmethod
    def extension_entries(units: Sequence[FileUnit]) -> set[str]:
        """The files an editor starts in each extension present: its manifest's `main` and
        `browser`, with `.js` added when the manifest leaves it off, as Node resolves them."""
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        paths = {unit.path for unit in units}
        found: set[str] = set()
        for unit in units:
            path = unit.path
            if not path.endswith("package.json") or not SourcePaths.is_editor_extension(path):
                continue
            root = path[: -len("package.json")]
            if not (root.endswith(".vsix!extension/") or re.search(r"/extensions/[^/]+/$", root)):
                continue
            try:
                manifest = ScannedJson.loads(unit.content.raw)
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue
            if not isinstance(manifest, dict) or not isinstance(manifest.get("engines"), dict):
                continue
            if "vscode" not in manifest["engines"]:
                continue
            for key in ("main", "browser"):
                value = manifest.get(key)
                if not isinstance(value, str) or not value.strip():
                    continue
                target = posixpath.normpath(root + value.strip().removeprefix("./"))
                for candidate in (target, f"{target}.js", f"{target}/index.js"):
                    if candidate in paths:
                        found.add(candidate)
                        break
        return found

    @staticmethod
    def under_fixture_directory(path: str) -> bool:
        """Whether any directory on this path is a test or example directory.

        Any segment, not just the first: pytorch's is `test/cpp_extensions/`,
        mongodb vendors one at `src/third_party/wiredtiger/test/3rdparty/`, and
        servo's is `tests/wpt/tests/tools/third_party/`. A rule that only looked
        at the top level would have caught one of the three.
        """
        return ContainerPaths.under_fixture_directory(path)

    @staticmethod
    def languages_from_hooks(inventory: Repository) -> dict[str, str]:
        """Languages implied by what a lifecycle script runs.

        `"postinstall": "node ./payload.png"` names both the interpreter and the
        file. An interpreter handed an explicit path does not consult the
        extension, so the file is JavaScript however it is spelled -- and
        `payload.png` otherwise gets `language=None` and only the
        language-agnostic rules, which is the rename half of the NUL-byte
        evasion.

        Only lifecycle commands are read, and only the token immediately after a
        recognised interpreter. That keeps this from becoming a general
        shell parser: the aim is to stop a rename hiding executed code, not to
        model every command line.
        """
        implied: dict[str, str] = {}
        for hook in inventory.hooks:
            if not hook.command:
                continue

            base = hook.path.rpartition("/")[0]
            tokens = [token for token in re.split(r"[\s;&|()]+", hook.command) if token]
            for index, token in enumerate(tokens):
                language = LanguageRegistry.language_from_interpreter(token)
                if language is None:
                    continue
                for candidate in tokens[index + 1 :]:
                    if candidate.startswith("-"):
                        continue
                    target = re.sub(r"^(?:\./)+", "", candidate)
                    if not target:
                        break
                    resolved = f"{base}/{target}" if base else target
                    implied.setdefault(resolved, language)
                    break
        return implied

    @staticmethod
    def nuget_hooks(units: Sequence[FileUnit]) -> set[str]:
        """What a NuGet package runs on the consumer's machine, when there is a `.nuspec` beside it.

        `tools/init.ps1` and `tools/install.ps1` run inside Visual Studio when the package is
        added; `build/` and `buildTransitive/` `.targets` and `.props` are imported into every
        build of every project that references the package, so their `<Exec>` tasks run there.
        Only beside a `.nuspec`: a repository's own `tools/install.ps1` is a script a person runs.
        """
        roots = {
            unit.path.rpartition("!")[2].rpartition("/")[0]
            for unit in units
            if unit.path.lower().endswith(".nuspec")
        }
        if not roots:
            return set()
        hooks: set[str] = set()
        for unit in units:
            member = unit.path.rpartition("!")[2]
            for root in roots:
                prefix = f"{root}/" if root else ""
                if not member.startswith(prefix):
                    continue
                inner = member[len(prefix) :].lower()
                if inner in ("tools/init.ps1", "tools/install.ps1", "tools/uninstall.ps1") or (
                    inner.startswith(("build/", "buildtransitive/"))
                    and inner.endswith((".targets", ".props"))
                ):
                    hooks.add(unit.path)
        return hooks

    _GEM_EXTENSIONS: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^extensions:[ \t]{0,8}$")

    _GEM_LISTED: ClassVar[re.Pattern[str]] = re.compile(r"[ \t]{0,8}-[ \t]{1,8}([^\n]{1,300})")

    @staticmethod
    def gem_extension_hooks(units: Sequence[FileUnit]) -> set[str]:
        """The native-extension scripts a published `.gem` runs when it is installed.

        `gem install` runs every `extconf.rb` (or extension Rakefile) its `metadata.gz` lists under
        `extensions:`, on the installing machine, before any code is required. A gemspec in a
        repository declares the same through `spec.extensions`; a built gem only through its
        metadata, so the scripts read as ordinary library code (review 98: active-record_lite and
        aliyun-live renamed a bundled image to `a.exe` and ran it from extconf.rb, unflagged).
        """
        import gzip
        import zlib

        hooks: set[str] = set()
        by_path = {unit.path: unit for unit in units}
        for unit in units:
            gem, _, member = unit.path.rpartition("!")
            if member != "metadata.gz" or not gem.lower().endswith(".gem"):
                continue
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(200_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                continue
            header = Hooks._GEM_EXTENSIONS.search(text)
            if header is None:
                continue
            for line in text[header.end() + 1 :].splitlines()[:64]:
                item = Hooks._GEM_LISTED.fullmatch(line)
                if item is None:
                    break
                extension = item.group(1).strip().strip("'\"")
                candidate = f"{gem}!data.tar.gz!{extension}"
                if extension and not extension.startswith(("/", "..")) and candidate in by_path:
                    hooks.add(candidate)
        return hooks

    @staticmethod
    def hooks_for(rel_path: str) -> Iterator[Hook]:
        """Identify paths that execute during install, build or version control.

        First-class because execution context is the largest single multiplier in
        the risk model. Detecting these before scanning is what lets the same
        capability pair be quiet in application code and decisive here.

        This is the filename-level pass. Manifest lifecycle scripts are found by
        the manifest detector, which can parse them properly.
        """
        name = ContainerPaths.basename(rel_path)
        if (
            name in DEPENDENCY_BUILD_FILENAMES
            or name.endswith(DEPENDENCY_BUILD_SUFFIXES)
            or f"/{rel_path}".endswith("/deps/build.jl")
        ):
            # Julia's Pkg runs a package's deps/build.jl when the package is added or built.
            yield Hook(kind="build", path=rel_path, name=name)
        elif name.endswith(".pth"):
            # Installed into site-packages, its `import` lines run in every Python process the
            # machine starts -- earlier and more often than any install hook.
            yield Hook(kind="startup", path=rel_path, name=name)
        elif name in PROJECT_BUILD_FILENAMES:
            yield Hook(kind="projectbuild", path=rel_path, name=name)
        elif rel_path.startswith(".githooks/") or "/.git/hooks/" in f"/{rel_path}":
            yield Hook(kind="githook", path=rel_path, name=name)
        elif rel_path.startswith(CI_HOOK_PREFIXES) or name in CI_HOOK_FILENAMES:
            yield Hook(kind="ci", path=rel_path, name=name)

    #: A hook's whole command lifted out of its manifest: `package.json#preinstall.sh`.
    _LIFTED_HOOK: ClassVar[re.Pattern[str]] = re.compile(r"^(?P<hook>[\w:.-]+?)\.sh$")

    @staticmethod
    def onto_manifest(findings: list[Finding], units: Sequence[FileUnit]) -> list[Finding]:
        """Findings on a hook's command read as shell, placed on the hook in its manifest.

        The lifted command is not a file anyone can open; the manifest line declaring the hook
        is. (An inline `node -e` program keeps its own path: `core.inline_programs`.)
        The finding keeps what it says and its evidence hash, and points at that line.
        """
        manifests = {u.path: u.content.raw for u in units if "#" not in u.path}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path or ""
            owner, _, lifted = path.rpartition("#")
            hook = Hooks._LIFTED_HOOK.match(lifted) if owner else None
            raw = manifests.get(owner) if hook else None
            if raw is None or hook is None:
                out.append(finding)
                continue
            found = raw.find(f'"{hook.group("hook")}"'.encode())
            start = max(found, 0)
            end = raw.find(b"\n", start)
            end = len(raw) if end < 0 else end
            line_text = raw[start:end].decode("utf-8", "replace")
            snippet = finding.evidence.snippet
            out.append(
                replace(
                    finding,
                    location=replace(
                        finding.location,
                        path=owner,
                        line=raw[:start].count(b"\n") + 1,
                        column=None,
                        end_line=None,
                        end_column=None,
                        byte_start=start,
                        byte_end=end,
                    ),
                    evidence=replace(
                        finding.evidence,
                        span=(start, end),
                        snippet=line_text if snippet and "[redacted]" not in snippet else snippet,
                    ),
                )
            )
        return out

    @staticmethod
    def hook_import_closure(units: Sequence[FileUnit], hooks: set[str]) -> set[str]:
        """First-party Python files reachable by import from an install hook.

        Read, never executed. Only files present in this scan are followed: a
        payload inside an installed third-party package is not this repository's
        file to judge, and following imports out of the tree would make the
        closure unbounded and mostly irrelevant.
        """
        from cordon_scanner.engine.closure import ImportClosure

        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return set()
        return ImportClosure.resolve(hooks, sources)

    @staticmethod
    def hook_js_closure(units: Sequence[FileUnit], hooks: set[str]) -> set[str]:
        """First-party JavaScript files an install-hook script loads or runs.

        `require("./lib/x")`, `import ... from "./x.js"`, `import("./x")`, and a sibling named as
        `path.join(__dirname, "bun_environment.js")` -- the last is how the Shai-Hulud 2.0
        `setup_bun.js` hands its obfuscated payload to Bun. Followed transitively within the
        files of this scan, never out of it, and bounded.
        """
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith((".js", ".cjs", ".mjs")) and not unit.content.is_binary
        }
        pending = sorted(path for path in hooks if path in sources)  # a set: fixed order (#23)
        found: set[str] = set()
        while pending and len(found) < JS_CLOSURE_LIMIT:
            current = pending.pop()
            directory = current.rpartition("/")[0]
            text = sources[current]
            relatives = [
                match.group("rel") or match.group("sib")
                for match in JS_LOCAL_REFERENCE.finditer(text)
            ]
            # A path built in steps from `__dirname`: a directory variable, then a file under it.
            folders = {"__dirname": ""} | {
                found_dir["name"]: "/".join(Hooks._js_segments(found_dir.group(2)))
                for found_dir in JS_DIRECTORY_VARIABLE.finditer(text)
            }
            # Only a path the script loads -- `require(...)` or `import(...)` of it, directly or
            # through a variable holding it. A path it copies to or writes is not code it runs.
            for joined in JS_JOINED_PATH.finditer(text):
                if joined["base"] not in folders or not Hooks._js_loaded(text, joined):
                    continue
                tail = "/".join(Hooks._js_segments(joined.group(2)))
                relatives.append(f"{folders[joined['base']]}/{tail}".lstrip("/"))
            for relative in relatives:
                stem = posixpath.normpath(f"{directory}/{relative}" if directory else relative)
                for candidate in (
                    stem,
                    f"{stem}.js",
                    f"{stem}.cjs",
                    f"{stem}.mjs",
                    f"{stem}/index.js",
                ):
                    if candidate in sources and candidate not in found and candidate not in hooks:
                        found.add(candidate)
                        pending.append(candidate)
                        break
        return found

    @staticmethod
    def _js_loaded(text: str, joined: re.Match[str]) -> bool:
        """Whether a joined path is loaded: `require(path.join(...))`, or a variable assigned it and
        then required or imported."""
        before = text[max(0, joined.start() - 40) : joined.start()]
        if re.search(r"\b(?:require|import)\s{0,4}\(\s{0,4}$", before):
            return True
        assigned = re.search(r"\b(?:const|let|var)\s{1,4}([\w$]{1,60})\s{0,4}=\s{0,4}$", before)
        if assigned is None:
            return False
        name = re.escape(assigned.group(1))
        return (
            re.search(rf"\b(?:require|import)\s{{0,4}}\(\s{{0,4}}{name}\s{{0,4}}\)", text)
            is not None
        )

    @staticmethod
    def _js_segments(arguments: str) -> list[str]:
        """The string literals of a `path.join` argument list, in order."""
        return re.findall(r"""['"`]([\w@./-]{1,200})['"`]""", arguments)

    DEOBFUSCATED: ClassVar[str] = "#deobfuscated.js"
    """Suffix of the unit an obfuscated file's recovered text is read as (`core.deobfuscation`)."""

    @staticmethod
    def lifted_inherit(ctx: ScanContext) -> ScanContext:
        """A recovered unit runs when the file it came from runs: install hook, entry point,
        consumer install, agent tool, or a published package's import entry."""
        tree = ctx.tree_paths

        def grown(paths: frozenset[str]) -> frozenset[str]:
            more = {p + Hooks.DEOBFUSCATED for p in paths if p + Hooks.DEOBFUSCATED in tree}
            return paths | more if more else paths

        return replace(
            ctx,
            install_hook_paths=grown(ctx.install_hook_paths),
            install_entry_paths=grown(ctx.install_entry_paths),
            consumer_install_paths=grown(ctx.consumer_install_paths),
            agent_run_paths=grown(ctx.agent_run_paths),
            import_entry_paths=grown(ctx.import_entry_paths),
            library_entry_paths=grown(ctx.library_entry_paths),
            library_closure_paths=grown(ctx.library_closure_paths),
        )

    _ACTION_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"""["']?(?:\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?)["']?/"""
    )

    @staticmethod
    def hook_script_paths(
        manifest_path: str, hooks: Sequence[Hook], known: frozenset[str]
    ) -> set[str]:
        r"""Files a lifecycle command runs.

        A manifest declaring `"postinstall": "node install.js"` means
        `install.js` executes at install time, but marking only the manifest
        leaves that file scored as ordinary application code. The same
        credential read and outbound request that is critical in a hook then
        reports as merely suspicious, purely because the code lives one file
        away from the declaration.

        Only paths already present in the scan are added. A command naming a
        file that is not there tells us nothing, and resolving outside the scan
        root would follow attacker-controlled text out of the tree.

        **Resolved with `posixpath`, not `os.path`.** Scan paths are POSIX
        everywhere, and `os.path.normpath` on Windows rewrites `/` as `\`: a
        `postinstall` naming `scripts/setup.js` resolved to `scripts\setup.js`,
        matched nothing in `known`, and the file was never marked as running at
        install time. Every `MALWARE.*` composite that requires install-hook
        context then downgraded to its `SUSPECT.*` counterpart -- so Windows
        got weaker findings for one of the commonest layouts there is, and
        silently, because the finding was still produced.

        Only hooks in a subdirectory were affected, which is why it survived: a
        top-level `postinstall.js` has no separator for `normpath` to rewrite,
        and that is the shape every corpus sample used.
        """
        base = PurePosixPath(manifest_path).parent
        found: set[str] = set()

        Hooks.hook_command_scripts(hooks, base, known, found)

        return found

    @staticmethod
    def hook_command_scripts(
        hooks: Sequence[Hook], base: PurePosixPath, known: frozenset[str], found: set[str]
    ) -> None:
        """The scripts each lifecycle command names, resolved against the package."""
        for hook in hooks:
            # `node -e "try{require('./postinstall')}catch(e){}"` runs `postinstall.js` exactly as
            # `node postinstall.js` does; core-js declares it that way.
            for required in INLINE_REQUIRE.findall(hook.command):
                stem = posixpath.normpath(str(base / required))
                for candidate in (
                    stem,
                    f"{stem}.js",
                    f"{stem}.cjs",
                    f"{stem}.mjs",
                    f"{stem}/index.js",
                ):
                    if candidate in known and not candidate.startswith(".."):
                        found.add(candidate)
                        break
            previous = ""
            # A GitHub action names its own files through the action's checkout directory.
            command = Hooks._ACTION_PATH.sub("./", Hooks.runs(hook.command))
            for token in re.split(r"[\s;&|]+", command):
                candidate = token.strip("\"'")
                runner, previous = previous, PurePosixPath(candidate).name
                if not candidate or candidate.startswith("-"):
                    continue
                if runner in JS_RUNNERS and "." not in PurePosixPath(candidate).name.strip("."):
                    # What a JavaScript runner is handed is a module, resolved the way Node
                    # resolves one: `node setup` is `setup.js`, `node scripts/postinstall` is
                    # `scripts/postinstall.js`, `node .` is the package's `index.js`, and
                    # `node bin/preinstall` is that file, extension or not. Skipped as program
                    # names, 40 published packages' own hooks read as opaque, and a payload in
                    # `setup.js` reached this way was never install-time code (review 98).
                    stem = posixpath.normpath(str(base / candidate))
                    if stem.startswith(".."):
                        continue
                    for resolved in (
                        stem,
                        *(f"{stem}{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts")),
                        *(f"{stem}/index{suffix}" for suffix in (".js", ".cjs", ".mjs")),
                    ):
                        if resolved in known:
                            found.add(resolved)
                            break
                    continue
                if candidate in known:
                    # A command that names a member by its scan path, as a CRAN DESCRIPTION's
                    # `sh <archive>!<pkg>/configure` does: that file runs at install, whatever
                    # its extension. Exact membership only.
                    found.add(candidate)
                    continue
                if "." not in PurePosixPath(candidate).name:
                    # No extension: a program name such as `node` or `make`,
                    # not a file in the repository.
                    continue
                resolved = posixpath.normpath(str(base / candidate))
                if resolved.startswith(".."):
                    continue
                if resolved in known:
                    found.add(resolved)

    @staticmethod
    def runs(command: str) -> str:
        """A lifecycle command with the parts that only print stripped out.

        `NousResearch/hermes-agent` declares this `postinstall`:

            echo 'Node dependencies installed. Run: python run_agent.py --help'

        Every token of that is inside the quotes of an `echo`, and the resolver
        read `python run_agent.py` out of it and marked `run_agent.py` as a file
        that executes at install time. From there the import closure reached 510
        modules and every credential read beside an HTTPS call in the agent became
        `MALWARE.EXFIL.001` at CRITICAL -- from a help message.

        Split on the shell's own separators and drop the segments whose command is
        a printer. `sh -c "python x.py"` keeps its payload, because `sh` is not a
        printer and that shape is a real one: the distinction is the same one
        `TextPosition.is_printed_text` draws inside file contents.
        """
        segments = re.split(r"(?:&&|\|\||[;&|\n])", command)
        kept = []
        for segment in segments:
            first = segment.strip().lstrip("@-").split(" ", 1)[0]
            if ContainerPaths.basename(first) in PRINTING_COMMANDS:
                continue
            kept.append(segment)
        return " ".join(kept)

    @staticmethod
    def hook_deferred_lines(
        units: list[FileUnit], hooks: set[str], entries: frozenset[str] | None = None
    ) -> frozenset[tuple[str, int, int]]:
        """Bodies inside the closure that the hooks never actually call.

        The closure answers which files run at install time. Importing a module
        runs its top level and defines its functions; it does not call them, and
        a library reached because `setup.py` reads its `__version__` is almost
        entirely functions nothing on that path calls. See
        `core.reachability.CallReachability` for what is and is not treated as
        reachable, and why every approximation there keeps the finding.
        """
        from cordon_scanner.analysis.python.reachability import CallReachability
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        # A manifest can be a hook as a whole and still hold code its install never runs: a
        # Homebrew formula's `service`, `test` and `caveats` blocks. Its ecosystem says which.
        brew = frozenset(
            (unit.path, first, last)
            for unit in units
            if unit.path in hooks
            and (eco := EcosystemRegistry.manifest_ecosystem(unit.path)) is not None
            and (ecosystem := EcosystemRegistry.get(eco)) is not None
            for first, last in ecosystem.not_run_at_install(unit.path, unit.content.text)
        )
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return brew
        return brew | CallReachability.deferred_lines(hooks, sources, entries)

    @staticmethod
    def manifest_hook_paths(
        units: list[FileUnit], acc: Accumulator | None = None
    ) -> tuple[set[str], set[str], set[str]]:
        """Paths that execute at install time, according to their manifests -- and, third, the
        scripts a published GitHub action's composite steps run, which are CI code.

        The inventory's packaging test, here too: fixing only the first place a `setup.py` becomes
        a hook left `hermes_cli/subcommands/setup.py`, an argument parser, seeding an import closure
        of 510 files (`Hooks.hook_executes`). A Dockerfile a dependency vendors is not a hook:
        its RUN steps run when somebody builds that image, never on install (opencv's zlib-ng).
        """
        paths: set[str] = set()
        consumer: set[str] = set()
        ci_scripts: set[str] = set()
        """Paths that run for whoever INSTALLS the package, a subset (`ScanContext.consumer_install_paths`):
        a `setup.py` reaches a consumer only when it overrides a consumer-time command."""
        known = frozenset(unit.path for unit in units)
        package_directories = {
            unit.path.rpartition("/")[0]
            for unit in units
            if ContainerPaths.basename(unit.path) == "__init__.py"
        }
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None or (
                ecosystem_id == "image" and SourcePaths.is_vendored(unit.path)
            ):
                continue
            if ContainerPaths.basename(unit.path) in PACKAGED_BUILD_FILENAMES and (
                unit.path.rpartition("/")[0] in package_directories
                # And the second half of the same test. Applying only the
                # package-directory half here is the mistake this function's
                # docstring already warns about, one member of the family later:
                # `test/cpp_extensions/setup.py` is a fixture pytorch's own test
                # suite compiles, and it seeded a 507-file closure over `torch`.
                # See `FIXTURE_DIRECTORIES`.
                or Hooks.under_fixture_directory(unit.path)
            ):
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
                # And the hooks only the tree shows: a CRAN source package's `configure` and
                # `cleanup` beside its DESCRIPTION. The manifest detector and the inventory
                # already ask; without it here those scripts were never install-time code.
                hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
                if hooks_from_tree is not None:
                    manifest = hooks_from_tree(manifest, known)
            except Exception as exc:  # noqa: BLE001
                Hooks.manifest_parser_failed(acc, unit, ecosystem_id, exc)
                continue
            # Consumer-time hooks only. A `prepare` or a `prepack` runs on the author's
            # machine, not on the machine of anybody who installs the package from a
            # registry -- and marking the script it names as install-time code is what
            # put `MALWARE.ANTI_ANALYSIS.001` at critical on `n8n`'s three-line
            # `scripts/prepare.mjs`, which is the file the anti-analysis composite's own
            # comment cites as the false positive it was corrected for. See
            # `core.models.AUTHOR_TIME_HOOKS`, including what this gives up.
            #
            # The MANIFEST still counts whenever it declares any of them, because
            # `SUSPECT.INSTALL.SCRIPT.001` is about the declaration and grades itself by
            # which kind it is.
            if any(not hook.action_step for hook in manifest.hooks):
                paths.add(unit.path)
            ci_scripts, paths, consumer = Hooks.hook_reach(
                manifest, ci_scripts, unit, known, paths, consumer
            )
        return paths, consumer, ci_scripts

    @staticmethod
    def manifest_parser_failed(
        acc: Accumulator | None, unit: FileUnit, ecosystem_id: str, exc: Exception
    ) -> None:
        """A manifest parser that raised: the file's install hooks are unknown, and the scan says so."""
        # Same containment as the lockfile path, and reported for the
        # same reason. Catching it and moving on quietly would trade one
        # failure mode (the scan dies) for the worse one (the manifest
        # was never read and nothing says so), which is the trade this
        # whole audit is about.
        if acc is not None:
            acc.complete = False
            acc.append(
                OperationalFinding.build(
                    path=unit.path,
                    rule_id="OPERATIONAL.PARSER.FAILED",
                    message=(
                        f"The {ecosystem_id} manifest parser failed on this file, "
                        f"so its install hooks were not identified: "
                        f"{type(exc).__name__}"
                    ),
                    remediation="Report this with the file that triggered it.",
                    severity=Severity.MEDIUM,
                )
            )

    @staticmethod
    def hook_reach(
        manifest: Manifest,
        ci_scripts: set[str],
        unit: FileUnit,
        known: frozenset[str],
        paths: set[str],
        consumer: set[str],
    ) -> tuple[set[str], set[str], set[str]]:
        """Where a manifest's hooks reach: the action steps that run its scripts, and what a consumer's install runs."""
        if manifest.hooks:
            # A published action's composite steps run on its consumers' runners as CI code:
            # what they name is read in CI context, not install context (review 98: as
            # install code, 305 of 2,978 benign actions blocked).
            steps = [hook for hook in manifest.hooks if hook.action_step]
            if steps:
                ci_scripts |= Hooks.hook_script_paths(unit.path, steps, known)
            reaching = [
                hook
                for hook in manifest.hooks
                if hook.name.lower() not in AUTHOR_TIME_HOOKS and hook not in steps
            ]
            if reaching:
                paths |= Hooks.hook_script_paths(unit.path, reaching, known)
                paths |= {
                    program.path
                    for hook in reaching
                    for program in InlinePrograms.lifted(unit.path, hook.name, hook.command or "")
                    if program.path in known
                }
            consuming = [hook for hook in manifest.hooks if hook.kind == "consumerinstall"]
            if consuming:
                consumer.add(unit.path)
                consumer |= Hooks.hook_script_paths(unit.path, consuming, known)
                consumer |= {
                    program.path
                    for hook in consuming
                    for program in InlinePrograms.lifted(unit.path, hook.name, hook.command or "")
                    if program.path in known
                }
        return ci_scripts, paths, consumer


__all__ = ["Hooks"]
