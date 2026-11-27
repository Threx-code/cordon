"""MCP server declarations in every agent's configuration dialect, and what they launch."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.detect.agents.paths import MCP_PATHS
from cordon_scanner.foundation.formats import jsonc
from cordon_scanner.foundation.formats.scanned_json import ScannedJson

if TYPE_CHECKING:
    from cordon_scanner.ecosystems.launchers import Launcher
    from cordon_scanner.foundation.content import FileContent


# -- A3: MCP launch commands -----------------------------------------------------------------
class LaunchSpecs:
    """How the words after a launch command read, by the kind of spec a launcher names (`Launcher.spec`): `<kind>_package(words)`
    finds the package spec among them, `<kind>_split(spec)` reads its (name, version or None), `<kind>_pinned(spec)` says whether
    it names one release. The declarations that use them are the adapters' `mcp_launch` (`ecosystems/launchers.py`)."""

    NPM_EXACT: ClassVar[re.Pattern[str]] = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?")
    PYPI_PIN: ClassVar[re.Pattern[str]] = re.compile(r"([\w.\-\[\],]+?)(?:==|@)(\d[\w.\-+]*)")
    PYPI_SPLIT: ClassVar[re.Pattern[str]] = re.compile(
        r"([\w.\-]+)(?:\[[^\]]*\])?(?:==|@)(\d[\w.\-+]*)"
    )
    GO_EXACT: ClassVar[re.Pattern[str]] = re.compile(r"v\d+\.\d+\.\d+(?:[-+][\w.+]+)?")
    GO_VALUE_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "-tags",
            "-ldflags",
            "-gcflags",
            "-asmflags",
            "-C",
            "-exec",
            "-mod",
            "-modfile",
            "-overlay",
            "-p",
            "-pkgdir",
        }
    )
    NUGET_EXACT: ClassVar[re.Pattern[str]] = re.compile(
        r"[0-9][0-9.]{0,30}(?:-[\w.]{1,60})?(?:\+[\w.]{1,60})?"
    )
    NUGET_VALUE_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {"--version", "--source", "--add-source", "--configfile", "--framework", "--verbosity"}
    )
    GAV: ClassVar[re.Pattern[str]] = re.compile(
        r"([\w.\-]+):([\w.\-]+):([\w.\-+]+)(?::[\w.\-]+)?(?:@\S+)?"
    )
    GEM_EXACT: ClassVar[re.Pattern[str]] = re.compile(r"(?:=\s*)?(\d[\w.]{0,60})")
    NIX_REV: ClassVar[re.Pattern[str]] = re.compile(r"(?:/|[?&]rev=)([0-9a-f]{40})(?=[#?&]|$)")
    CONDA_PIN: ClassVar[re.Pattern[str]] = re.compile(
        r"([\w.\-]{1,200})\s*={1,2}\s*(\d[\w.\-+]{0,60})"
    )
    DENO_SPECIFIER: ClassVar[re.Pattern[str]] = re.compile(r"npm:(\S+)")
    SWIFT_EXACT: ClassVar[re.Pattern[str]] = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?")

    # -- finding the package among the words -------------------------------------------------

    @staticmethod
    def _first_package(rest: list[str]) -> str | None:
        """The first word that is not a flag or a flag's value (the `npx` / `uvx` reading, unchanged)."""
        package = None
        skip_next = False
        for arg in rest:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-p", "--package", "--from", "--python", "--with"):
                if arg in ("-p", "--package", "--from"):
                    skip_next = False
                    continue
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            package = arg
            break
        return package or None

    @staticmethod
    def npm_package(rest: list[str]) -> str | None:
        return LaunchSpecs._first_package(rest)

    @staticmethod
    def pypi_package(rest: list[str]) -> str | None:
        return LaunchSpecs._first_package(rest)

    @staticmethod
    def deno_npm_package(rest: list[str]) -> str | None:
        """`deno run npm:pkg@1.2.3`: the `npm:` specifier, without its prefix."""
        for arg in rest:
            found = LaunchSpecs.DENO_SPECIFIER.fullmatch(arg)
            if found:
                return found.group(1)
        return None

    @staticmethod
    def image_package(rest: list[str]) -> str | None:
        """`docker run [options] IMAGE`: the image reference, for a command that runs one."""
        from cordon_scanner.detect.agents.configuration import ServerExposure

        launched = ServerExposure.docker_run(rest)
        return launched.image if launched is not None and launched.image else None

    @staticmethod
    def go_package(rest: list[str]) -> str | None:
        """`go run module@version`: a module path with a version query; a local package path launches nothing downloaded."""
        skip = False
        for arg in rest:
            if skip:
                skip = False
                continue
            if arg in LaunchSpecs.GO_VALUE_FLAGS:
                skip = True
                continue
            if arg.startswith("-"):
                continue
            return arg if "@" in arg and not arg.startswith((".", "/")) else None
        return None

    @staticmethod
    def nuget_package(rest: list[str]) -> str | None:
        """`dnx package[@version]` or `dnx package --version V`."""
        package: str | None = None
        version: str | None = None
        skip = False
        for index, arg in enumerate(rest):
            if skip:
                skip = False
                continue
            flag, _, inline = arg.partition("=")
            if flag in LaunchSpecs.NUGET_VALUE_FLAGS:
                if flag == "--version":
                    version = inline or (rest[index + 1] if index + 1 < len(rest) else None)
                skip = not inline
                continue
            if arg.startswith("-"):
                continue
            if package is None:
                package = arg
        if package is None:
            return None
        return f"{package}@{version}" if version and "@" not in package else package

    @staticmethod
    def maven_package(rest: list[str]) -> str | None:
        """`jbang group:artifact:version`: the first word that is a Maven coordinate."""
        return next(
            (a for a in rest if not a.startswith("-") and LaunchSpecs.GAV.fullmatch(a)), None
        )

    @staticmethod
    def gem_package(rest: list[str]) -> str | None:
        """`gem exec [-v REQ] [-g GEM] gem_name command`: the gem, with a `-v` requirement written `gem@REQ`."""
        name: str | None = None
        requirement: str | None = None
        skip = False
        for index, arg in enumerate(rest):
            if skip:
                skip = False
                continue
            flag, _, inline = arg.partition("=")
            if flag in ("-v", "--version", "-g", "--gem"):
                value = inline or (rest[index + 1] if index + 1 < len(rest) else "")
                if flag in ("-v", "--version"):
                    requirement = value or None
                else:
                    name = value or name
                skip = not inline
                continue
            if arg.startswith("-"):
                continue
            if name is None:
                name = arg
            break
        if not name:
            return None
        return f"{name}@{requirement}" if requirement else name

    @staticmethod
    def nix_package(rest: list[str]) -> str | None:
        """`nix run FLAKE#attr`: the flake reference (the words before `--`)."""
        for arg in rest:
            if arg == "--":
                return None
            if arg.startswith("-"):
                continue
            return arg if ":" in arg or "#" in arg else None
        return None

    @staticmethod
    def conda_package(rest: list[str]) -> str | None:
        """`pixi exec [--spec SPEC] command`: the spec, else the command's first word (the package it guesses)."""
        for index, arg in enumerate(rest):
            flag, _, inline = arg.partition("=")
            if flag in ("--spec", "-s"):
                return inline or (rest[index + 1] if index + 1 < len(rest) else None)
        skip = False
        for arg in rest:
            if skip:
                skip = False
                continue
            if arg in (
                "--with",
                "-w",
                "--channel",
                "-c",
                "--platform",
                "--manifest-path",
                "--list",
            ):
                skip = True
                continue
            if arg.startswith("-"):
                continue
            return arg
        return None

    @staticmethod
    def swift_package(rest: list[str]) -> str | None:
        """`mint run owner/repo@version`."""
        return next((a for a in rest if not a.startswith("-")), None)

    # -- reading it ---------------------------------------------------------------------------

    @staticmethod
    def npm_split(spec: str) -> tuple[str, str | None]:
        head, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
        name = "@" + head if spec.startswith("@") else head
        return name, version if LaunchSpecs.NPM_EXACT.fullmatch(version) else None

    @staticmethod
    def pypi_split(spec: str) -> tuple[str, str | None]:
        match = LaunchSpecs.PYPI_SPLIT.fullmatch(spec)
        if match:
            return match.group(1), match.group(2)
        return re.split(r"[\[=@<>~!]", spec, maxsplit=1)[0], None

    @staticmethod
    def image_split(spec: str) -> tuple[str, str | None]:
        """`name@sha256:...` is a digest, `name:tag` a tag (a colon before the last `/` is a registry port)."""
        if "@" in spec:
            name, _, digest = spec.partition("@")
            return name, digest or None
        last = spec.rpartition("/")[2]
        if ":" in last:
            name, _, tag = spec.rpartition(":")
            return name, tag or None
        return spec, None

    @staticmethod
    def go_split(spec: str) -> tuple[str, str | None]:
        name, _, version = spec.rpartition("@")
        return name, version if LaunchSpecs.GO_EXACT.fullmatch(version) else None

    @staticmethod
    def nuget_split(spec: str) -> tuple[str, str | None]:
        name, _, version = spec.partition("@")
        return name, version if LaunchSpecs.NUGET_EXACT.fullmatch(version) else None

    @staticmethod
    def maven_split(spec: str) -> tuple[str, str | None]:
        found = LaunchSpecs.GAV.fullmatch(spec)
        if found is None:
            return spec, None
        version = found.group(3)
        floating = (
            version in ("RELEASE", "LATEST") or "+" in version or version.startswith(("[", "("))
        )
        return f"{found.group(1)}:{found.group(2)}", None if floating else version

    @staticmethod
    def gem_split(spec: str) -> tuple[str, str | None]:
        name, _, requirement = spec.partition("@")
        found = LaunchSpecs.GEM_EXACT.fullmatch(requirement.strip()) if requirement else None
        return name, found.group(1) if found else None

    @staticmethod
    def nix_split(spec: str) -> tuple[str, str | None]:
        """`github:owner/repo/<rev>#attr` to (`owner/repo`, rev); another reference keeps its text before `#` and `?`."""
        reference = spec.partition("#")[0]
        rev = LaunchSpecs.NIX_REV.search(reference)
        scheme, _, rest = reference.partition(":")
        if scheme in ("github", "gitlab", "sourcehut") and rest:
            pieces = rest.partition("?")[0].split("/")
            return "/".join(pieces[:2]), rev.group(1) if rev else None
        return reference.partition("?")[0], rev.group(1) if rev else None

    @staticmethod
    def conda_split(spec: str) -> tuple[str, str | None]:
        found = LaunchSpecs.CONDA_PIN.fullmatch(spec.strip())
        if found:
            return found.group(1), found.group(2)
        return re.split(r"[=<>!~ ]", spec.strip(), maxsplit=1)[0], None

    @staticmethod
    def swift_split(spec: str) -> tuple[str, str | None]:
        name, _, version = spec.partition("@")
        return name, version if LaunchSpecs.SWIFT_EXACT.fullmatch(version) else None

    # -- whether it names one release -------------------------------------------------------------

    @staticmethod
    def npm_pinned(spec: str) -> bool:
        return LaunchSpecs.npm_split(spec)[1] is not None

    @staticmethod
    def pypi_pinned(spec: str) -> bool:
        return LaunchSpecs.PYPI_PIN.fullmatch(spec) is not None

    @staticmethod
    def image_pinned(spec: str) -> bool:
        return "@sha256:" in spec

    @staticmethod
    def go_pinned(spec: str) -> bool:
        return LaunchSpecs.go_split(spec)[1] is not None

    @staticmethod
    def nuget_pinned(spec: str) -> bool:
        return LaunchSpecs.nuget_split(spec)[1] is not None

    @staticmethod
    def maven_pinned(spec: str) -> bool:
        return LaunchSpecs.maven_split(spec)[1] is not None

    @staticmethod
    def gem_pinned(spec: str) -> bool:
        return LaunchSpecs.gem_split(spec)[1] is not None

    @staticmethod
    def nix_pinned(spec: str) -> bool:
        return LaunchSpecs.NIX_REV.search(spec.partition("#")[0]) is not None

    @staticmethod
    def conda_pinned(spec: str) -> bool:
        return LaunchSpecs.CONDA_PIN.fullmatch(spec.strip()) is not None

    @staticmethod
    def swift_pinned(spec: str) -> bool:
        return LaunchSpecs.swift_split(spec)[1] is not None


class McpConfigs:
    """MCP server declarations in every agent's configuration dialect, and what they launch."""

    PATHS: ClassVar[tuple[str, ...]] = MCP_PATHS
    """The files an agent reads its MCP servers from (`agents.paths.MCP_PATHS`): where to look for
    the declarations `mcp_servers` reads."""

    @staticmethod
    def launchers() -> tuple[tuple[str, Launcher], ...]:
        """Every (ecosystem id, launcher) the adapters declare (`mcp_launch`), in registry order."""
        from cordon_scanner.ecosystems.base import BaseEcosystem
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        return tuple(
            (ecosystem.id, launcher)
            for ecosystem in EcosystemRegistry.all_ecosystems()
            if isinstance(ecosystem, BaseEcosystem) and isinstance(ecosystem.mcp_launch, tuple)
            for launcher in ecosystem.mcp_launch
        )

    @staticmethod
    def launcher_ecosystems() -> frozenset[str]:
        """The ecosystems an MCP server can be launched from by a command that names its release (those whose spec is read)."""
        return frozenset(ecosystem for ecosystem, _ in McpConfigs.launchers())

    @staticmethod
    def purl_type(ecosystem: str) -> str:
        """The package-URL type of an ecosystem's packages (its adapter's: `golang` for `gomod`, `gem` for `rubygems`)."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        adapter = EcosystemRegistry.get(ecosystem)
        return adapter.purl_type if adapter is not None else ecosystem

    @staticmethod
    def spec_kind(ecosystem: str) -> str | None:
        return next((lc.spec for e, lc in McpConfigs.launchers() if e == ecosystem), None)

    @staticmethod
    def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
        """`@scope/pkg@1.2.3` to (`@scope/pkg`, `1.2.3`); a floating spec gets version None."""
        kind = McpConfigs.spec_kind(ecosystem) or "pypi"
        split: Callable[[str], tuple[str, str | None]] = getattr(LaunchSpecs, f"{kind}_split")
        return split(spec)

    @staticmethod
    def program(command: str) -> str:
        """The program a command names, as one word: its last path part, on either separator, lower
        case, without Windows' `.cmd` or `.exe`. A Windows config names `C:\\Program Files\\nodejs\\
        npx.cmd`; split on `/` alone it stayed the whole path, so its server's package was never
        examined, nor a `docker.exe run`'s image, nor an agent hook's runner (4 Nov)."""
        return re.split(r"[/\\]", command)[-1].lower().removesuffix(".cmd").removesuffix(".exe")

    @staticmethod
    def launched_package(command: str, args: list[str]) -> tuple[str, str, bool] | None:
        """The (ecosystem, package spec, pinned) an MCP launch command downloads, if it does."""
        runner = McpConfigs.program(command)
        rest = list(args)
        launchers = McpConfigs.launchers()
        found: tuple[str, Launcher] | None = next(
            ((e, lc) for e, lc in launchers if any(words == (runner,) for words in lc.commands)),
            None,
        )
        if found is None:
            for ecosystem, launcher in launchers:
                for words in launcher.commands:
                    if (
                        len(words) > 1
                        and words[0] == runner
                        and [a.lower() for a in rest[: len(words) - 1]] == list(words[1:])
                    ):
                        found = (ecosystem, launcher)
                        rest = rest[len(words) - 1 :]
                        if launcher.skip and rest[: len(launcher.skip)] == list(launcher.skip):
                            rest = rest[len(launcher.skip) :]
                        break
                if found is not None:
                    break
        if found is None:
            return None
        ecosystem, launcher = found
        read: Callable[[list[str]], str | None] = getattr(
            LaunchSpecs, launcher.read or f"{launcher.spec}_package"
        )
        package = read(rest)
        if not package:
            return None
        pinned: Callable[[str], bool] = getattr(LaunchSpecs, f"{launcher.spec}_pinned")
        return ecosystem, package, pinned(package)

    @staticmethod
    def mcp_servers(path: str, text: str) -> list[tuple[str, dict[str, Any]]]:
        """Every MCP server a configuration declares, as `(name, {command, args, url, env, ...})`.

        The agents disagree on the shape. Claude, Cursor, Gemini, Cline, Kiro and Amazon Q write
        `mcpServers: {name: {command, args}}`; VS Code writes `servers`; Zed writes `context_servers`
        with the launch under `command: {path, args}`; opencode writes `mcp` with `command` as one
        list; Codex writes TOML `[mcp_servers.name]`; Continue writes YAML with `mcpServers` as a
        list. A server missed for its dialect is a server never checked.
        """
        member = path.rpartition("!")[2]
        if member.endswith(".toml"):
            try:
                document: Any = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, ValueError):
                return []
            servers: Any = document.get("mcp_servers") if isinstance(document, dict) else None
        elif member.endswith((".yaml", ".yml")) or "/.continue/mcpServers/" in f"/{member}":
            return McpConfigs._continue_servers(text)
        else:
            document = McpConfigs._json_text(text)
            if not isinstance(document, dict):
                return []
            servers = (
                document.get("mcpServers")
                or document.get("servers")
                or document.get("context_servers")
                or document.get("mcp")
            )
        if not isinstance(servers, dict):
            return []
        out: list[tuple[str, dict[str, Any]]] = []
        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            server = dict(server)
            command = server.get("command")
            if isinstance(command, dict):  # Zed: command: {path, args, env}
                server["args"] = command.get("args") or server.get("args")
                server["env"] = command.get("env") or server.get("env")
                server["command"] = command.get("path")
            elif isinstance(command, list) and command:  # opencode: command: ["npx", "-y", "pkg"]
                server["command"], server["args"] = str(command[0]), [str(a) for a in command[1:]]
            if "environment" in server and "env" not in server:
                server["env"] = server["environment"]
            out.append((str(name), server))
        return out

    @staticmethod
    def _continue_servers(text: str) -> list[tuple[str, dict[str, Any]]]:
        """Continue's `mcpServers:` list, read for the four keys that matter without a YAML library:
        each `- name:` starts a server; `args` is a flow list or the block list beneath it."""
        servers: list[dict[str, Any]] = []
        in_block = False
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if re.match(r"^\s*mcpServers\s*:", line):
                in_block = True
                continue
            if not in_block:
                continue
            env_start = re.match(r"^(\s*)(?:-\s*)?env\s*:\s*$", line)
            if env_start is not None and servers:
                indent = len(env_start.group(1))
                env: dict[str, str] = {}
                for following in lines[index + 1 :]:
                    pair = re.match(r"^(\s+)([A-Za-z_][\w]*)\s*:\s*((?:.*\S)?)\s*$", following)
                    if pair is None or len(pair.group(1)) <= indent:
                        break
                    env[pair.group(2)] = pair.group(3).strip("'\"")
                servers[-1]["env"] = env
                continue
            match = _YAML_KEY.match(line)
            if match is None:
                continue
            key, value = match.group(1), match.group(2).strip().strip("'\"")
            if (line.lstrip().startswith("-") and key == "name") or not servers:
                servers.append({})
            current = servers[-1]
            if key == "args":
                if value.startswith("["):
                    current["args"] = [
                        a.strip().strip("'\"") for a in value.strip("[]").split(",") if a.strip()
                    ]
                else:
                    items = []
                    for following in lines[index + 1 :]:
                        item = _YAML_ITEM.match(following)
                        if item is None or _YAML_KEY.match(following):
                            break
                        items.append(item.group(1).strip("'\""))
                    current["args"] = items
            else:
                current[key] = value
        return [
            (str(s.get("name", "server")), s) for s in servers if s.get("command") or s.get("url")
        ]

    @staticmethod
    def without_comments(text: str) -> str:
        """`re.sub(r'("(?:\\\\.|[^"\\\\])*")|//[^\\n]*|/\\*[\\s\\S]*?\\*/', keep strings, text)`, read
        once: JSON with `//` and `/* */` comments, strings kept whole. As an expression an unclosed
        string or comment was read to the end of the text from every quote or `/*` after it (quadratic);
        here a string that cannot close marks every quote before where it failed as failing too (each
        such quote was read as escaped inside it, so its own read continues the same way), and a `/*`
        with no `*/` after it ends every later one."""
        out: list[str] = []
        at, size = 0, len(text)
        strings_fail_before, comments_open = 0, True
        while at < size:
            char = text[at]
            if char == '"' and at >= strings_fail_before:
                end = McpConfigs._string_end(text, at)
                if end > 0:
                    out.append(text[at:end])
                    at = end
                    continue
                strings_fail_before = -end
            elif char == "/" and text.startswith("//", at):
                newline = text.find("\n", at)
                at = size if newline < 0 else newline
                continue
            elif char == "/" and comments_open and text.startswith("/*", at):
                close = text.find("*/", at + 2)
                if close >= 0:
                    at = close + 2
                    continue
                comments_open = False
            out.append(char)
            at += 1
        return "".join(out)

    @staticmethod
    def _string_end(text: str, start: int) -> int:
        """The index past the string opening at `start` (`"(?:\\\\.|[^"\\\\])*"`), or minus the index its
        read stopped at when it cannot close."""
        at, size = start + 1, len(text)
        while at < size:
            char = text[at]
            if char == '"':
                return at + 1
            if char == "\\":
                if at + 1 >= size or text[at + 1] == "\n":
                    return -at
                at += 2
                continue
            at += 1
        return -at

    @staticmethod
    def _json_text(text: str) -> Any:
        try:
            return ScannedJson.loads(text)
        except ValueError:
            pass
        stripped = McpConfigs.without_comments(text)
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            return ScannedJson.loads(stripped)
        except ValueError:
            return None

    @staticmethod
    def _command_strings(value: Any) -> list[str]:
        """A command field in any of the shapes the dev-container and agent-environment schemas allow:
        a string, an argument list, or an object of named commands."""
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [" ".join(str(a) for a in value)] if value else []
        if isinstance(value, dict):
            return [c for v in value.values() for c in McpConfigs._command_strings(v)]
        return []

    @staticmethod
    def _hook_commands(hooks: dict[str, Any]) -> list[str]:
        commands: list[str] = []
        for entries in hooks.values():
            for entry in entries if isinstance(entries, list) else ():
                if not isinstance(entry, dict):
                    continue
                for hook in entry.get("hooks") or ():
                    if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                        commands.append(hook["command"])
                if isinstance(entry.get("command"), str):
                    commands.append(entry["command"])
        return commands

    @staticmethod
    def _json(content: FileContent) -> Any:
        # JSON with comments and trailing commas (VS Code config, dev containers): the shared helper.
        return jsonc.Jsonc.loads(content.text)


# Both are matched against every line of an MCP config an attacker may write, so neither may be
# quadratic in a line (review 98, 27-PERFORMANCE). The indentation is possessive (`\s*+`: what it gave
# back the dash cannot take and the next `\s*` would), and a value is "up to its last non-blank" rather
# than a lazy `(.*?)` re-tried against `\s*$` at every length -- the same groups, found once.
_YAML_KEY: Final = re.compile(r"^\s*+-?\s*(name|command|url|args)\s*:\s*((?:.*\S)?)\s*$")
_YAML_ITEM: Final = re.compile(r"^\s*-\s+(.*\S|[^\S\n])\s*$")
r"""One `- item` of a block list. The `[^\S\n]` branch keeps the lazy `(.+?)` form's one odd answer:
a dash followed by blanks only captures one blank."""


__all__ = ["McpConfigs"]
