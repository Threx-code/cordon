"""What an agent's configuration makes the machine do, judged without running any of it.

Pure functions over strings and parsed settings, used by `detect/agents.py`. Three questions recur
across every agent's configuration format:

* What does a command it runs do? A hook, an MCP server's launch, a settings key that runs a helper,
  an editor task that starts when the folder opens -- each is a shell command, and the same few
  shapes are the attack in all of them: fetch code and run it, send credentials or the environment
  off the machine, open a shell to somewhere else. `classify` answers that once for all of them.
* Where does it send the agent's traffic? An API base URL or proxy pointed elsewhere hands the
  developer's API key to whoever runs that host (CVE-2026-21852).
* What does it give a server? A container launched with the host's root, its Docker socket or its
  SSH keys; a filesystem server scoped to the whole disk; an environment variable that loads code
  into the process before it starts.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Final

# -- Commands -------------------------------------------------------------------------------

_SHELL_FETCH_EXEC: Final = re.compile(
    r"(?i)\b(?:curl|wget|fetch)\b[^\n|;]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\b(?:curl|wget)\b[^\n]{0,300}\|\s*(?:python3?|node|perl|ruby)\b(?![ \t]{1,8}-[cm]\b)"
    r"|\b(?:curl|wget)\b[^\n]{0,200}(?:-o|-O|--output)\s*\S+[^\n]{0,80}&&[^\n]{0,80}\b(?:sh|bash|chmod\s+\+x)\b"
    r"|\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:ba|z)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b"
    r"|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b"
)
_POWERSHELL_FETCH_EXEC: Final = re.compile(
    r"(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
    r"net\.webclient|start-bitstransfer)\b[^\n]{0,300}(?:\|\s*(?:iex|invoke-expression)\b|\biex\b|"
    r"\binvoke-expression\b|start-process)"
    r"|\b(?:iex|invoke-expression)\s*[\(\s]\s*[\(\s]*(?:new-object\s+net\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)\b"
    r"|-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/]{40,}={0,2}"
)
_INTERPRETER_FETCH_EXEC: Final = re.compile(
    r"(?is)\bpython[23]?(?:\.\d+)?\s+-c\b.{0,400}?\b(?:urlopen|urllib|requests\.get|httpx\.get|http\.client)\b"
    r".{0,400}?\b(?:exec|eval)\s*\("
    r"|\bnode\s+(?:-e|--eval|-p)\b.{0,400}?\b(?:fetch\s*\(|https?\.get\s*\(|require\(\s*[\"']https?[\"']\s*\))"
    r".{0,400}?(?:\beval\b|\bFunction\s*\(|child_process|execSync|\bspawn\s*\()"
    r"|\b(?:perl|ruby)\s+-e\b.{0,300}?\b(?:LWP|open-uri|Net::HTTP|URI\.open)\b"
)
_CREDENTIAL_SOURCE: Final = re.compile(
    r"(?i)(?:~|\$HOME|\$\{HOME\}|/root|/home/[\w.-]+)/\.(?:ssh|aws|azure|kube|docker|gnupg|npmrc|pypirc|netrc|git-credentials|config/gcloud)\b"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?<![\w.-])\.env\b(?!\.example|\.sample|\.template)"
    r"|\$\(\s*(?:env|printenv|set)\s*\)|`\s*(?:env|printenv)\s*`"
    r"|\b(?:GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|NPM_TOKEN)\b"
)
_SENDS_IT: Final = re.compile(
    r"(?i)\b(?:curl|wget|httpie|nc|ncat|netcat|socat|invoke-webrequest|invoke-restmethod|iwr|irm)\b"
    r"[^\n]{0,200}(?:\s-d\b|\s--data(?:-binary|-raw|-urlencode)?\b|\s-F\b|\s--form\b|\s-T\b|"
    r"\s--upload-file\b|\s--post-file\b|\s--body-file\b|\s-X\s*(?:POST|PUT)\b|\s-Method\s+(?:Post|Put)\b|"
    r"\s-H\s*[\"']?Authorization\b|@-|\s\d{2,5}\s*<)"
    r"|\bhttp\s+(?:POST|PUT)\b"
)
"""A network tool carrying data out: a data, form or upload flag, a header, stdin, or a raw socket.
A URL alone is a fetch, and the word `http` in prose is not a command."""
_ENV_TO_NETWORK: Final = re.compile(
    r"(?i)\b(?:env|printenv|set|export\s+-p)\s*\|\s*(?:base64\s*\|\s*)?(?:curl|wget|nc|ncat|netcat|socat)\b"
)
_REVERSE_SHELL: Final = re.compile(
    r"(?i)/dev/(?:tcp|udp)/[\w.-]+/\d{1,5}"
    r"|\b(?:nc|ncat|netcat)\b[^\n]{0,80}\s-(?:e|c)\s+\S*(?:sh|cmd|powershell)\b"
    r"|\bmkfifo\b[^\n]{0,120}\b(?:nc|ncat|netcat|openssl\s+s_client)\b"
    r"|\bsocat\b[^\n]{0,120}\bexec:[\"']?\S*sh\b"
    r"|\bpython[23]?\s+-c\b[^\n]{0,400}\bsocket\b[^\n]{0,400}\b(?:pty\.spawn|subprocess|os\.dup2)\b"
    r"|\bbash\s+-i\s*>&"
)


_TOKEN_HOMES: Final = {
    "OPENAI_API_KEY": ("api.openai.com", ".openai.azure.com"),
    "ANTHROPIC_API_KEY": ("api.anthropic.com",),
    "GITHUB_TOKEN": ("api.github.com", "github.com", "uploads.github.com"),
    "NPM_TOKEN": ("registry.npmjs.org",),
    "AWS_SECRET_ACCESS_KEY": (".amazonaws.com",),
}
"""The service each token variable belongs to. `curl https://api.openai.com/v1/models -H
"Authorization: Bearer $OPENAI_API_KEY"` is the key being used, not stolen."""
_DESTINATIONS: Final = re.compile(r"(?i)https?://([a-z0-9.-]+)")


class CommandClassifier:
    """What a command an agent configuration runs does: attack-shaped, routine, or reaching out."""

    @staticmethod
    def _sent_home(source: str, command: str) -> bool:
        """A token variable sent only to its own service's hosts."""
        homes = _TOKEN_HOMES.get(source.upper())
        if homes is None:
            return False
        hosts = [h.lower() for h in _DESTINATIONS.findall(command)]
        return bool(hosts) and all(
            any(host == home.lstrip(".") or host.endswith(home) for home in homes) for host in hosts
        )

    @staticmethod
    def classify(command: str) -> CommandVerdict | None:
        """What an attack-shaped command does, or None for one that is not attack-shaped."""
        if not command:
            return None
        if _REVERSE_SHELL.search(command):
            return CommandVerdict("reverse-shell", "opens an interactive shell to another machine")
        if _ENV_TO_NETWORK.search(command) or (
            _SENDS_IT.search(command)
            and any(
                not CommandClassifier._sent_home(m.group(0), command)
                for m in _CREDENTIAL_SOURCE.finditer(command)
            )
        ):
            return CommandVerdict(
                "exfiltration", "sends credentials or the environment to another machine"
            )
        if (
            _SHELL_FETCH_EXEC.search(command)
            or _POWERSHELL_FETCH_EXEC.search(command)
            or _INTERPRETER_FETCH_EXEC.search(command)
        ):
            return CommandVerdict("fetch-exec", "downloads code and runs it")
        return None

    @staticmethod
    def reaches_out(command: str) -> bool:
        """A hook command that touches the network, runs a remote package, decodes a payload,
        evaluates a string, or edits shell start-up or cron -- what a hook needs a reviewer for.
        Local automation over the edited file (jq, a formatter, the repository's own script) does
        none of these."""
        return _REACHES_OUT.search(command) is not None

    @staticmethod
    def is_routine(command: str) -> bool:
        """A command whose first program is a developer tool, or a script kept in the repository.

        A hook that formats, lints, tests, notifies, or runs one of the repository's own scripts --
        whose contents the scan reads as the repository's code -- is what hooks are committed for.
        """
        try:
            words = shlex.split(command, posix=True)
        except ValueError:
            words = command.split()
        while words and _ASSIGNMENT.match(words[0]):
            words = words[1:]
        if not words:
            return False
        first = words[0]
        if first.rsplit("/", 1)[-1] in _PACKAGE_RUNNERS:
            # `npx prettier --write .`: the tool is the first word that is not a flag.
            tool = next((w for w in words[1:] if not w.startswith("-") and w != "dlx"), "")
            return tool.rsplit("@", 1)[0].rsplit("/", 1)[-1] in _DEV_TOOLS
        if first in _DEV_TOOLS or first.rsplit("/", 1)[-1] in _DEV_TOOLS:
            return True
        if CommandClassifier._in_repository(first):
            return True
        if first.rsplit("/", 1)[-1] in _INTERPRETERS and len(words) > 1:
            return CommandClassifier._in_repository(words[1])
        return False

    @staticmethod
    def _in_repository(word: str) -> bool:
        return word.startswith(
            ("./", "scripts/", ".claude/", ".cursor/", ".gemini/", ".github/", "tools/", "bin/",
             "$CLAUDE_PROJECT_DIR", "${CLAUDE_PROJECT_DIR}", '"$CLAUDE_PROJECT_DIR', "$CLAUDE_PLUGIN_ROOT",
             "${CLAUDE_PLUGIN_ROOT}", '"${CLAUDE_PLUGIN_ROOT}', "~/.claude/")
        )  # fmt: skip


@dataclass(frozen=True)
class CommandVerdict:
    kind: str
    """`fetch-exec`, `exfiltration` or `reverse-shell`."""
    reason: str


_DEV_TOOLS: Final = frozenset(
    {
        # formatters, linters, type checkers, test runners
        "ruff", "black", "isort", "flake8", "pylint", "mypy", "pyright", "pytest", "tox", "nox",
        "prettier", "eslint", "biome", "tsc", "jest", "vitest", "mocha", "stylelint", "markdownlint",
        "gofmt", "goimports", "golangci-lint", "rustfmt", "clippy-driver", "shellcheck", "shfmt",
        "clang-format", "swiftformat", "swiftlint", "ktlint", "rubocop", "phpcs", "php-cs-fixer",
        "dotnet", "terraform", "tflint", "hadolint", "yamllint", "actionlint", "codespell",
        # build tools and package scripts
        "npm", "pnpm", "yarn", "bun", "deno", "uv", "poetry", "pip", "go", "cargo", "make", "just",
        "task", "gradle", "./gradlew", "mvn", "./mvnw", "bundle", "rake", "composer", "mix",
        # version control, notifications, and plain output
        "git", "gh", "jq", "echo", "printf", "true", "date", "tee", "cat", "osascript",
        "notify-send", "terminal-notifier", "afplay", "say", "paplay", "powershell.exe",
    }
)  # fmt: skip
_PACKAGE_RUNNERS: Final = frozenset({"npx", "bunx", "pnpx", "uvx"})
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_INTERPRETERS: Final = frozenset({"python", "python3", "node", "bash", "sh", "zsh", "pwsh", "ruby"})


_REACHES_OUT: Final = re.compile(
    r"(?i)\b(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|rsync|ftp|telnet|invoke-webrequest|"
    r"invoke-restmethod|iwr|irm)\b|https?://|\b(?:npx|bunx|pnpx|uvx|pipx)\s+(?!-)"
    r"|\bbase64\s+(?:-d|--decode|-D)\b|\bcrontab\b|~/\.(?:bashrc|zshrc|profile|bash_profile)\b"
    r"|\beval\b"
)


# -- Where agent traffic goes ---------------------------------------------------------------

API_BASE_VARIABLES: Final = frozenset(
    {
        "ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
        "OPENAI_BASE_URL", "OPENAI_API_BASE", "AZURE_OPENAI_ENDPOINT", "GOOGLE_GEMINI_BASE_URL",
        "GEMINI_API_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy",
        "http_proxy", "all_proxy",
    }
)  # fmt: skip
"""Variables that decide where an agent sends its requests, and so its API key."""

_OFFICIAL_API_HOSTS: Final = (
    "api.anthropic.com", ".anthropic.com", "api.openai.com", ".openai.azure.com",
    ".amazonaws.com", ".googleapis.com", "localhost", "127.0.0.1", "[::1]",
    "0.0.0.0",  # noqa: S104  (a host recognised in a URL, not an address to bind)
    "host.docker.internal",
)  # fmt: skip
_URL: Final = re.compile(r"(?i)^\s*(?:[a-z][a-z0-9+.-]*://)?(?:[^@/\s]*@)?([^/:\s?#]+)")


class ApiTraffic:
    """Where an agent's API traffic, and so its API key, is sent."""

    @staticmethod
    def host_of(url: str) -> str:
        found = _URL.match(url)
        return found.group(1).lower().strip("[]") if found else ""

    @staticmethod
    def redirects_api(name: str, value: object) -> bool:
        """A variable that sends the agent's API traffic somewhere other than the provider."""
        if name not in API_BASE_VARIABLES or not isinstance(value, str) or not value.strip():
            return False
        if value.strip().startswith(("${", "$")):
            return False
        host = ApiTraffic.host_of(value)
        if not host:
            return False
        return not any(
            host == official.lstrip(".") or host.endswith(official)
            for official in _OFFICIAL_API_HOSTS
        )


# -- What a server is given -----------------------------------------------------------------

_DOCKER_VALUE_FLAGS: Final = frozenset(
    {
        "-e", "--env", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network",
        "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label",
        "--env-file", "--add-host", "--cap-add", "--cap-drop", "--device", "--pid", "--ipc",
        "--security-opt", "--tmpfs", "-h", "--hostname", "-m", "--memory", "--cpus", "--gpus",
        "--restart", "--log-driver", "--runtime", "--userns", "--uts", "--ulimit", "--shm-size",
        "--dns", "--expose", "--group-add", "--health-cmd", "--label-file", "--link", "--log-opt",
        "--stop-signal", "--volumes-from", "--cgroupns", "--pull",
    }
)  # fmt: skip
_HOST_PATHS: Final = re.compile(
    r"(?i)^(?:/|/etc|/root|/home|/users|/var/run/docker\.sock|/run/docker\.sock|/proc|/sys|/boot"
    r"|c:\\?|~|\$home|\$\{home\}|%userprofile%)(?:/|\\)?$"
    r"|(?:^|/)\.(?:ssh|aws|azure|kube|docker|gnupg|config/gcloud)(?:/|$)|docker\.sock$"
)
_SOCKET_ONLY: Final = re.compile(r"(?i)docker\.sock")
_ESCAPE_CAPS: Final = frozenset(
    {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN"}
)


@dataclass(frozen=True)
class DockerLaunch:
    image: str | None
    host_access: tuple[str, ...]
    """The flags that give the container the host: privilege, host namespaces, host paths."""

    @property
    def socket_only(self) -> bool:
        """Only the Docker socket is mounted: what a Docker-management server needs to work, and
        still root-equivalent, so reviewed rather than refused."""
        return bool(self.host_access) and all(_SOCKET_ONLY.search(a) for a in self.host_access)


class ServerExposure:
    """What an MCP server is given: the host from its container, code through its environment, the whole disk."""

    @staticmethod
    def docker_run(args: list[str]) -> DockerLaunch | None:
        """`docker run ...` (or `podman run`), parsed: the image, and what of the host it is given."""
        if "run" not in args:
            return None
        rest = args[args.index("run") + 1 :]
        image: str | None = None
        access: list[str] = []
        index = 0
        while index < len(rest):
            word = rest[index]
            if not word.startswith("-"):
                image = word
                break
            flag, _, inline = word.partition("=")
            value = inline
            if flag in _DOCKER_VALUE_FLAGS and not inline:
                index += 1
                value = rest[index] if index < len(rest) else ""
            if flag == "--privileged":
                access.append("--privileged")
            elif (
                flag in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns")
                and value == "host"
            ):
                access.append(f"{flag}={value}")
            elif flag == "--cap-add" and value.upper().removeprefix("CAP_") in _ESCAPE_CAPS:
                access.append(f"--cap-add={value}")
            elif flag == "--security-opt" and re.search(r"(?i)unconfined|label[=:]disable", value):
                access.append(f"--security-opt={value}")
            elif flag in ("-v", "--volume"):
                source = value.split(":", 1)[0]
                if _HOST_PATHS.search(source):
                    access.append(f"{flag} {value}")
            elif flag == "--mount":
                source = next(
                    (
                        p.split("=", 1)[1]
                        for p in value.split(",")
                        if p.startswith(("source=", "src="))
                    ),
                    "",
                )
                if source and _HOST_PATHS.search(source):
                    access.append(f"--mount {value}")
            index += 1
        return DockerLaunch(image, tuple(access))

    @staticmethod
    def injects_code(name: str, value: object) -> bool:
        """An environment variable that loads code into the server's process before it starts."""
        if not isinstance(value, str) or not value.strip():
            return False
        if name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"):
            # Usually heap sizes and system properties; only a `-javaagent` loads code.
            return "-javaagent" in value
        if name in _INJECTING_VARIABLES:
            return True
        return name == "NODE_OPTIONS" and _NODE_PRELOAD.search(value) is not None

    @staticmethod
    def credential_in_url(url: str) -> str | None:
        """A credential carried in a URL's query string, which ends up in logs and history."""
        found = _SECRET_QUERY.search(url)
        if found is None or found.group(1).startswith(("${", "$", "<", "%7B")):
            return None
        return found.group(1)

    @staticmethod
    def broad_filesystem_scope(args: list[str]) -> str | None:
        """A filesystem server given the whole disk or home directory, or None."""
        if not any(_FILESYSTEM_SERVERS.search(a) for a in args):
            return None
        return next((a for a in args if _WHOLE_DISK.match(a.strip())), None)

    @staticmethod
    def wide_directory(path: object) -> bool:
        """An extra working directory that is the whole disk or a home directory."""
        return isinstance(path, str) and _WIDE_DIRECTORIES.match(path.strip()) is not None


_INJECTING_VARIABLES: Final = frozenset(
    {"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "PYTHONSTARTUP", "PERL5OPT",
     "RUBYOPT", "GCONV_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"}
)  # fmt: skip
_NODE_PRELOAD: Final = re.compile(
    r"(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader)(?:[=\s]|$)"
)


_SECRET_QUERY: Final = re.compile(
    r"(?i)[?&](?:token|access_token|api[_-]?key|apikey|key|secret|auth|password|sig|signature)=([^&#\s]{12,})"
)


OFFICIAL_MCP_PACKAGES: Final = frozenset(
    {
        "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab", "@modelcontextprotocol/server-git",
        "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-sqlite", "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-redis", "@modelcontextprotocol/server-sentry",
        "@modelcontextprotocol/server-gdrive", "@modelcontextprotocol/server-aws-kb-retrieval",
        "@modelcontextprotocol/inspector", "@playwright/mcp", "@upstash/context7-mcp",
        "@notionhq/notion-mcp-server", "@supabase/mcp-server-supabase", "@stripe/mcp",
        "@sentry/mcp-server", "@cloudflare/mcp-server-cloudflare", "@azure/mcp",
        "@browserbasehq/mcp", "@heroku/mcp-server", "@shopify/dev-mcp", "@vercel/mcp-adapter",
        "figma-developer-mcp", "firecrawl-mcp", "mcp-remote", "chrome-devtools-mcp",
        "mcp-server-git", "mcp-server-fetch", "mcp-server-time", "mcp-server-sqlite",
        "awslabs.core-mcp-server", "awslabs.aws-documentation-mcp-server",
    }
)  # fmt: skip
"""The MCP servers people launch most, by registry name: a name one or two edits from one of them,
or a scope one edit from theirs, is a lookalike."""


class PackageLookalike:
    """MCP server packages named like the popular ones."""

    @staticmethod
    def _distance(a: str, b: str) -> int:
        if abs(len(a) - len(b)) > 2:
            return 3
        previous = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            current = [i]
            for j, cb in enumerate(b, 1):
                current.append(
                    min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
                )
            previous = current
        return previous[-1]

    @staticmethod
    def lookalike_of(package: str) -> str | None:
        """The official MCP package this name imitates, or None."""
        name = re.sub(r"(?<=.)@[^@/]*$", "", package)
        name = re.sub(r"==.*$", "", name)
        if name in OFFICIAL_MCP_PACKAGES:
            return None
        scope, _, base = name.partition("/") if name.startswith("@") else ("", "", name)
        for official in OFFICIAL_MCP_PACKAGES:
            o_scope, _, o_base = (
                official.partition("/") if official.startswith("@") else ("", "", official)
            )
            if (
                scope
                and o_scope
                and scope != o_scope
                and base == o_base
                and PackageLookalike._distance(scope, o_scope) <= 2
            ):
                return official
            # One edit on a short name; two on a name of ten characters or more, where `rn` for
            # `m` is the classic two-edit swap.
            allowed = 2 if len(o_base) >= 10 else 1
            if (
                scope == o_scope
                and base != o_base
                and 0 < PackageLookalike._distance(base, o_base) <= allowed
                and len(base) > 6
            ):
                return official
        return None


_FILESYSTEM_SERVERS: Final = re.compile(
    r"(?i)(?:^|/)(?:@modelcontextprotocol/)?(?:mcp-)?server-filesystem\b"
)
_WHOLE_DISK: Final = re.compile(
    r"(?i)^(?:/|~|~/|\$HOME|\$\{HOME\}|/home|/Users|/root|C:\\?|%USERPROFILE%)$"
)


_WIDE_DIRECTORIES: Final = re.compile(
    r"(?i)^(?:/|~|~/|\$HOME/?|\$\{HOME\}/?|/home/?|/Users/?|/root/?|C:\\?|%USERPROFILE%)$"
)


__all__ = [
    "API_BASE_VARIABLES",
    "OFFICIAL_MCP_PACKAGES",
    "ApiTraffic",
    "CommandClassifier",
    "CommandVerdict",
    "DockerLaunch",
    "PackageLookalike",
    "ServerExposure",
]
