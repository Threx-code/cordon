"""Legitimate use: the reasons a composite that matched is not what it looks like.

Reading a credential and reaching the network is what an API client does all day when the credential
goes to the service that issued it. These are the capability detector's checks for the uses that look
like an attack pattern and are not: a credential handed to its own service or issuer, a credential
store read by its own client, a setting a file configures itself with, a release download verified
against a digest it ships, an official installer, a destination that is this machine, the output a
package ships, a provisioning script a person runs by hand, a Homebrew formula, an agent tool that
never runs what it fetched."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pyast import CREDENTIAL_VARIABLE
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.load_path import LoadPath
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class LegitimateUse:
    """Checks for the legitimate uses that match an attack pattern."""

    LOOPBACK: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0)\b|\[::1\]|['\"]::1['\"]"
    )

    ELSEWHERE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\b[a-z][a-z0-9+.-]{1,20}://|\b(?:\d{1,3}\.){3}\d{1,3}\b|"
        rb"\b[a-z0-9-]{1,63}\.(?:com|net|org|io|dev|app|xyz|ru|cn|top|me|co|sh|site|online)\b",
        re.IGNORECASE,
    )

    SHIPPED_OUTPUT: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:build|bin|dist)/[^!]{1,400}\.(?:c?js|mjs)$"
    )

    #: Findings whose evidence is a value followed from where it is read to where it goes
    #: (`analysis/javascript/js_flow.py`), not two patterns near each other: a server's reply reaching an
    #: evaluator, the machine's identity or a credential file reaching a request.
    FLOW_EVIDENCE_RULES: ClassVar[frozenset[str]] = frozenset(
        {
            "SUSPECT.DROPPER.REMOTE_CODE.001",
            "SUSPECT.EXFIL.FLOW_IDENTITY.001",
            "SUSPECT.EXFIL.FLOW_SECRET.001",
        }
    )

    @staticmethod
    def flow_in_shipped_code(rule_id: str, content: FileContent, ctx: ScanContext) -> bool:
        """A followed flow in the code a published npm package runs: its library entry points (`main`,
        `exports`) and what its install hooks load. There `dist/` and the minified bundle are not
        build output beside the code -- they are the code (review 98, 17-PROOF-REVIEW: the
        generated-output and minified ceilings lowered 21 study-half misses' flow findings).
        Proximity findings keep the ceilings: a bundle holds a loader's decoder and evaluator."""
        return (
            rule_id in LegitimateUse.FLOW_EVIDENCE_RULES
            and ctx.package_distribution
            and ctx.distribution == "npm"
            # Not a `bin` target alone: a CLI that fetches and runs its plugins or its update runs
            # when a person runs it (review 98: both benign blocks were `bin` tools).
            and (content.path in ctx.library_entry_paths or ctx.in_install_hook(content.path))
        )

    @staticmethod
    def shipped_output(path: str, ctx: ScanContext) -> bool:
        return (
            ctx.package_distribution
            and ctx.distribution == "npm"
            and LegitimateUse.SHIPPED_OUTPUT.search(path) is not None
        )

    @staticmethod
    def loopback_only(region: bytes) -> bool:
        """Whether every destination named in `region` is this machine."""
        if not LegitimateUse.LOOPBACK.search(region):
            return False
        for found in LegitimateUse.ELSEWHERE.finditer(region):
            text = found.group(0).lower()
            if text.endswith(b"://"):
                tail = region[found.end() : found.end() + 40].lower()
                if not LegitimateUse.LOOPBACK.match(tail):
                    return False
            elif text not in (b"127.0.0.1", b"0.0.0.0"):
                return False
        return True

    FORMULA: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"^class\s+\w+\s*<\s*(?:Portable)?Formula\b", re.MULTILINE
    )

    @staticmethod
    def is_formula(content: FileContent) -> bool:
        """A Homebrew formula: Ruby declaring `class Name < Formula`."""
        return content.path.endswith(".rb") and bool(LegitimateUse.FORMULA.search(content.raw))

    #: Files a person runs to set up a machine, by name or extension: never imported, never run
    #: by a package manager on someone else's behalf.
    HAND_RUN_PROVISIONING_NAMES: ClassVar[frozenset[str]] = frozenset(
        {"vagrantfile", "dockerfile", "containerfile"}
    )

    HAND_RUN_PROVISIONING_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".dockerfile",
        ".patch",
        ".diff",
        ".nix",
        ".tpl",
        ".tmpl",
        ".j2",
        ".postinst",
        ".preinst",
        ".chroot",
    )

    @staticmethod
    def is_hand_run_provisioning(path: str, language: str | None) -> bool:
        name = path.rpartition("!")[2].rpartition("/")[2].lower()
        return (
            name in LegitimateUse.HAND_RUN_PROVISIONING_NAMES
            or name.startswith(("dockerfile.", "vagrantfile."))
            or name.endswith(LegitimateUse.HAND_RUN_PROVISIONING_SUFFIXES)
            or language in ("shell", "powershell", "batch", "dockerfile")
        )

    _URL_HOST = re.compile(r"https?://([a-z0-9.-]{3,253})", re.IGNORECASE)

    SERVICE_HOSTS: ClassVar[dict[str, tuple[str, ...]]] = {
        "GITHUB": ("github.com", "githubusercontent.com", "ghcr.io"),
        "GH": ("github.com", "githubusercontent.com", "ghcr.io"),
        "GITLAB": ("gitlab.com",),
        "NPM": ("npmjs.org", "npmjs.com"),
        "PYPI": ("pypi.org", "pythonhosted.org"),
        "TWINE": ("pypi.org",),
        "HF": ("huggingface.co",),
        "HUGGINGFACE": ("huggingface.co",),
        "DOCKER": ("docker.io", "docker.com"),
        "CODECOV": ("codecov.io",),
        "OPENAI": ("openai.com",),
        "ANTHROPIC": ("anthropic.com",),
        "SLACK": ("slack.com",),
        "SENTRY": ("sentry.io",),
    }

    @classmethod
    def credential_for_its_own_service(cls, content: FileContent) -> bool:
        """Every credential this Python file reads is handed straight to a call addressed to the
        service the credential is named for.

        lxml's build helper calls `read_url(url, github_api_token=os.environ.get(
        "GITHUB_API_TOKEN"))` with `url` bound to `https://api.github.com/...`: the token goes to
        the service that issued it, which is what a token is for. Judged per read and from the
        call the read is an argument of, never from what else the file contacts -- the same
        build also downloads zlib from `zlib.net`, without the token. A whole-environment read,
        a credential named for no service, or one read that goes anywhere else keeps the
        finding.
        """
        if not content.path.endswith(".py"):
            return False
        try:
            tree = PythonSyntax.shared(content.text)
        except (SyntaxError, ValueError, RecursionError):
            return False

        parents: dict[int, ast.AST] = {}
        for node in PythonSyntax.nodes(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node

        def scope_of(node: ast.AST) -> int:
            current = parents.get(id(node))
            while current is not None and not isinstance(
                current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
            ):
                current = parents.get(id(current))
            return id(current) if current is not None else id(tree)

        # Bindings per function: `url` is assigned in many functions of a build script, and
        # the one that matters is the one in the function making the call.
        bound: dict[tuple[int, str], list[ast.AST]] = {}
        for node in PythonSyntax.nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.setdefault((scope_of(node), target.id), []).append(node.value)

        def urls_in(call: ast.Call) -> list[str]:
            found: list[str] = []
            for argument in [*call.args, *(k.value for k in call.keywords)]:
                values: list[ast.AST] = [argument]
                key = (scope_of(argument), argument.id) if isinstance(argument, ast.Name) else None
                if key is not None and len(bound.get(key, [])) == 1:
                    values = bound[key]
                for value in values:
                    for inner in PythonSyntax.nodes(value):
                        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                            found.extend(
                                m.group(1).lower() for m in cls._URL_HOST.finditer(inner.value)
                            )
            return found

        from cordon_scanner.analysis.python.pyast import PythonAnalyzer

        handed = PythonAnalyzer.excused_lines(content.text).get(Capability.CREDENTIAL, frozenset())
        reads = 0
        for node in PythonSyntax.nodes(tree):
            key: str | None = None
            if (
                LegitimateUse._environ(node)
                and not isinstance(parents.get(id(node)), ast.Subscript | ast.Attribute)
                and getattr(node, "lineno", 0) not in handed
            ):
                return False  # the environment as a whole, other than handed to a child
            key = LegitimateUse._credential_key(key, node)
            if key is None or not CREDENTIAL_VARIABLE.search(key):
                continue
            reads += 1
            service = next(
                (
                    domains
                    for prefix, domains in cls.SERVICE_HOSTS.items()
                    if key.upper() == prefix or key.upper().startswith(prefix + "_")
                ),
                None,
            )
            carrier = LegitimateUse._carrier_call(node, parents)
            if service is None or not isinstance(carrier, ast.Call):
                return False
            hosts = urls_in(carrier)
            if not hosts or not all(
                any(h == d or h.endswith("." + d) for d in service) for h in hosts
            ):
                return False
        return reads > 0

    @staticmethod
    def _credential_key(key: str | None, node: ast.AST) -> str | None:
        """The variable name an environment read asks for: os.environ.get, os.getenv or os.environ[...] with a literal name."""
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and LegitimateUse._environ(func.value)
            ) or (isinstance(func, ast.Attribute) and func.attr == "getenv"):
                key = str(node.args[0].value)
        elif (
            isinstance(node, ast.Subscript)
            and LegitimateUse._environ(node.value)
            and isinstance(node.slice, ast.Constant)
        ):
            key = str(node.slice.value)
        return key

    @staticmethod
    def _carrier_call(node: ast.AST, parents: dict[int, ast.AST]) -> ast.AST | None:
        """The node a credential read is handed to, past the keywords, operators, f-strings and dicts that only carry it."""
        carrier = parents.get(id(node))
        while isinstance(
            carrier,
            ast.keyword | ast.BinOp | ast.JoinedStr | ast.FormattedValue | ast.BoolOp | ast.Dict,
        ):
            carrier = parents.get(id(carrier))
        return carrier

    @staticmethod
    def _environ(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )

    @staticmethod
    def official_installs_only(content: FileContent, hits: list[CapabilityHit]) -> bool:
        from cordon_scanner.detect.code.verified_download import VerifiedDownload

        return VerifiedDownload.official_installs_only(content.raw, hits)

    @staticmethod
    def verified_release_download(
        unit: FileUnit, ctx: ScanContext, file_hits: list[CapabilityHit]
    ) -> bool:
        from cordon_scanner.detect.code.verified_download import VerifiedDownload

        if not ctx.package_distribution:
            # Condition (b) places the digest in the package, and only a published package's
            # members are known to be what the consumer receives beside the script. A listed
            # tool's own release is pinned by its URL alone (`official_install`), wherever it is.
            return VerifiedDownload.official_install(unit.content.text, unit.language, file_hits)
        return VerifiedDownload.verified(
            unit.content.text,
            unit.language,
            unit.content.path,
            file_hits,
            ctx.tree_paths,
            # Condition (c), the package's own `repository` (`ScanContext.package_repository`):
            # a release on github.com is the package's only if its owner and repository match.
            # Hosts with no owner in the path (the npm registries, nodejs.org) do not need it.
            ctx.package_repository or None,
        ) or VerifiedDownload.package_install(
            unit.content.text, unit.language, file_hits, ctx.package_repository or None, ctx
        )

    @staticmethod
    def tool_runs_nothing_downloaded(unit: FileUnit, ctx: ScanContext) -> bool:
        """An agent's tool script that fetches and runs, but never runs what it fetched.

        A skill's helper is run by the agent on request, and `curl "$api" | jq` beside
        `python3 -c` is what such a script does. Install-time code keeps the co-occurrence
        rule: there the pair is the attack. See `detect/download_flow.py` for what is followed
        and the measurement; a language it does not read keeps the co-occurrence verdict.
        """
        from cordon_scanner.detect.code.download_flow import DownloadFlow

        content = unit.content
        if content.path in ctx.consumer_install_paths or not LoadPath.agent_run(content, ctx):
            return False
        return DownloadFlow.runs_download(content.text, unit.language) == []

    _SETTING_READ: ClassVar[re.Pattern[str]] = re.compile(
        r"""^\s{0,8}(?:
            process\.env\.(?P<dotted>[A-Za-z_][A-Za-z0-9_]{0,80})\b(?!\s{0,4}[\[(])
          | (?:os\.(?:getenv|environ\.get|environ\s{0,4}\[)|process\.env\s{0,4}\[
             |std::env::var(?:_os)?\s{0,4}\(|env!\s{0,4}\(|ENV(?:\.fetch\s{0,4}\(|\s{0,4}\[)
             |System\.getenv\s{0,4}\(|Environment\.GetEnvironmentVariable\s{0,4}\(
             |os\.Getenv\s{0,4}\()
            \s{0,4}\(?\s{0,4}["'](?P<quoted>[A-Za-z_][A-Za-z0-9_]{0,80})["']
        )""",
        re.VERBOSE,
    )

    _PLATFORM_LOOKUP: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s{0,8}(?:platform\.(?:machine|system|architecture|processor|python_version)\s{0,4}\("
        r"|os\.(?:homedir|platform|arch|tmpdir|cpus|endianness)\s{0,4}\("
        r"|process\.(?:platform|arch)\b|sys\.platform\b)"
    )

    @classmethod
    def a_setting(cls, content: FileContent, hit: CapabilityHit) -> bool:
        """Whether a credential or reconnaissance hit reads only a setting the file configures
        itself with, so that it is not what a request to a drop point carries away.

        A notifier reads its bot token and posts a message; a stealer reads the environment, the
        user and host names, or the public address, and posts those (review 98: the 62 benign
        units blocked by `SUSPECT.EXFIL.DROP_POINT.001` alone against 16 malware samples, every
        one of which sends identity or the whole environment). A named setting that is a
        well-known credential of another service (`NPM_TOKEN`, `GITHUB_TOKEN`, AWS keys -- see
        `secretflow.CREDENTIAL_HOMES`) is loot whatever reads it.
        """
        if hit.capability not in (Capability.CREDENTIAL, Capability.RECONNAISSANCE):
            return False
        if hit.rule_id.endswith("_SENT") or "PUBLIC_IP" in hit.rule_id:
            return False
        end = min(hit.byte_end, hit.byte_start + 240)
        text = content.raw[hit.byte_start : max(end, hit.byte_start + 1)].decode("utf-8", "replace")
        if cls._PLATFORM_LOOKUP.match(text):
            return True
        read = cls._SETTING_READ.match(text)
        if read is None:
            return False
        from cordon_scanner.analysis.shared.credential_homes import CREDENTIAL_HOMES

        name = read.group("dotted") or read.group("quoted") or ""
        return not any(pattern.match(name) for pattern, _ in CREDENTIAL_HOMES)

    #: Credentials whose issuer is known, and the hosts that issue them.
    #:
    #: Sending a service's own token to that service is authentication. It is
    #: what the token is FOR, it happens in every CI script and packaging script
    #: that reads a private repository, and it gives an attacker nothing: the
    #: host already knows the credential.
    ISSUER_HOSTS: ClassVar[tuple[tuple[tuple[bytes, ...], tuple[bytes, ...]], ...]] = (
        ((b"GITHUB_TOKEN", b"GH_TOKEN", b"GITHUB_PAT"), (b"github.com", b"githubusercontent.com")),
        ((b"GITLAB_TOKEN", b"CI_JOB_TOKEN"), (b"gitlab.com",)),
        ((b"NPM_TOKEN", b"NODE_AUTH_TOKEN"), (b"registry.npmjs.org", b"npmjs.com")),
        ((b"PYPI_TOKEN", b"TWINE_PASSWORD"), (b"pypi.org", b"files.pythonhosted.org")),
        ((b"CARGO_REGISTRY_TOKEN",), (b"crates.io",)),
        ((b"DOCKER_TOKEN", b"DOCKERHUB_TOKEN"), (b"docker.io", b"index.docker.io")),
        ((b"AWS_SECRET_ACCESS_KEY", b"AWS_SESSION_TOKEN"), (b"amazonaws.com",)),
    )

    HOST_IN_URL = re.compile(rb"https?://([A-Za-z0-9._-]{4,253})")

    #: A credential store, and the clients that store exists to serve.
    STORE_CLIENTS: ClassVar[tuple[tuple[re.Pattern[bytes], re.Pattern[bytes]], ...]] = (
        (
            re.compile(rb"\.ssh[/\\\"', ]"),
            re.compile(
                rb"paramiko|SSHClient|asyncssh|\bssh2\b|x/crypto/ssh|\bssh\.(?:Dial|NewClient)\b"
                rb"|SSH_AUTH_SOCK|net\.Dial\(\s{0,4}\"unix\"|\brsync\b|\bscp\b|\bsftp\b|Net::SSH|JSch"
            ),
        ),
        (
            re.compile(rb"\.aws[/\\]"),
            re.compile(rb"boto3|botocore|aws-sdk|@aws-sdk|Aws::|AWSSDK|amazonaws\.com"),
        ),
        (
            re.compile(rb"\.config/gcloud|application_default_credentials"),
            re.compile(rb"google\.auth|googleapis\.com|google-auth|@google-cloud"),
        ),
        (
            re.compile(rb"\.azure[/\\]"),
            re.compile(
                rb"azure\.identity|@azure/|management\.azure\.com|login\.microsoftonline\.com"
            ),
        ),
        (
            re.compile(rb"\.pypirc"),
            re.compile(rb"\btwine\b|upload\.pypi\.org|test\.pypi\.org"),
        ),
    )

    @classmethod
    def store_used_by_its_own_client(
        cls, content: FileContent, window: list[CapabilityHit]
    ) -> bool:
        """Whether a credential store here is read only by the client it belongs to.

        A deploy tool loads `~/.ssh/id_ed25519` into paramiko and connects; an S3 helper lets
        boto3 read `~/.aws/credentials`. The key goes where it authenticates, which is what it
        is for (review 98: SSH and cloud tools blocked by `SUSPECT.EXFIL.CREDENTIAL_STORE.001`).
        Every store named must belong to a family here, and EVERY outbound call in the window
        must be that family's client: a stealer that reads the same file and posts it with
        `requests` or a raw socket is untouched, as is a browser's cookie store, which has no
        client but the browser.
        """
        stores = [h for h in window if h.rule_id == "CAP.CREDENTIAL.STORE.001"]
        egress = [h for h in window if h.capability is Capability.EGRESS]
        if not stores or not egress:
            return False
        families: list[re.Pattern[bytes]] = []
        for hit in stores:
            text = content.raw[max(0, hit.byte_start - 2) : hit.byte_end + 2]
            client = next((c for store, c in cls.STORE_CLIENTS if store.search(text)), None)
            if client is None:
                return False
            families.append(client)
        return all(
            any(
                client.search(content.raw[hit.byte_start : hit.byte_end + 40])
                for client in families
            )
            for hit in egress
        )

    @classmethod
    def credential_reaches_its_own_issuer(
        cls, content: FileContent, window: list[CapabilityHit]
    ) -> bool:
        """Whether every credential here is being sent to the host that issued it.

        `vllm`'s `setup.py` asks GitHub which commit `main` is on, and
        authenticates so the request is not rate-limited:

            github_token = os.getenv("GH_TOKEN", os.getenv("GITHUB_TOKEN"))
            curl_cmd += ["-H", f"Authorization: token {github_token}"]

        A credential read, an outbound request, and an install-time context --
        `MALWARE.EXFIL.001` at CRITICAL, in the MALICIOUS category, telling the
        reader to treat their host as compromised. `pytorch`'s `torch/hub.py`
        does the same thing for the same reason.

        Nothing is exfiltrated. The host being contacted is the one that issued
        the token, already knows it, and is the only party the token is good
        against. This is what the credential is for.

        Narrow on purpose, and in the safe direction: it takes effect only when
        EVERY host named in the window belongs to the issuer of EVERY credential
        named in it. A payload that reads `GITHUB_TOKEN` and posts it anywhere
        else names another host and is untouched -- which is the whole attack
        this rule exists to catch.
        """
        if not window:
            return False
        lines = content.line_starts
        first = min(h.byte_start for h in window)
        last = max(h.byte_end for h in window)
        del lines
        text = content.raw[first:last]
        if not text:
            return False

        hosts = {m.group(1).lower() for m in cls.HOST_IN_URL.finditer(text)}
        if not hosts:
            return False

        issuers: list[tuple[bytes, ...]] = []
        for names, owned in cls.ISSUER_HOSTS:
            if any(name in text for name in names):
                issuers.append(owned)
        if not issuers:
            return False

        def owned_by_some_issuer(host: bytes) -> bool:
            return any(
                host == owner or host.endswith(b"." + owner) for owned in issuers for owner in owned
            )

        return all(owned_by_some_issuer(host) for host in hosts)


__all__ = ["LegitimateUse"]
