"""A prebuilt binary fetched from a release host and checked against a digest the package ships.

`@ohos-ports/larksuite-cli` (review 98, FP-2) is the case: its `scripts/install.js` downloads the
Lark CLI release archive from `github.com/larksuite/cli/releases/download/...` or
`registry.npmmirror.com`, refuses any other host, compares the archive's sha256 with the line for
it in the `checksums.txt` it ships, and only then extracts and `chmod`s the binary. That is fetch,
write and spawn in a postinstall hook, so `MALWARE.DROPPER.001` reported it at CRITICAL with
"treat the host as compromised".

## What this may and may not do

It answers one question about one file -- is every download in it a pinned release, verified
against a digest that did not come from the network, before anything runs? -- and the only
thing the answer may change is the dropper-by-pattern grading (`capability._composite_finding`):
`MALWARE.DROPPER.001` is withdrawn and `SUSPECT.DROPPER.001` reports the span at MEDIUM.

It never makes a file clean, and that is a design constraint rather than caution (review 98,
`08` P3): whoever owns the repository owns the release and the checksum too, so a malicious
binary published as a release asset with its own sha256 beside it satisfies every condition here.
What the conditions remove is the *shape* of a dropper -- a download whose content the author
does not fix -- not the question of what the binary is. Every other rule over the file
(credential reads, persistence, obfuscation, the binary rules over what it ships) is untouched.

## Why lexical

The conditions are read off the source, comments removed, without data flow. Each one fails
closed: a URL whose host or repository cannot be read as a literal, a digest whose reference
cannot be placed in the package, a check that cannot be ordered before the first `chmod` or
spawn -- all leave the finding as it was. The cost of that is lowering fewer real installers,
never lowering a dropper the conditions do not describe.
"""

from __future__ import annotations

import ast
import posixpath
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.foundation.comments import BLOCK_COMMENT_LANGUAGES, SourceComments
from cordon_scanner.foundation.models import Capability
from cordon_scanner.intel.malware.hosts import Destinations

if TYPE_CHECKING:
    from cordon_scanner.detect.code.capability import CapabilityHit

#: Hosts that serve release artefacts and nothing else an install script would fetch from them.
#: Path-qualified where the host also serves other things: `github.com` only under
#: `/<owner>/<repo>/releases/download/<tag>/`, `cdn.jsdelivr.net` only under `/npm/`.
RELEASE_HOSTS: Final = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "registry.npmjs.org",
        "registry.npmmirror.com",
        "nodejs.org",
        "cdn.jsdelivr.net",
    }
)

#: What a hit of these capabilities says about the file is not "it installs a binary", and none
#: of them is part of downloading and verifying one. A credential read, a persistence location,
#: a decode, host fingerprinting, a sleep or a wallet beside the download keeps the dropper.
DISQUALIFYING_CAPABILITIES: Final = frozenset(
    {
        Capability.CREDENTIAL,
        Capability.RECONNAISSANCE,
        Capability.PERSIST,
        Capability.DECODE,
        Capability.DYNAMIC_DISPATCH,
        Capability.ANTI_ANALYSIS,
        Capability.DELAY,
        Capability.WALLET,
        Capability.DESERIALIZE,
    }
)

#: A download piped into its interpreter, or written and started in one command line: nothing can
#: be verified between the two. Kept in step with `CapabilityDetector.DOWNLOAD_RUN_CONSTRUCTS`.
UNVERIFIABLE_RUNS: Final = frozenset(
    {
        "CAP.JS.COMMAND_FETCH_RUN.001",
        "CAP.BAT.FETCH_EXEC.001",
        "CAP.SH.FETCH_EXEC.001",
        "CAP.INVISIBLE_SMUGGLING.001",
    }
)


class VerifiedDownload:
    """Whether a file's downloads are pinned releases checked against a shipped digest."""

    MAX_CHARS: ClassVar[int] = 256 << 10
    """Install scripts are a few hundred lines. A bundle is not one, and its structure cannot be
    read this way."""

    LANGUAGES: ClassVar[frozenset[str]] = frozenset({"javascript", "typescript", "python"})

    # -- (a) every fetch URL is a literal release URL -------------------------------------------

    URL: ClassVar[re.Pattern[str]] = re.compile(
        r"https?://(?P<host>[^\s\"'`/\\?#]{0,253})(?P<path>[^\s\"'`\\]{0,600})"
    )
    HOSTNAME: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}"
    )
    PLACEHOLDER_HOST: ClassVar[re.Pattern[str]] = re.compile(r"[a-z][a-z-]{0,62}")
    """A dotless name in help text -- `http://your-proxy:port`, `https://your-corp-mirror/` in
    larksuite's error message. Nothing on the internet answers to it. `localhost` is not one."""
    RAW_IP: ClassVar[re.Pattern[str]] = re.compile(
        r"\d{1,3}(?:\.\d{1,3}){3}|\[|0x[0-9a-f]{1,8}$|\d{1,10}$"
    )
    BARE_SCHEME: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:startsWith|endsWith|includes|indexOf|startswith|endswith|===|!==|==|!=)[ \t]{0,4}\(?"
        r"[ \t]{0,4}[\"'`]https?://[\"'`]"
    )
    """`registry.startsWith("https://")`: a test of a scheme, not a URL."""
    GITHUB_REPOSITORY_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"/(?P<owner>[\w.-]{1,100})/(?P<repo>[\w.-]{1,100})"
    )
    """The `/<owner>/<repo>` before `/releases/download/<tag>/`, once its constants are
    substituted. `/releases/latest/download/` is not a pinned release and never reaches here."""
    JS_CONSTANT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:const|let|var)[ \t]{1,4}([A-Za-z_$][\w$]{0,60})[ \t]{0,4}=[ \t]{0,4}"
        r"[\"'`]([^\"'`$\n{}\\]{0,200})[\"'`]"
    )
    PY_CONSTANT: ClassVar[re.Pattern[str]] = re.compile(
        r"^[ \t]{0,8}([A-Za-z_]\w{0,60})[ \t]{0,4}=[ \t]{0,4}[\"']([^\"'\n{}\\]{0,200})[\"']",
        re.MULTILINE,
    )
    PLACEHOLDER: ClassVar[re.Pattern[str]] = re.compile(
        r"\$\{([A-Za-z_$][\w$]{0,60})\}|\{([A-Za-z_]\w{0,60})\}"
    )

    ENV_READ: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:process\.env|\benv)(?:\.|\[[ \t]{0,4}[\"'])([A-Za-z_][A-Za-z0-9_]{0,80})"
        r"|os\.environ(?:\.get)?[ \t]{0,4}[\[(][ \t]{0,4}[\"']([A-Za-z_][A-Za-z0-9_]{0,80})"
        r"|os\.getenv[ \t]{0,4}\([ \t]{0,4}[\"']([A-Za-z_][A-Za-z0-9_]{0,80})"
    )
    URLISH_NAME: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)url|host|mirror|registry|endpoint|server|base|download|cdn|origin|source"
    )
    CONSUMER_SETTINGS: ClassVar[frozenset[str]] = frozenset(
        {"npm_config_registry", "https_proxy", "http_proxy", "no_proxy", "all_proxy"}
    )
    """Settings of whoever runs the install, not of the package: npm's own registry (the mirror
    larksuite tries for a corporate proxy) and the proxy variables, which route a request without
    choosing its destination. The package's author cannot point either anywhere."""

    DECODED: ClassVar[re.Pattern[str]] = re.compile(
        r"\batob[ \t]{0,4}\(|fromCharCode|Buffer\.from[ \t]{0,4}\([^)]{0,200}[\"'](?:base64|hex)[\"']"
        r"|b64decode|b32decode|a85decode|bytes\.fromhex|unhexlify|codecs\.decode"
        r"|\.reverse[ \t]{0,4}\([ \t]{0,4}\)[ \t]{0,4}\.join|(?:\\x[0-9a-fA-F]{2}){4}|(?:\\u[0-9a-fA-F]{4}){4}"
    )
    """A URL assembled by decoding is the one thing this never accepts, with or without a DECODE
    hit: the host a reader sees is then not the host that is fetched."""

    FROM_RESPONSE: ClassVar[re.Pattern[str]] = re.compile(
        r"\.(?:browser_download_url|download_url|tarball|href|redirect_url|assets)\b"
        r"|\[[ \t]{0,4}[\"'](?:browser_download_url|download_url|tarball|url)[\"'][ \t]{0,4}\]"
    )
    """A download URL read out of a response (a release API listing, registry metadata) is chosen
    by whoever serves the response. Following `headers.location` is not this: a redirect is how
    `github.com/.../releases/download` serves an asset, and `curl --location` does the same."""
    PARSES_JSON: ClassVar[re.Pattern[str]] = re.compile(
        r"JSON\.parse|\.json[ \t]{0,4}\(|json\.loads?\("
    )

    OTHER_EGRESS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)method[\"']?[ \t]{0,4}[:=][ \t]{0,4}[\"'](?:post|put|patch|delete)[\"']"
        r"|\b(?:requests|httpx|axios|got|session)\.(?:post|put|patch)[ \t]{0,4}\("
        r"|[\"'](?:--data[\w-]{0,12}|--upload-file|--form|-[dFT]|-X[ \t]{0,2}POST)[\"' ]"
        r"|\bnet\.(?:connect|createConnection|Socket)\b|\bdgram\.|\btls\.connect\b"
        r"|\bdns\.(?:lookup|resolve\w{0,8})\b|\bWebSocket\b|socket\.socket\b|\bsmtplib\b|\bftplib\b"
    )
    """Egress that is not fetching a file: a body sent, a socket opened, a name resolved."""

    # -- (b) a digest compared with a reference the package ships, before anything runs ---------

    JS_HASH: ClassVar[re.Pattern[str]] = re.compile(
        r"createHash[ \t]{0,4}\([ \t]{0,4}[\"'](?:sha256|sha384|sha512|sha3-256|sha3-512|blake2b512)[\"']"
    )
    PY_HASH: ClassVar[re.Pattern[str]] = re.compile(
        r"hashlib\.(?:sha256|sha384|sha512|sha3_256|sha3_512|blake2b)[ \t]{0,4}\("
        r"|hashlib\.(?:new|file_digest)[ \t]{0,4}\([^)]{0,120}[\"'](?:sha256|sha384|sha512|sha3_256|sha3_512|blake2b)[\"']"
    )
    """SHA-2, SHA-3 and BLAKE2 only. MD5 and SHA-1 have chosen-prefix collisions, so a match
    with either says less than the condition needs."""
    DIGEST: ClassVar[re.Pattern[str]] = re.compile(
        r"\.(?:hex)?digest[ \t]{0,4}\(|file_digest[ \t]{0,4}\("
    )
    COMPARISON: ClassVar[re.Pattern[str]] = re.compile(
        r"!==|===|!=|==|\.equals[ \t]{0,4}\(|timingSafeEqual[ \t]{0,4}\(|compare_digest[ \t]{0,4}\("
    )
    REFUSAL: ClassVar[re.Pattern[str]] = re.compile(
        r"\bthrow\b|\breject[ \t]{0,4}\(|process\.exit[ \t]{0,4}\(|\braise\b|sys\.exit[ \t]{0,4}\("
        r"|\bexit[ \t]{0,4}\(|\breturn[ \t]{1,4}(?:false|False)\b"
    )
    """A digest computed and compared and then ignored verifies nothing: a mismatch must stop."""

    DIGEST_LITERAL: ClassVar[re.Pattern[str]] = re.compile(
        r"[\"'`](?:[0-9a-fA-F]{64}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128}"
        r"|sha(?:256|384|512)-[A-Za-z0-9+/]{43,88}={0,2})[\"'`]"
    )
    DIGEST_FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"[\"'`]([\w.@-]{0,80}(?i:checksum|sha\d{0,3}sum|shasum|digest|hashes|integrity)[\w.@-]{0,40}"
        r"|[\w.@-]{1,120}\.(?i:sha256|sha512|sha256sum|sha512sum))[\"'`]"
    )
    READS_A_FILE: ClassVar[re.Pattern[str]] = re.compile(
        r"readFileSync|readFile|createReadStream|\brequire[ \t]{0,4}\(|\bopen[ \t]{0,4}\("
        r"|read_text|read_bytes|\bjoin[ \t]{0,4}\("
    )
    NETWORK_DIGEST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(?:https?://|\$\{|\+[ \t]{0,4}[\"'`]|\{\w{1,60}\})[^\"'`\s]{0,300}"
        r"(?:checksum|sha\d{0,3}sum|shasum|digest|hashes|integrity)"
        r"|(?:\}|[\"'`])\.sha(?:256|512)(?:sum)?\b"
    )
    """A digest fetched from where the binary is fetched from vouches for nothing the host did not
    also choose: `pumperly-mcp` and `restflow-cli` download `checksums.txt` beside the asset."""

    CHMOD: ClassVar[re.Pattern[str]] = re.compile(
        r"chmodSync[ \t]{0,4}\(|\bchmod[ \t]{0,4}\(|[\"'`]chmod[\"'`]|\bchmod[ \t]{1,4}[+0-7]"
    )
    RUN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:execFileSync|execFile|execSync|exec|spawnSync|spawn|fork|execa|eval)[ \t]{0,4}\("
        r"|\bnew[ \t]{1,4}Function[ \t]{0,4}\(|\brequire[ \t]{0,4}\([ \t]{0,4}(?![\"'`])"
        r"|subprocess\.\w{1,20}[ \t]{0,4}\(|os\.(?:system|popen|exec\w{0,4}|spawn\w{0,4})[ \t]{0,4}\("
    )
    DOWNLOAD_TOOL: ClassVar[re.Pattern[str]] = re.compile(
        r"[ \t]{0,4}\(?[ \t]{0,4}\[?[ \t]{0,4}[\"'`](?:curl|wget)\b"
    )
    """The download itself, when it is a spawn of curl or wget: it runs before the check by
    definition, and what it runs is the fetch, which (a) has already constrained."""

    JS_FUNCTION: ClassVar[re.Pattern[str]] = re.compile(
        r"\bfunction\b[ \t]{0,4}\*?[ \t]{0,4}([A-Za-z_$][\w$]{0,60})[ \t]{0,4}\([^)]{0,400}\)[^{;]{0,100}\{"
        r"|\b(?:const|let|var)[ \t]{1,4}([A-Za-z_$][\w$]{0,60})[ \t]{0,4}=[ \t]{0,4}(?:async[ \t]{1,4})?"
        r"(?:function\b[^{;]{0,300}|\([^)]{0,300}\)[ \t]{0,4}=>[ \t]{0,4}|[A-Za-z_$][\w$]{0,40}[ \t]{0,4}=>[ \t]{0,4})\{"
    )
    CALL: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]{0,60})[ \t]{0,4}\(")

    @classmethod
    def verified(
        cls,
        text: str,
        language: str | None,
        path: str,
        hits: Sequence[CapabilityHit],
        tree_paths: frozenset[str],
        declared_repository: str | None,
    ) -> bool:
        """Whether every condition holds. `hits` are the whole file's, not one window's."""
        if language not in cls.LANGUAGES or len(text) > cls.MAX_CHARS:
            return False
        if any(
            hit.capability in DISQUALIFYING_CAPABILITIES
            or hit.rule_id in UNVERIFIABLE_RUNS
            or hit.rule_id.startswith("INTEL.")
            for hit in hits
        ):
            return False
        code = cls._code(text, language)
        if (
            cls._destination_named(code)
            or cls.DECODED.search(code)
            or cls.OTHER_EGRESS.search(code)
        ):
            return False
        if cls.PARSES_JSON.search(code) and cls.FROM_RESPONSE.search(code):
            return False
        if not cls._downloads_only_releases(code, language, declared_repository):
            return False
        return cls._digest_checked_first(code, language, path, tree_paths)

    @classmethod
    def own_release(
        cls,
        text: str,
        language: str | None,
        hits: Sequence[CapabilityHit],
        declared_repository: str | None,
    ) -> bool:
        """Every condition of `verified` but the digest, and a release of the package's own
        GitHub repository among the downloads.

        `opendocswork-mcp`'s postinstall fetches `github.com/<its repo>/releases/download/
        v<its version>/...` and marks it executable -- what esbuild-style binary wrappers do, with
        no checksum. Without the digest the binary is the author's to change, as it is with one;
        what this rules out is the dropper's shape: another host, another repository, a URL
        assembled from the environment, a payload decoded on the way (review 98: no malware in
        the DataDog set fetched its own repository's release; the worm copies fetch
        TruffleHog's).
        """
        if not declared_repository or language not in cls.LANGUAGES or len(text) > cls.MAX_CHARS:
            return False
        if any(
            hit.capability in DISQUALIFYING_CAPABILITIES
            or hit.rule_id in UNVERIFIABLE_RUNS
            or hit.rule_id.startswith("INTEL.")
            for hit in hits
        ):
            return False
        code = cls._code(text, language)
        if (
            cls._destination_named(code)
            or cls.DECODED.search(code)
            or cls.OTHER_EGRESS.search(code)
        ):
            return False
        if cls.PARSES_JSON.search(code) and cls.FROM_RESPONSE.search(code):
            return False
        return "github.com" in code and cls._downloads_only_releases(
            code, language, declared_repository
        )

    # -- source -----------------------------------------------------------------------------------

    @staticmethod
    def _code(text: str, language: str) -> str:
        """`text` with every comment blanked, offsets kept: a URL in a comment is not fetched."""
        chars = list(text)
        if language in BLOCK_COMMENT_LANGUAGES:
            for start, end in SourceComments.block_comment_spans(text, language):
                for index in range(start, end):
                    if chars[index] != "\n":
                        chars[index] = " "
        offset = 0
        for line in text.split("\n"):
            column = SourceComments.comment_column(line, language)
            if column is not None:
                for index in range(offset + column, offset + len(line)):
                    chars[index] = " "
            offset += len(line) + 1
        return "".join(chars)

    @staticmethod
    def _destination_named(code: str) -> bool:
        raw = code.encode("utf-8", "replace")
        return Destinations.could_match(raw) and bool(
            Destinations.destination_matcher().search(raw)
        )

    # -- (a) and (c) ------------------------------------------------------------------------------

    @classmethod
    def _downloads_only_releases(
        cls, code: str, language: str, declared_repository: str | None
    ) -> bool:
        constants = cls._constants(code, language)
        declared = cls.github_repository(declared_repository) if declared_repository else None
        releases = 0
        for found in cls.URL.finditer(code):
            host = found.group("host").lower()
            if not host:
                # `"https://"` on its own: a scheme test is fine, the start of a concatenation is not.
                if cls.BARE_SCHEME.search(code, max(0, found.start() - 40), found.end() + 1):
                    continue
                return False
            if ":" in host:
                host = host.split(":", 1)[0]
            if cls.RAW_IP.match(host) or Destinations.is_interaction_host(host):
                return False
            if cls.PLACEHOLDER_HOST.fullmatch(host) and host != "localhost":
                continue
            if not cls.HOSTNAME.fullmatch(host) or host not in RELEASE_HOSTS:
                # Not a release host, or one assembled from a variable (`https://${host}/...`).
                return False
            if not cls._release_url(host, found.group("path"), constants, declared):
                return False
            releases += 1
        if not releases:
            return False
        for found in cls.ENV_READ.finditer(code):
            name = next(group for group in found.groups() if group)
            if name.lower() not in cls.CONSUMER_SETTINGS and cls.URLISH_NAME.search(name):
                # A download base the environment can change is not a URL written in the file.
                return False
        return True

    @classmethod
    def _release_url(
        cls, host: str, path: str, constants: dict[str, str], declared: str | None
    ) -> bool:
        if host == "cdn.jsdelivr.net":
            return path.startswith("/npm/")
        if host != "github.com":
            return True
        # Only what names the repository has to resolve; the tag and the asset name after
        # `/releases/download/` are the version and the platform, which is what varies.
        repository, marker, asset = path.partition("/releases/download/")
        if not marker or not asset.strip("/"):
            return False
        resolved = cls.PLACEHOLDER.sub(
            lambda m: constants.get(m.group(1) or m.group(2), "\0"), repository
        )
        release = cls.GITHUB_REPOSITORY_PATH.fullmatch(resolved)
        if release is None:
            return False
        owner, repo = release.group("owner"), release.group("repo")
        # (c): the release must be the package's own. When the manifest's repository is not known
        # the condition cannot be shown to hold, and it is not assumed.
        return declared is not None and f"{owner}/{repo.removesuffix('.git')}".lower() == declared

    @classmethod
    def _constants(cls, code: str, language: str) -> dict[str, str]:
        """String constants assigned once in the file. A name assigned two values is neither."""
        pattern = cls.PY_CONSTANT if language == "python" else cls.JS_CONSTANT
        values: dict[str, str] = {}
        ambiguous: set[str] = set()
        for found in pattern.finditer(code):
            name, value = found.group(1), found.group(2)
            if values.get(name, value) != value:
                ambiguous.add(name)
            values[name] = value
        return {name: value for name, value in values.items() if name not in ambiguous}

    GITHUB_REPOSITORY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(?:github\.com[:/]|^github:|^)([\w.-]{1,100})/([\w.-]{1,100})"
    )

    @classmethod
    def github_repository(cls, declared: str) -> str | None:
        """`owner/repo` from a `package.json` `repository` value, in any of npm's spellings."""
        value = declared.strip()
        value = value.removeprefix("git+").removesuffix("/")
        if "://" in value and "github.com" not in value.lower():
            return None
        found = cls.GITHUB_REPOSITORY.search(value)
        if found is None:
            return None
        return f"{found.group(1)}/{found.group(2).removesuffix('.git')}".lower()

    # -- (b) --------------------------------------------------------------------------------------

    @classmethod
    def _digest_checked_first(
        cls, code: str, language: str, path: str, tree_paths: frozenset[str]
    ) -> bool:
        if cls.NETWORK_DIGEST.search(code):
            return False
        if not (
            cls.DIGEST_LITERAL.search(code) or cls._reads_a_shipped_digest(code, path, tree_paths)
        ):
            return False
        frames = cls._python_frames(code) if language == "python" else cls._js_frames(code)
        if frames is None:
            return False
        calls = cls._calls(code, frames)
        hash_call = cls.PY_HASH if language == "python" else cls.JS_HASH
        checks = [
            digest.start()
            for start in (found.start() for found in hash_call.finditer(code))
            if (digest := cls.DIGEST.search(code, start, start + 2000)) is not None
            and cls._refuses_a_mismatch(code, digest.start(), frames)
        ]
        runs = [found.start() for found in cls.CHMOD.finditer(code)] + [
            found.start()
            for found in cls.RUN.finditer(code)
            if not cls.DOWNLOAD_TOOL.match(code, found.end() - 1)
        ]
        if not checks or not runs:
            return False
        # The first check has to come before every chmod and every run, in the frame they share.
        first = min(checks)
        return all(cls._before(first, run, frames, calls) for run in runs)

    @classmethod
    def _reads_a_shipped_digest(cls, code: str, path: str, tree_paths: frozenset[str]) -> bool:
        """A digest file named in the code, read from disk, and present in the package."""
        archive = path.rpartition("!")[0]
        prefix = f"{archive}!" if archive else ""
        names = {
            posixpath.basename(p.rpartition("!")[2])
            for p in tree_paths
            if p.startswith(prefix) and "!" not in p[len(prefix) :]
        }
        for found in cls.DIGEST_FILE.finditer(code):
            if posixpath.basename(found.group(1)) not in names:
                continue
            if cls.READS_A_FILE.search(code, max(0, found.start() - 200), found.end() + 200):
                return True
        return False

    @classmethod
    def _refuses_a_mismatch(cls, code: str, at: int, frames: list[tuple[int, int, str]]) -> bool:
        start, end = cls._region(at, frames)
        return bool(cls.COMPARISON.search(code, start, end)) and bool(
            cls.REFUSAL.search(code, start, end)
        )

    @staticmethod
    def _region(at: int, frames: list[tuple[int, int, str]]) -> tuple[int, int]:
        """The innermost function around `at`, or 1,500 characters either side at top level."""
        inner = [(s, e) for s, e, _ in frames if s <= at < e]
        if inner:
            return max(inner)
        return max(0, at - 1500), at + 1500

    # -- ordering ---------------------------------------------------------------------------------

    @classmethod
    def _js_frames(cls, code: str) -> list[tuple[int, int, str]] | None:
        pairs = cls._brace_pairs(code)
        frames = []
        for found in cls.JS_FUNCTION.finditer(code):
            opener = found.end() - 1
            close = pairs.get(opener)
            if close is None:
                return None
            frames.append((found.start(), close + 1, found.group(1) or found.group(2)))
        return frames

    @staticmethod
    def _brace_pairs(code: str) -> dict[int, int]:
        """Each `{` and its `}`, skipping string and template literals. One pass."""
        pairs: dict[int, int] = {}
        stack: list[int] = []
        index, length = 0, len(code)
        while index < length:
            char = code[index]
            if char in "\"'`":
                index += 1
                while index < length and code[index] != char:
                    if code[index] == "\\":
                        index += 1
                    elif code[index] == "\n" and char != "`":
                        break
                    index += 1
            elif char == "{":
                stack.append(index)
            elif char == "}" and stack:
                pairs[stack.pop()] = index
            index += 1
        return pairs

    @staticmethod
    def _python_frames(code: str) -> list[tuple[int, int, str]] | None:
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError, RecursionError):
            return None
        starts = [0]
        for line in code.split("\n"):
            starts.append(starts[-1] + len(line) + 1)
        frames = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.end_lineno:
                start = starts[node.lineno - 1] + node.col_offset
                end = starts[node.end_lineno - 1] + (node.end_col_offset or 0)
                frames.append((start, end, node.name))
        return frames

    @classmethod
    def _calls(cls, code: str, frames: list[tuple[int, int, str]]) -> dict[str, list[int]]:
        """Where each function is called from, outside its own body."""
        spans = {name: (start, end) for start, end, name in frames}
        heads = {start for start, _, _ in frames}
        calls: dict[str, list[int]] = {}
        for found in cls.CALL.finditer(code):
            name = found.group(1)
            span = spans.get(name)
            if span is None or span[0] <= found.start() < span[1]:
                continue
            if found.start() in heads or code[
                max(0, found.start() - 9) : found.start()
            ].rstrip().endswith("function"):
                continue
            calls.setdefault(name, []).append(found.start())
        return calls

    @classmethod
    def _chain(
        cls, at: int, frames: list[tuple[int, int, str]], calls: dict[str, list[int]]
    ) -> list[tuple[tuple[int, int] | None, int]]:
        """`(frame, position in it)` from the innermost function out to the top level, following
        each function to its first call. A function nobody calls ends the chain where it is."""
        chain: list[tuple[tuple[int, int] | None, int]] = []
        for _ in range(12):
            inner = [(s, e, n) for s, e, n in frames if s <= at < e]
            if not inner:
                chain.append((None, at))
                return chain
            start, end, name = max(inner)
            chain.append(((start, end), at))
            sites = calls.get(name)
            if not sites:
                return chain
            at = sites[0]
        return chain

    @classmethod
    def _before(
        cls,
        check: int,
        run: int,
        frames: list[tuple[int, int, str]],
        calls: dict[str, list[int]],
    ) -> bool:
        """Whether `check` happens before `run`: compared where their call chains first meet."""
        checks = cls._chain(check, frames, calls)
        runs = cls._chain(run, frames, calls)
        run_frames = {frame: index for index, (frame, _) in enumerate(runs)}
        for index, (frame, position) in enumerate(checks):
            if frame not in run_frames:
                continue
            other = runs[run_frames[frame]][1]
            if position != other:
                return position < other
            # One call reaches both: the order is inside it, one frame down.
            below_check = checks[index - 1] if index else None
            below_run = runs[run_frames[frame] - 1] if run_frames[frame] else None
            if below_check and below_run and below_check[0] == below_run[0]:
                return below_check[1] < below_run[1]
            return False
        return False


__all__ = ["RELEASE_HOSTS", "VerifiedDownload"]
