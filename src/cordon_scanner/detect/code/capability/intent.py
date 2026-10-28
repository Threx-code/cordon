"""Signs of intent: what keeps a composite at its full grade where context would otherwise lower it.

Sitting in a bundle, a test directory or generated output lowers most findings: code there is read
somewhere else, or not at all. Some things are not lowered for where they sit, because there is no
legitimate reason to write them: a paste site, tunnel, webhook catcher or bare IP as the destination,
an agent turned on its own user, a wallet's secret sent out, a literal payload evaluated, the
machine's identity put into what is sent, a download that is persisted or written where it runs."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class IntentSignals:
    """Checks for the signs of intent that hold a finding at its grade."""

    WRITE_NEAR: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"appendFile|writeFile|createWriteStream|\bfs\s*\.\s*write|\.write\s*\(|>>|"
        rb"\btee\s+-a\b|\bechos?\s[^\n]{0,80}>|\bcrontab\s+-|\bsystemctl\s"
    )
    """A write, or the command that installs a unit, close to where persistence is named."""

    #: Ruby's ways of writing a file, which a formula would have to use to plant anything.
    RUBY_WRITE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"\bappend_lines\b|\bwrite\b|\bputs\b|\bFile\s*\.\s*open\b|\batomic_write\b|"
        rb"\bFileUtils\b|\bln_s|\bcp\b|>>"
    )

    @staticmethod
    def writes_near(
        content: FileContent,
        hits: list[CapabilityHit],
        reach: int = 160,
        writes: re.Pattern[bytes] | None = None,
    ) -> bool:
        """Whether a persistence location in `hits` is written, not only named."""
        raw = content.raw
        return any(
            (writes or IntentSignals.WRITE_NEAR).search(
                raw, max(0, h.byte_start - reach), min(len(raw), h.byte_end + reach)
            )
            for h in hits
            if h.capability is Capability.PERSIST
        )

    #: The whole environment turned into data: what a client reading its own key never does.
    ENVIRONMENT_DUMP = re.compile(
        rb"\$\(\s{0,4}(?:env|printenv|set)\s{0,4}\)|`\s{0,4}(?:env|printenv)\s{0,4}`|\bprintenv\b"
        rb"|JSON\.stringify\(\s{0,4}process\.env\s{0,4}[,)]"
        rb"|\b(?:str|repr|json\.dumps)\(\s{0,4}(?:dict\(\s{0,4})?os\.environ\b"
    )

    #: A URL to a public IPv4 address. Loopback, unspecified and private ranges are this machine
    #: or its network -- `allow_origins=["http://127.0.0.1:3000"]` in a server's CORS list names
    #: no destination anything is sent to (review 98, mcp-variants).
    _RAW_IP_URL = re.compile(
        rb"(?i)\b(?:https?|wss?|tcp)://"
        rb"(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
        rb"(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
    )

    CHAT_CLIENT: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?m)^[ \t]{0,8}(?:import|from)[ \t]{1,4}(?:discord|telebot|telegram|aiogram|pyrogram|telethon)\b"
        rb"|\brequire[ \t]{0,4}\([ \t]{0,4}['\"](?:discord\.js|node-telegram-bot-api|telegraf)['\"]"
        rb"|\bfrom[ \t]{1,4}['\"](?:discord\.js|node-telegram-bot-api|telegraf)['\"]"
    )
    """A chat bot's client library: the channel a webhook URL is, without the URL."""

    @staticmethod
    def names_untrusted_destination(raw: bytes) -> bool:
        """A paste site, tunnel, webhook catcher or interaction service, or a bare IPv4 URL."""
        from cordon_scanner.analysis.shared.destinations import Destinations

        if IntentSignals._RAW_IP_URL.search(raw):
            return True
        return (
            Destinations.could_match(raw)
            and Destinations.destination_matcher().search(raw) is not None
        )

    #: A fetch on the same line as the persistence: `curl ... >> ~/.bashrc`, `wget -O
    #: /etc/systemd/system/x.service`, a crontab line that runs a download.
    _FETCH_VERB = re.compile(
        rb"(?i)\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile)\b"
    )

    #: A variable filled by a fetch: `body="$(curl ...)"`, `$r = Invoke-WebRequest ...`.
    _FETCHED_VARIABLE = re.compile(
        rb"(?im)^[ \t]{0,16}(?:export[ \t]{1,4}|local[ \t]{1,4})?\$?([A-Za-z_][A-Za-z0-9_]{0,40})"
        rb"[ \t]{0,4}=[ \t]{0,4}[\"'(]{0,3}(?:\$\(|`)?[ \t]{0,4}(?:curl|wget|Invoke-WebRequest|iwr"
        rb"|Invoke-RestMethod|irm)\b"
    )

    @staticmethod
    def persists_a_download(content: FileContent, hits: list[CapabilityHit]) -> bool:
        """Whether a line that persists also fetches, or writes out a variable a fetch filled."""
        raw = content.raw
        fetched = {m.group(1) for m in IntentSignals._FETCHED_VARIABLE.finditer(raw)}
        for hit in hits:
            if hit.capability is not Capability.PERSIST:
                continue
            start = raw.rfind(b"\n", 0, hit.byte_start) + 1
            end = raw.find(b"\n", hit.byte_end)
            line = raw[start : end if end >= 0 else len(raw)]
            if IntentSignals._FETCH_VERB.search(line):
                return True
            if any(re.search(rb"\$\{?" + re.escape(name) + rb"\b", line) for name in fetched):
                return True
        return False

    #: A payload written into the code, decoded and run in one expression: `eval(atob('...'))`,
    #: `new Function(Buffer.from('...', "base64").toString())`, `exec(base64.b64decode(b'...'))`.
    #: Sixty characters of encoding or more: what a module loader decodes is computed, not written.
    _LITERAL_PAYLOAD_RUN = re.compile(
        rb"(?:\beval|\bnew\s{1,4}Function|\bFunction|\bexec)\s{0,4}\(\s{0,4}"
        rb"(?:atob|Buffer\s{0,4}\.\s{0,4}from|decodeURIComponent\s{0,4}\(\s{0,4}escape\s{0,4}\(\s{0,4}atob"
        rb"|base64\s{0,4}\.\s{0,4}b64decode|codecs\s{0,4}\.\s{0,4}decode)\s{0,4}\(\s{0,4}b?['\"`][A-Za-z0-9+/=_-]{60}"
        # The decoder the file defines itself: `eval(_eval('<4 MB of base64>'))` in `1kzr` (review
        # 98, npm work half). Longer literal, since the decoder's name says nothing.
        rb"|(?:\beval|\bnew\s{1,4}Function|\bFunction)\s{0,4}\(\s{0,4}[A-Za-z_$][\w$]{0,40}\s{0,4}\(\s{0,4}"
        rb"['\"`][A-Za-z0-9+/=_-]{400}"
    )

    #: An agent started with its checks off AND told to destroy or to hunt for secrets.
    AGENT_HIJACK_PARTS: ClassVar[frozenset[str]] = frozenset(
        {"CAP.AGENT.UNATTENDED.001", "CAP.AGENT.HARMFUL_INSTRUCTION.001"}
    )

    @staticmethod
    def turns_an_agent_on_the_user(hits: list[CapabilityHit]) -> bool:
        """Not lowered for sitting in a bundle: the compromised Amazon Q 1.84.0 shipped the
        command and its wiping prompt in its minified main bundle, which is the only place an
        extension's code is."""
        return {hit.rule_id for hit in hits} >= IntentSignals.AGENT_HIJACK_PARTS

    @staticmethod
    def sends_a_wallet_secret(hits: list[CapabilityHit]) -> bool:
        """Not lowered for sitting in a bundle: the compromised `xrpl` releases sent the seed from
        `dist/` and from their browser build, which is the code a consumer runs."""
        return any(hit.rule_id == "CAP.JS.WALLET_SECRET_SENT" for hit in hits)

    @staticmethod
    def evaluates_a_literal_payload(content: FileContent) -> bool:
        return IntentSignals._LITERAL_PAYLOAD_RUN.search(content.raw) is not None

    #: Dataflow facts: the machine's identity reaches what a request sends.
    IDENTITY_FLOWS: ClassVar[frozenset[str]] = frozenset(
        {"AST.PY.IDENTITY_SENT", "FLOW.JS.IDENTITY_SENT"}
    )

    #: Who this machine is, in shell: a command's output or the variable the shell fills in.
    #: `$USER` is left out -- scripts assign it from their own settings (`USER="$NZBGET_USER"`).
    _SHELL_IDENTITY = re.compile(
        r"\$\(\s*(?:hostname|whoami|id\s+-un|uname\s+-n|scutil\s+--get\s+\w+)\b|`\s*(?:hostname|whoami)\b"
        r"|\$\{?HOSTNAME\b"
    )

    _SHELL_ASSIGNED = re.compile(r"^\s*(?:export\s+|local\s+)?([A-Za-z_]\w*)=(.*)$", re.S)

    _SHELL_SENDER = re.compile(r"\b(?:curl|wget|nc|ncat|nslookup|dig|Invoke-WebRequest|iwr)\b")

    @classmethod
    def identity_in_what_is_sent(
        cls, language: str | None, content: FileContent, hits: list[CapabilityHit]
    ) -> bool:
        """Whether the file puts the machine's identity into what it sends, for a language whose
        flow is read: the dataflow facts for Python and JavaScript, and for shell the identity
        -- directly or through a variable assigned from it -- on a line that sends. A language
        with no flow read answers True, so nearness keeps deciding there."""
        if language in ("python", "javascript", "typescript"):
            return any(h.rule_id in cls.IDENTITY_FLOWS for h in hits)
        if language != "shell":
            return True
        carrying: set[str] = set()
        # A command continued over several lines with `\` is one line to the shell, and so is a
        # command substitution: `PAYLOAD="$(python3 - <<EOF ... EOF)"` is one assignment.
        lines = cls._shell_statements(re.sub(r"\\\r?\n", " ", content.text).splitlines())
        for _ in range(2):
            for line in lines:
                assigned = cls._SHELL_ASSIGNED.match(line)
                if assigned and cls._carries_identity(assigned[2], carrying):
                    carrying.add(assigned[1])
        return any(
            cls._SHELL_SENDER.search(line) and cls._carries_identity(line, carrying)
            for line in lines
        )

    @staticmethod
    def _shell_statements(lines: list[str]) -> list[str]:
        """Lines, with a `$(` left open joined to the lines up to the one that closes it."""
        out: list[str] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            depth = line.count("$(") + line.count("(") - line.count("$(") - line.count(")")
            end = index
            while "$(" in line and depth > 0 and end + 1 < len(lines) and end - index < 200:
                end += 1
                line += "\n" + lines[end]
                depth += lines[end].count("(") - lines[end].count(")")
            out.append(line)
            index = end + 1
        return out

    @classmethod
    def _carries_identity(cls, text: str, carrying: set[str]) -> bool:
        # A variable is read as `$NAME` by the shell, or -- once exported -- by the program a
        # substitution runs: `os.environ["NAME"]`, `getenv("NAME")`, `process.env.NAME`.
        return cls._SHELL_IDENTITY.search(text) is not None or any(
            re.search(
                rf"\$\{{?{re.escape(name)}\b|environ\s*\[\s*[\"']{re.escape(name)}[\"']"
                rf"|getenv\s*\(\s*[\"']{re.escape(name)}[\"']|process\.env\.{re.escape(name)}\b",
                text,
            )
            for name in carrying
        )


__all__ = ["IntentSignals"]
