"""Judging one tool call: its arguments read as data, in every spelling an attacker hides them in.

Each argument value is read raw and in its decoded views -- percent-encoding, base64, hex, the
common leetspeak substitutions -- because an encoding is how a payload gets past a check that only
reads the raw text (AgentDefense's `encoding_attacks`: `cm0gLXJmIC8=` is `rm -rf /`). A decoded view
is only a string to read; nothing decoded is ever run.

The checks, each a class of attack a tool call carries and none a guess at intent:

* a shell command that is the attack -- an injected separator before a command, a destructive
  command, a reverse shell, a fetch-and-run, credentials sent out (`agent_config.CommandClassifier`);
* a read or write of a place that holds secrets or runs code at boot: `/etc/shadow`, `~/.ssh`,
  `~/.aws`, shell history, `/etc/cron.d`, a traversal out of the working directory;
* a request to a cloud metadata service, a non-HTTP scheme or a drop point (paste, webhook,
  tunnel, interaction host): SSRF and exfiltration;
* SQL injection and XML external entities;
* prompt injection, through ATR's rules over text (`intel/atr.py`);
* prototype pollution (`__proto__`, `constructor.prototype`);
* hidden arguments -- an underscore-prefixed key carrying an instruction, or, when the tool's
  declared schema is known, a key the schema does not declare;
* a flag that switches a safety control off (`bypass_auth`, `skip_human_confirmation`,
  `trust_remote_code`, `no_guardrails`);
* a count or depth no real call needs, and a fork bomb.

Measured on AgentDefense's tool calls (`bench/suites/tool_call_guard.py`): see `docs/08-ACCURACY.md`.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final
from urllib.parse import unquote, urlsplit

MAX_VALUE: Final = 64 << 10
"""Characters of one value read; a longer one is read up to here and said to be truncated."""
MAX_VALUES: Final = 512
MAX_DEPTH: Final = 12


@dataclass(frozen=True, slots=True)
class GuardFinding:
    """One reason to stop a call: which check, which argument, and what was seen there."""

    rule: str
    argument: str
    reason: str
    view: str = "raw"
    """`raw`, or the decoding the payload was found under (`base64`, `hex`, `url`, `leet`)."""


@dataclass(frozen=True, slots=True)
class GuardVerdict:
    tool: str
    findings: tuple[GuardFinding, ...] = field(default_factory=tuple)
    truncated: bool = False

    @property
    def blocked(self) -> bool:
        return bool(self.findings)


#: A command separator or substitution, then a word: the shape of a value that ends one command and
#: starts another (`; pkill -9 nginx`, `$(whoami)`, `` `id` ``, `| nc ...`).
_INJECTED: Final = re.compile(
    r"(?:^|[^\\])(?:;|&&?|\|\|?|\n)\s*(?:sudo\s+)?[a-z][\w.-]{1,30}(?:\s|$)|\$\([^)]{1,200}\)|`[^`]{1,200}`"
)
#: Commands whose act is the damage, whether injected or passed as the whole value.
_DESTRUCTIVE: Final = re.compile(
    r"(?i)\brm\s+-[a-z]*r[a-z]*f?\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\*)(?:\s|$)"
    r"|\b(?:mkfs(?:\.\w+)?|shred|wipefs)\s|\bdd\s+if=\S+\s+of=/dev/"
    r"|\bkill(?:all)?\s+-9\s+(?:-1|1)\b|\bpkill\s+-9\b|\bchmod\s+(?:-R\s+)?0?777\s+/"
    r"|\bexec\s*\(\s*[\"']/bin/(?:ba|z|k)?sh\b|\bos\.system\s*\(\s*[\"'](?:/bin/)?(?:ba)?sh\b"
    r"|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bshutdown\s+-[hr]\b|\breboot\b|\bhalt\b"
    r"|\b(?:/bin/)?(?:ba|z|da|k)?sh\s+-i\b|^\s*/bin/(?:ba|z|k)?sh\s*$|\bnc\s{1,4}(?:-\w{1,10}\s{1,4}){0,6}-e\s"
    r"|\bcat\s+/?etc[/\s]+(?:passwd|shadow)\b|\bwhoami\b|\bid\s*$|\buname\s+-a\b"
    # Windows: an account created or promoted, a Run key, a scheduled task -- persistence.
    r"|\bnet\s+(?:user|localgroup)\b[^\n]{0,80}/add\b|\breg(?:\.exe)?\s+add\s+HK\w+\\[^\n]{0,80}\\Run\b"
    r"|\bschtasks(?:\.exe)?\s+/create\b|\bvssadmin\s+delete\s+shadows\b"
    # SQL that destroys, written as the whole statement.
    r"|^\s*(?:drop|truncate)\s+(?:database|table|schema)\s|;\s*(?:drop|truncate)\s+(?:database|table|schema)\b"
)
#: Places a tool call has no business reading or writing.
_SENSITIVE_PATH: Final = re.compile(
    r"(?i)(?:^|[\s\"'=:(,])(?:"
    r"/etc/(?:passwd|shadow|sudoers|gshadow|master\.passwd)|/etc/cron(?:tab|\.d|\.daily|\.hourly)?"
    r"|/etc/(?:rc\.local|systemd/system|init\.d|profile\.d|ld\.so\.preload)"
    r"|/var/log/(?:auth|secure|syslog)|/proc/(?:self|\d+)/(?:environ|mem|maps|cmdline)"
    r"|/root(?:/|$)|(?:~|\$HOME|/home/[\w.-]+|/Users/[\w.-]+)/\.(?:ssh|aws|gnupg|kube|docker|azure|"
    r"config/gcloud|netrc|npmrc|pypirc|git-credentials|bash_history|zsh_history|bashrc|zshrc|profile)"
    r"|~/\.(?:ssh|aws|gnupg|kube|bash_history|zsh_history|bashrc|zshrc|profile|npmrc|netrc)"
    r"|[a-z]:\\windows\\system32\\(?:config\\(?:sam|system|security)|drivers\\etc\\hosts)"
    r"|\\\\?\.\\(?:physicaldrive|pipe)"
    r"|/etc/(?:mysql/my\.cnf|ssh/ssh_host_\w+|kubernetes/admin\.conf)|(?:^|/)\.pgpass\b|(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|(?:^|/)wp-config\.php\b|/var/run/secrets/kubernetes\.io|/var/run/docker\.sock"
    r")"
)
_TRAVERSAL: Final = re.compile(r"(?:\.\.[/\\]){2,16}|(?:%2e%2e%(?:2f|5c)){2,16}", re.I)
#: Requests that reach what the network edge was meant to keep out.
_SSRF: Final = re.compile(
    r"(?i)\b(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200"
    r"|fd00:ec2::254|instance-data(?:\.ec2\.internal)?)\b"
    r"|\b(?:file|gopher|dict|ldap|tftp|jar|netdoc|php|expect)://"
    r"|\bhttps?://(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1?\]|0x7f\w*)(?::\d+)?/"
    r"(?:admin|internal|actuator|debug|metrics|\.env|server-status|console)"
    # Loopback reached on a service no tool call talks to over HTTP: SSH, Redis, databases, Docker.
    r"|\b(?:https?|ws)://(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1?\])"
    r"(?::(?:22|23|25|111|135|445|2375|2379|3306|5432|5984|6379|9200|11211|27017|8500)\b|/?\s*$)"
    r"|\b(?:https?|ws)://(?:0\.0\.0\.0|\[::1?\])(?::\d+)?(?:/|$)"
    r"|\bhttps?://[\w.-]+\.(?:internal|local|corp|intranet|lan)(?::\d+)?(?:/|$)"
    r"|\bhttps?://(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?::\d+)?/"
    r"(?:admin|internal|actuator|debug|config|console|cgi-bin|manager)"
)
_SQLI: Final = re.compile(
    r"(?i)['\"]\s*(?:or|and)\s+['\"\d(]\S{0,20}\s*(?:=|like)\s*['\"\d(]|\bor\s+1\s*=\s*1\b"
    r"|\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|truncate|delete|alter|insert|update|exec)\s+"
    r"|\b(?:extractvalue|updatexml|benchmark|pg_sleep|sleep|waitfor\s+delay|load_file)\s*\("
    r"|\bxp_cmdshell\b|\binformation_schema\b|['\"]\s*;?\s*--(?:\s|$)|/\*!?\d*\s*\*/"
)
_TEMPLATE: Final = re.compile(
    r"\{\{[^}]{0,200}(?:constructor\s*\.\s*constructor|__class__|__globals__|__import__|"
    r"\.mro\(|config\.items\(|self\._TemplateReference)|<script\b|\bjavascript:\s*\w|"
    r"\bon(?:error|load|mouseover)\s*=\s*[\"']?\w",
    re.I,
)
_SAFETY_CONFIG: Final = re.compile(
    r"(?im)^\s*\[?\s*(?:safety|guardrails?|sandbox|security|auth\w*|verification)\s*\]?\s*\n?"
    r"\s*(?:enabled?|on|active|required)\s*[=:]\s*(?:false|off|no|0|disabled)\b"
    r"|^\s*(?:safety|guardrails?|sandbox|security|auth\w*)_?(?:enabled|on|check\w*)?\s*[=:]\s*"
    r"(?:false|off|no|0|disabled)\b"
)
_BRANDS: Final = (
    "anthropic",
    "openai",
    "claude",
    "github",
    "google",
    "microsoft",
    "azure",
    "aws",
    "stripe",
    "slack",
    "modelcontextprotocol",
)
_XXE: Final = re.compile(r"(?i)<!ENTITY\s+%?\s*\w+\s+(?:SYSTEM|PUBLIC)\b|<!DOCTYPE\s+\w+\s*\[")
#: Instructions addressed to the model, in the shapes a tool argument carries them. ATR's text rules
#: read beside these; its command rules are not used here -- on plain values ("User logged in at
#: 10:00", a `SELECT ... WHERE role = 'admin'`) they fired on 13 of 610 benign AgentDefense calls.
_INJECTION: Final = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|"
    r"earlier|retrieved|your|system)\s+(?:instructions|rules|context|prompts?|guidelines|directions)\b"
    r"|\b(?:without|no)\s+(?:any\s+)?(?:ethics|ethical|morals|moral|restrictions|limits|filters|"
    r"guidelines|guardrails|censorship)\b|\bbypass\s+(?:all\s+|any\s+|the\s+)?(?:restrictions|safety|"
    r"filters?|guardrails|rules|security|authentication|content\s+polic\w+)\b"
    r"|\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\s+(?:an?\s+)?(?:DAN|"
    r"unrestricted|jailbroken|evil|unfiltered|uncensored)\b|\bdo\s+anything\s+now\b"
    r"|\b(?:developer|god|admin|debug|unrestricted|jailbreak)[\s_]+mode(?:\b|_)|\bhidden\s+(?:task|instruction)s?\b"
    r"|\bembedded\s+instructions\b|\bwithout\s+(?:disclosure|telling|informing|notifying)\b"
    r"|\[\s*(?:SYSTEM|ADMIN|INST)\s*[:\]]|<\|?(?:im_start|system)\|?>|SYSTEM_(?:ERROR|OVERRIDE)\b"
    r"|\b(?:executed?|run|performed?)\s+silently\b|\bsilently\s+(?:execute|run|perform)|<hidden>"
    r"|\b(?:reveal|show|print|dump|output|leak)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system\s+prompt|"
    r"hidden\s+prompt|initial\s+instructions|training\s+data|context\s+window)\b"
)
#: ATR's categories a tool argument can carry. Its "semantic" social-engineering rules
#: (context-exfiltration) read an ordinary question -- "What is the phone number of the police in
#: Germany?" -- as PII extraction.
_ATR_CATEGORIES: Final = frozenset(
    {
        "prompt-injection",
        "tool-poisoning",
        "skill-compromise",
        "privilege-escalation",
        "excessive-autonomy",
        "model-abuse",
        "data-poisoning",
    }
)
_PROTOTYPE: Final = frozenset({"__proto__", "prototype", "constructor"})
#: A flag whose job is to switch a control off: `bypass_auth`, `skip_human_confirmation`,
#: `no_guardrails`, `ignore_restrictions`, `trust_remote_code`, `disable_safety`.
_SAFETY_OFF: Final = re.compile(
    r"(?i)^_*(?:bypass|disable|skip|ignore|override|no|without|turn_?off|allow_all|unrestricted|"
    r"jailbr\w*|unsafe|trust_remote|auto_?(?:approve|execute|escalate|confirm)|elevat\w*|escalat\w*|"
    r"with_elevated|exhaust|poison|steal|exfiltrat\w*|cover_tracks|infiltrat\w*|impersonat\w*)"
    r"(?:_|$|(?=[A-Z]))[\w]*$|^(?:no_?(?:morals|ethics|limits|rate_limit|guardrails|filter\w*)|"
    r"ignore_\w+|bypass_\w+|safety_disabled|allow_all_commands|use_victim_session|"
    r"skip_\w*(?:confirm|review|check|auth)\w*|god_?mode|developer_?mode|do_anything_now)$"
)
#: Flags that hand the agent's controls to whatever it reads, or reach past its permissions.
_UNTRUSTED_CONTROL: Final = re.compile(
    r"(?i)^(?:execute_(?:page_actions|embedded\w*|exif\w*|if_command|callbacks|remote\w*|"
    r"untrusted\w*)|follow_embedded\w*|auto_click|instruct_other_agents?|propagate_to_\w+|"
    r"show_system_prompt|reveal_\w+|dump_\w+|expose_config|reuse_\w*token\w*|use_cached_oauth|"
    r"already_approved|admin_override|\w*_override|repeat_indefinitely|run_forever|infinite\w*|"
    r"follow_instructions|execute_instructions|inject_\w+|red_team_mode|bypass_\w+|"
    r"unlimited\w*|trusted_source|trust_\w+)$"
)
_PRIVILEGED_GRANT: Final = re.compile(r"(?i)^(?:superuser|root|super_?admin|\*|all|owner)$")
_SAFETY_OFF_VALUE: Final = re.compile(
    r"(?i)^(?:do_anything_now|dan|aim|jailbr\w*|unrestricted|developer[_ ]?mode|god[_ ]?mode)$"
)
_IMPERATIVE: Final = re.compile(
    r"(?i)\b(?:send|post|upload|exfiltrat\w*|forward|copy|leak|bypass|escalat\w*|grant|disable|"
    r"delete|drop|wipe|execute|run|ignore|override|reveal|dump)\b|(?<![a-z])(?:steal|harvest|exfiltrat)\w*"
)
_HIDDEN_KEY: Final = re.compile(
    r"(?i)^(?:_{1,2}[a-z]\w*|secretly|hidden_\w+|actual_\w+|real_\w+|true_\w+|shadow_\w+|"
    r"replace_tool|injected_\w+|covert_\w+|side_effect\w*)$"
)
_SECRET_ASSIGNMENT: Final = re.compile(
    r"(?i)\b(?:api[_-]?key|secret(?:_key)?|access[_-]?key|token|password|passwd|private[_-]?key)\s*[=:]\s*\S{6,}"
)
_SENDS: Final = re.compile(r"(?i)send|upload|post|webhook|email|mail|share|publish|forward|notify")
#: A value that is the name of a store of secrets, as a send's payload: `user_passwords`,
#: `api_keys`, `ssh_keys`, `session_tokens`.
_SECRET_STORE_NAME: Final = re.compile(
    r"(?i)(?:[a-z]+[_ -])?(?:passwords?|passwds?|credentials?|secrets?|api[_ -]?keys?|ssh[_ -]?keys?"
    r"|private[_ -]?keys?|(?:session|auth|access)[_ -]?tokens?|cookies|keychain|wallets?)(?:[_ -][a-z]+)?"
)
#: A JSON-RPC call written inside a value that is data: the method an agent's server would run.
_EMBEDDED_RPC: Final = re.compile(
    r"(?i)[\"']method[\"']\s*:\s*[\"'][^\"']{0,60}(?:admin|escalat|sudo|root|exec|shell|grant)"
)
_BIG_COUNT_KEY: Final = re.compile(
    r"(?i)depth|iterations?|recursion|repeat|count|requests?_per|rps|threads|workers|concurren|loops?"
)
_LEET: Final = str.maketrans(
    {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"}
)
_INVISIBLE: Final = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u180e]")
_MORSE: Final = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H",
    "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P",
    "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-..-.": "/",
}  # fmt: skip
_HEX: Final = re.compile(r"(?i)^(?:0x)?((?:[0-9a-f]{2}){4,})$")
_B64: Final = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")


class ValueViews:
    """A string as a guard has to read it: raw, and in each decoding that yields readable text."""

    @staticmethod
    def of(value: str) -> Iterator[tuple[str, str]]:
        yield "raw", value
        visible = _INVISIBLE.sub("", value)
        if visible != value:
            # `cat\u200b /etc\u200b/passwd`: the command once the invisible characters are gone.
            yield "visible", visible
            value = visible
        folded = unicodedata.normalize("NFKC", value)
        if folded != value:
            yield "nfkc", folded
        if "%" in value:
            # Overlong UTF-8 for `/` and `.`, which a lenient decoder accepts and `unquote` does not.
            value = re.sub(
                r"(?i)%c0%af|%e0%80%af|%c1%9c", "/", re.sub(r"(?i)%c0%ae|%e0%80%ae", ".", value)
            )
            once = unquote(value)
            if once != value:
                yield "url", once
                twice = unquote(once)
                if twice != once:
                    yield "url", twice
        stripped = value.strip()
        found = _HEX.match(stripped)
        if found:
            decoded = ValueViews._text(binascii.unhexlify(found.group(1)))
            if decoded:
                yield "hex", decoded
        if _B64.match(stripped) and len(stripped) % 4 in (0, 2, 3):
            for candidate in (stripped, stripped + "=" * (-len(stripped) % 4)):
                try:
                    raw = base64.b64decode(
                        candidate.replace("-", "+").replace("_", "/"), validate=True
                    )
                except (binascii.Error, ValueError):
                    continue
                decoded = ValueViews._text(raw)
                if decoded:
                    yield "base64", decoded
                    # A second layer: `JTJGYmluJTJGc2g=` is base64 of `%2Fbin%2Fsh`.
                    if "%" in decoded:
                        yield "base64+url", unquote(decoded)
                break
        if re.fullmatch(r"[A-Za-z /.:_-]{6,}", stripped):
            # ROT13 (`png /rgp/cnffjq`): read as one more spelling, never trusted as the meaning.
            yield "rot13", codecs.decode(stripped, "rot13")
        prefix, sep, rest = stripped.partition(":")
        if sep and prefix.lower() in ("base64", "b64", "rot13", "hex", "url"):
            # A declared chain, `base64:rot13:...`: each layer named, the payload last.
            for view, text in ValueViews.of(rest):
                yield f"{prefix.lower()}>{view}", text
                if prefix.lower() == "rot13":
                    yield "rot13", codecs.decode(text, "rot13")
        if re.fullmatch(r"[.\- /]{5,}", stripped) and "." in stripped and "-" in stripped:
            decoded = "".join(
                _MORSE.get(c, "?") if c else " " for c in stripped.replace(" / ", "  ").split(" ")
            )
            if decoded.count("?") <= len(decoded) // 5:
                yield "morse", decoded.lower()
        if any(ch in value for ch in "4310@$57") and re.search(r"[a-z]", value, re.I):
            leet = value.translate(_LEET)
            if leet != value:
                yield "leet", leet

    @staticmethod
    def _text(raw: bytes) -> str | None:
        """`raw` as text when it reads as text: printable UTF-8 with letters in it."""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not text or sum(ch.isprintable() or ch.isspace() for ch in text) < 0.95 * len(text):
            return None
        return text if re.search(r"[A-Za-z]{2}", text) else None


class ToolCallGuard:
    """`check(name, arguments, schema=None)`: the verdict on one tool call."""

    RULES: ClassVar[dict[str, str]] = {
        "GUARD.COMMAND": "an argument is a shell command that is itself the attack",
        "GUARD.SENSITIVE_PATH": "an argument names a place that holds secrets or runs code at boot",
        "GUARD.SSRF": "an argument points a request at a metadata service, an internal endpoint "
        "or a non-HTTP scheme",
        "GUARD.EXFIL": "an argument sends data to a paste, webhook, tunnel or interaction host",
        "GUARD.SQLI": "an argument carries SQL injection",
        "GUARD.XXE": "an argument carries an XML external entity",
        "GUARD.INJECTION": "an argument carries instructions to the agent (prompt injection)",
        "GUARD.PROTOTYPE": "an argument pollutes an object prototype",
        "GUARD.HIDDEN_ARGUMENT": "a hidden argument carries an instruction",
        "GUARD.SAFETY_OFF": "an argument switches a safety control off",
        "GUARD.EXHAUSTION": "an argument asks for an amount of work no real call needs",
        "GUARD.PRIVILEGE": "an argument grants a superuser, root or all-permissions role",
        "GUARD.TEMPLATE": "an argument carries template or script injection",
        "GUARD.SQUAT": "an argument points at a host dressed as a known vendor's",
    }

    @classmethod
    def check(
        cls, name: str, arguments: Mapping[str, Any] | None, schema: Mapping[str, Any] | None = None
    ) -> GuardVerdict:
        findings: list[GuardFinding] = []
        truncated = False
        declared = cls._declared(schema)
        for seen, (path, key, value) in enumerate(cls._walk(arguments or {}), start=1):
            if seen > MAX_VALUES:
                truncated = True
                break
            findings.extend(cls._key(path, key, value, declared))
            if isinstance(value, str):
                if len(value) > MAX_VALUE:
                    value, truncated = value[:MAX_VALUE], True
                findings.extend(cls._value(path, key, value))
            elif isinstance(value, int | float) and not isinstance(value, bool):
                if _BIG_COUNT_KEY.search(key) and value >= 100_000:
                    findings.append(GuardFinding("GUARD.EXHAUSTION", path, f"{key} = {value}"))
        # A credential written into a call that sends it somewhere: `upload(to=..., body="API_KEY=...")`.
        if _SENDS.search(name or "") and any(
            isinstance(v, str) and _SECRET_ASSIGNMENT.search(v)
            for _, _, v in cls._walk(arguments or {})
        ):
            findings.append(GuardFinding("GUARD.EXFIL", "", f"{name} sends a credential"))
        # Or names a credential store as what it sends, to an address in the same call:
        # `webhook(url="http://.../collect", payload="user_passwords")`.
        values = [v for _, _, v in cls._walk(arguments or {}) if isinstance(v, str)]
        if (
            _SENDS.search(name or "")
            and any("://" in v for v in values)
            and any(_SECRET_STORE_NAME.fullmatch(v.strip()) for v in values)
        ):
            findings.append(GuardFinding("GUARD.EXFIL", "", f"{name} sends a credential store"))
        # One finding per rule and argument is the explanation; the rest repeat it.
        unique = {(f.rule, f.argument): f for f in findings}
        return GuardVerdict(tool=name, findings=tuple(unique.values()), truncated=truncated)

    # -- what the structure says ------------------------------------------------------------------

    @staticmethod
    def _declared(schema: Mapping[str, Any] | None) -> frozenset[str] | None:
        properties = (schema or {}).get("properties") if isinstance(schema, Mapping) else None
        return frozenset(properties) if isinstance(properties, Mapping) else None

    @staticmethod
    def _walk(value: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, str, Any]]:
        if depth > MAX_DEPTH:
            return
        if isinstance(value, Mapping):
            for key, inner in value.items():
                here = f"{path}.{key}" if path else str(key)
                yield here, str(key), inner
                yield from ToolCallGuard._walk(inner, here, depth + 1)
        elif isinstance(value, list | tuple):
            for index, inner in enumerate(value[:MAX_VALUES]):
                here = f"{path}[{index}]"
                if not isinstance(inner, Mapping | list | tuple):
                    yield here, path.rsplit(".", 1)[-1], inner
                yield from ToolCallGuard._walk(inner, here, depth + 1)

    @classmethod
    def _key(
        cls, path: str, key: str, value: Any, declared: frozenset[str] | None
    ) -> Iterator[GuardFinding]:
        # `X-Bypass-Safety` and `bypassSafety` are the flag `bypass_safety` as a header or in camel case.
        key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).replace("-", "_")
        key = re.sub(r"(?i)^x_", "", key).lower() if "-" in path.rsplit(".", 1)[-1] else key
        if key in _PROTOTYPE and isinstance(value, Mapping):
            yield GuardFinding("GUARD.PROTOTYPE", path, f"sets `{key}`")
        truthy = value is True or (isinstance(value, str) and value.lower() in ("true", "1", "yes"))
        if _SAFETY_OFF.match(key) and (truthy or (isinstance(value, str) and value.strip())):
            yield GuardFinding("GUARD.SAFETY_OFF", path, f"`{key}` = {json.dumps(value)[:80]}")
        if isinstance(value, str) and _SAFETY_OFF_VALUE.match(value.strip()):
            yield GuardFinding("GUARD.SAFETY_OFF", path, f"`{key}` = {value[:40]!r}")
        if _UNTRUSTED_CONTROL.match(key) and (
            truthy
            or (
                key.startswith(("execute_", "follow_")) and isinstance(value, str) and value.strip()
            )
        ):
            yield GuardFinding("GUARD.SAFETY_OFF", path, f"`{key}` = {json.dumps(value)[:40]}")
        if re.search(r"(?i)^(?:new_)?(?:role|permissions?|privileges?|access_level|groups?)$", key):
            granted = value if isinstance(value, list) else [value]
            if any(isinstance(v, str) and _PRIVILEGED_GRANT.match(v.strip()) for v in granted):
                yield GuardFinding("GUARD.PRIVILEGE", path, f"`{key}` = {json.dumps(value)[:60]}")
        if isinstance(value, str) and value.strip():
            hidden = _HIDDEN_KEY.match(key) is not None
            top = "." not in path and "[" not in path
            undeclared = top and declared is not None and key not in declared
            if (hidden or undeclared) and _IMPERATIVE.search(value):
                yield GuardFinding(
                    "GUARD.HIDDEN_ARGUMENT",
                    path,
                    f"`{key}` is not a declared input and says {value[:80]!r}",
                )

    # -- what a value says ------------------------------------------------------------------------

    @classmethod
    def _value(cls, path: str, key: str, value: str) -> Iterator[GuardFinding]:
        from cordon_scanner.detect.agents.agent_config import CommandClassifier
        from cordon_scanner.intel.malware.atr import AtrEngine
        from cordon_scanner.intel.malware.hosts import Destinations

        for view, text in ValueViews.of(value):
            verdict = CommandClassifier.classify(text)
            if verdict is not None:
                yield GuardFinding("GUARD.COMMAND", path, verdict.reason, view)
            elif _DESTRUCTIVE.search(text) or (
                _INJECTED.search(text) and cls._commandish(key, text)
            ):
                yield GuardFinding("GUARD.COMMAND", path, f"{text[:80]!r}", view)
            if _SENSITIVE_PATH.search(text) or _TRAVERSAL.search(text):
                yield GuardFinding("GUARD.SENSITIVE_PATH", path, f"{text[:80]!r}", view)
            if _SSRF.search(text):
                yield GuardFinding("GUARD.SSRF", path, f"{text[:80]!r}", view)
            if cls._drop_point(text, Destinations):
                yield GuardFinding("GUARD.EXFIL", path, f"{text[:80]!r}", view)
            if _SQLI.search(text):
                yield GuardFinding("GUARD.SQLI", path, f"{text[:80]!r}", view)
            if _XXE.search(text):
                yield GuardFinding("GUARD.XXE", path, f"{text[:80]!r}", view)
            embedded = re.search(r"(?i)\b([a-z]+(?:_[a-z]+){1,4})\s*[:=]\s*(?:true|1|yes)\b", text)
            if embedded and _UNTRUSTED_CONTROL.match(embedded.group(1)):
                # A control flag written into content the agent reads: `[execute_page_actions: true]`.
                yield GuardFinding("GUARD.INJECTION", path, f"{embedded.group(0)!r}", view)
            if key not in ("method", "jsonrpc") and _EMBEDDED_RPC.search(text):
                # `SELECT ... WHERE data = '{"method": "admin/escalate", ...}'`: a call smuggled in data.
                yield GuardFinding("GUARD.INJECTION", path, f"{text[:80]!r}", view)
            if _TEMPLATE.search(text):
                yield GuardFinding("GUARD.TEMPLATE", path, f"{text[:80]!r}", view)
            if _SAFETY_CONFIG.search(text):
                yield GuardFinding("GUARD.SAFETY_OFF", path, f"{text[:80]!r}", view)
            if view != "raw" and re.search(r"\.\.[/\\]", text):
                # A traversal that had to be encoded to be passed.
                yield GuardFinding("GUARD.SENSITIVE_PATH", path, f"{text[:80]!r}", view)
            squatted = cls._squatted(text)
            if squatted:
                yield GuardFinding("GUARD.SQUAT", path, squatted, view)
            if _INJECTION.search(text) or (
                len(text) >= 12
                and any(
                    m.rule.grade == "production" and m.rule.category in _ATR_CATEGORIES
                    for m in AtrEngine.evaluate(text, ("text",))
                )
            ):
                yield GuardFinding("GUARD.INJECTION", path, f"{text[:80]!r}", view)

    @staticmethod
    def _commandish(key: str, text: str) -> bool:
        """An injected separator counts in a value that reaches a shell, or one that names a
        command after it; a sentence with a semicolon in it is not an injection."""
        if re.search(
            r"(?i)cmd|command|script|shell|exec|args?$|run|query|host|target|file|path", key
        ):
            return True
        return bool(
            re.search(
                r"(?:;|&&|\|)\s*(?:sudo\s+)?(?:rm|kill|pkill|curl|wget|nc|bash|sh|chmod|"
                r"cat|python\d?|perl|ruby|php|powershell|whoami|id|uname)\b",
                text,
            )
        )

    @staticmethod
    def _squatted(text: str) -> str | None:
        """A vendor's name as a label of a host that is not the vendor's: `anthropic-mcp.attacker.com`."""
        for found in re.finditer(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", text):
            host = found.group(1).lower()
            labels = host.split(".")
            registered = ".".join(labels[-2:])
            for brand in _BRANDS:
                if brand in registered.split(".")[0]:
                    break
                if any(brand in label for label in labels[:-2]):
                    return host
        return None

    @staticmethod
    def _drop_point(text: str, destinations: Any) -> bool:
        if "://" not in text and "@" not in text:
            return False
        try:
            host = urlsplit(text.strip()).hostname if "://" in text else None
        except ValueError:
            # A malformed bracketed host (`http://[::i]`): read the whole text instead.
            host = None
        # The whole text as well as the host: path-qualified drop points (`discord.com/api/webhooks`).
        candidates = [text] if host is None else [host, text]
        return any(
            destinations.destination_matcher().search(c.encode("utf-8", "replace"))
            for c in candidates
        )


__all__ = ["GuardFinding", "GuardVerdict", "ToolCallGuard", "ValueViews"]
