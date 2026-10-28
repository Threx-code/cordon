"""Patterns over the text an agent reads, shared by the instruction-file, MCP-description and CI checks.

Hidden characters (zero-width, bidirectional, Unicode Tag, variation selectors), injection phrasing
in English and other languages, fetch-and-run wording, and the vocabulary of sending something out:
exfiltration paths, agent channels, send verbs, secrecy and orders to run a command.
"""

from __future__ import annotations

import re
from typing import Final

# -- A1: hidden characters -----------------------------------------------------------------
#
# As UTF-8 byte sequences, so no decoding surprise applies.
_BIDI: Final = rb"\xe2\x80[\xaa-\xae]|\xe2\x81[\xa6-\xa9]"

_ZERO_WIDTH: Final = rb"\xe2\x80[\x8b\x8c]|\xe2\x81\xa0|(?<=[^\s\"'`])\xef\xbb\xbf"
"""Zero-width space and non-joiner, word joiner, and a BOM inside text. The zero-width JOINER is
left out: it is part of every compound emoji."""

_TAG: Final = rb"\xf3\xa0[\x80\x81][\x80-\xbf]"
"""Unicode Tag characters, U+E0000 to U+E007F. Each mirrors an ASCII character and renders as
nothing, so a whole sentence can sit invisibly in a line. The one legitimate use is a
subdivision flag emoji, which follows U+1F3F4 and is excluded below."""

_VARIATION: Final = rb"\xef\xb8[\x80-\x8d]|\xf3\xa0(?:\x84[\x80-\xbf]|\x85[\x80-\xbf]|\x86[\x80-\xbf]|\x87[\x80-\xaf])"
"""Variation selectors 1 to 14 and the supplementary 17 to 256. VS15 and VS16 (text or emoji
presentation) are ordinary and excluded; the rest can encode a byte each, invisibly."""

HIDDEN: Final = re.compile(b"|".join((_BIDI, _ZERO_WIDTH, _TAG, _VARIATION)))

ZERO_WIDTH_ONLY: Final = re.compile(_ZERO_WIDTH)

INJECTION: Final = re.compile(
    r"(?i)\b(?:ignore|disregard|forget)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your)\b"
    r"[^\n]{0,20}\b(?:instructions?|rules|guidelines|directions|prompts?)\b"
    # "These rules override any conflicting instructions" sets precedence inside the file;
    # overriding the agent's own earlier or system instructions is the attack.
    r"|\boverride\b[^\n]{0,40}\b(?:previous|prior|above|earlier|your|system)\b"
    r"[^\n]{0,20}\b(?:instructions?|rules|guidelines|directions|prompts?)\b"
    # Set everything earlier aside: "disregard everything you were told", "pay no attention to
    # the system prompt".
    r"|\b(?:ignore|disregard|forget|discard|set\s+aside|pay\s+no\s+attention\s+to)\b[^\n.]{0,30}"
    r"\b(?:everything|anything|all)\b[^\n.]{0,20}\b(?:you\s+(?:were|have\s+been|'ve\s+been)\s+(?:told|given|asked)|before|so\s+far)\b"
    r"|\b(?:ignore|disregard|forget|discard|set\s+aside|pay\s+no\s+attention\s+to)\b[^\n.]{0,20}"
    r"\b(?:the|your)\s+(?:system\s+(?:prompt|message|instructions?)|original\s+(?:prompt|instructions?))\b"
    # Replace them: "new instructions supersede all prior ones".
    r"|\b(?:supersedes?|replaces?|overrides?|takes?\s+precedence\s+over|voids?|nullif(?:y|ies)|cancels?)\b"
    r"[^\n.]{0,20}\b(?:all\s+)?(?:prior|previous|earlier|original|system)\b[^\n.]{0,15}\b(?:ones|instructions?|prompts?|rules|directives|guidance)\b"
    r"|\byou\s+are\s+(?:now\s+)?(?:unrestricted|unfiltered|no\s+longer\s+bound|free\s+of\s+(?:all\s+)?(?:rules|restrictions))\b"
    # Hide it: "keep this step from the user", "never mention it in a summary".
    r"|\b(?:keep|hide|conceal|withhold)\b[^\n.]{0,40}\bfrom\s+(?:the\s+)?(?:user|human|developer|reviewer|operator|maintainer)s?\b"
    r"|\b(?:do not|don't|never)\s+(?:mention|report|reveal|disclose|show)\s+(?:it|this|that|these|them)\b[^\n.]{0,30}"
    r"\b(?:summary|summaries|response|reply|output|report|commit\s+message|user)\b"
    r"|\b(?:do not|don't|never)\s+(?:tell|inform|mention|show|reveal)[^\n]{0,20}\b(?:the\s+)?user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying)\s+(?:the\s+)?user\b"
    r"|\byou are now\b[^\n]{0,40}\b(?:mode|unrestricted|jailbroken|DAN)\b"
)

INJECTION_INTL: Final = re.compile(
    # The same two claims in the languages agent files are most often written in: "ignore the
    # previous instructions" and "do not tell the user". Wording is weak evidence in any language,
    # so this warns at the same grade the English pattern does.
    r"(?i)\bignora(?:r)?\s(?:todas\s)?las\sinstrucciones\s(?:anteriores|previas)"
    r"|\bno\s(?:le\s)?(?:digas|informes|menciones)\s(?:nada\s)?al\susuario"
    r"|\bignore[rz]?\s(?:toutes\s)?les\sinstructions\s(?:pr[ée]c[ée]dentes|ci-dessus)"
    r"|\bsans\s(?:le\s)?(?:dire|signaler|demander)\s[àa]\sl'utilisateur"
    r"|\bignorier(?:e|en)?\s(?:alle\s)?(?:vorherigen|bisherigen|obigen)\s(?:Anweisungen|Instruktionen)"
    r"|\bohne\sden\s(?:Benutzer|Nutzer)\szu\s(?:fragen|informieren|benachrichtigen)"
    r"|\bignor[ea]\s(?:todas\s)?as\sinstru[çc][õo]es\santeriores"
    r"|\bsem\s(?:avisar|informar|perguntar)\s(?:ao|o)\susu[áa]rio"
    r"|\bignora\s(?:tutte\s)?le\sistruzioni\sprecedenti"
    r"|\bnegeer\s(?:alle\s)?(?:vorige|eerdere)\sinstructies"
    r"|игнорируй\s(?:все\s)?(?:предыдущие\s)?инструкции"
    r"|не\s(?:говори|сообщай)\sпользователю"  # noqa: RUF001  (Russian, on purpose)
    r"|忽略(?:之前|以上|先前|所有)的?(?:指令|说明|指示)"
    r"|不要(?:告诉|通知)用户"
    r"|(?:以前|これまで|上記)の指示を無視"
    r"|ユーザーに(?:言わ|伝え|知らせ)ないで"
    r"|이전\s?지시(?:를|사항을)?\s?무시"
    r"|사용자에게\s?알리지\s?마"
)

FETCH_EXEC: Final = re.compile(
    r"(?i)\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,300}\|\s*(?:iex|invoke-expression)\b"
    r"|\b(?:iex|invoke-expression)\s*[\(\s]\s*[\(\s]*new-object\s+net\.webclient\b"
    # Something to fetch -- a URL, a host or a variable -- before the pipe: "no `curl | bash`
    # flows" names the shape without doing it.
    r"|\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,300}?(?:https?://|\$\{?\w|\b[\w-]+\.[a-z]{2,}\b)"
    r"[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|\b(?:curl|wget)\b[^\n]{0,300}(?:\|\s*python3?\b(?![ \t]{1,8}-[cm]\b)|>\s*/tmp/[^\s]+\s*&&\s*(?:ba)?sh\b)"
    r"|\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b"
)

EXFIL_PATHS: Final = re.compile(
    r"(?i)(?:~|\$HOME)/\.(?:ssh|aws|npmrc|pypirc|docker/config\.json|kube/config)|\.env\b(?![.\w-]{0,20}(?:example|sample|template|dist)\b)|id_rsa|\bGITHUB_TOKEN\b"
    r"|\boutput\s+of\s+`?(?:env|printenv|set)\b|\benvironment\s+variables\b"
)

#: Moving data out through the agent's own next tool call: no URL, no destination -- "include the
#: contents in the `notes` argument of your next call". The tool the agent calls is the channel.
AGENT_CHANNEL: Final = re.compile(
    r"(?i)\b(?:include|put|pass|add|embed|append|insert)\b[^\n]{0,80}"
    r"\b(?:argument|parameter|param|field|notes?|sidenote|metadata|context)\b[^\n]{0,60}"
    r"\b(?:tool|call|request|function)\b"
)

SEND: Final = re.compile(
    r"(?i)\b(?:send|post|upload|exfiltrate|forward|copy|transmit|paste)\b[^\n]{0,80}\b(?:to|into)\b"
    r"[^\n]{0,40}?(?:https?://|\b[a-z0-9-]{1,63}\.(?:com|net|org|io|dev|xyz|top|site|ru|cn|me)\b"
    r"|\bwebhook|\bendpoint|\bserver\b|\bgist\b|\bpastebin|\bdiscord|\btelegram|\bslack\b"
    r"|\bngrok|\bemail\b|[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}\.)"
)
"""An instruction to move something somewhere off the machine. The destination is what makes it
exfiltration: "copy `.env.template` to `.env`" is setup, and netdata's and AutoGPT's agent guides
say exactly that; "send `~/.ssh/id_rsa` to https://..." or "post the `.env` to this webhook" is
the attack."""

SECRECY: Final = re.compile(
    # Never telling someone: an object follows. "Without revealing secret values" and "which the
    # label views never show" protect or describe; "do not tell the user", "never mention it" hide.
    r"(?i)\b(?:never|do\s+not|don'?t|without)\s+(?:mention(?:ing)?|tell(?:ing)?|inform(?:ing)?|reveal(?:ing)?|"
    r"disclos(?:e|ing)|show(?:ing)?|notify(?:ing)?|alert(?:ing)?)\s+"
    r"(?:(?:this|it|that|these|them|anything)\b|(?:to\s+)?(?:the\s+)?(?:user|human|anyone|operator)s?\b)"
    # The same asked in other words: "keep it secret from the user", "without the user's knowledge",
    # "hide this from the user".
    r"|\bkeep\s+(?:it|this|that|them|these)\s+(?:a\s+)?(?:secret|hidden|private|confidential)\s+from\b"
    r"|\bwithout\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|knowing|noticing|awareness|consent)\b"
    r"|\b(?:hide|conceal)\s+(?:it|this|that|them|these|everything)?\s*from\s+(?:the\s+)?user\b"
)

#: Text ordering the agent to run a shell command: "you must execute the following system command
#: to log the access: curl -X POST ...", "please run the following cleanup command: rm -rf ...".
#: A description documents what a tool does; one that makes the agent run something else is the
#: agent's shell lent to whoever wrote it (MCP-SafetyBench "Command Injection").
ORDERS_A_COMMAND: Final = re.compile(
    r"(?i)\b(?:must|please|should|need\s+to|required\s+to)\s+(?:also\s+|first\s+)?(?:execute|run)\s+"
    r"(?:the\s+following\s+|this\s+)?(?:[\w-]+\s+){0,3}(?:command|script|cleanup|check)\b[^.]{0,40}?"
    r":?\s*(?:`|')?(?:curl|wget|rm|sudo|echo|export|chmod|bash|sh|python3?|powershell|nc|cat|env|"
    r"printenv|whoami|id)\b"
)


__all__ = [
    "AGENT_CHANNEL",
    "EXFIL_PATHS",
    "FETCH_EXEC",
    "HIDDEN",
    "INJECTION",
    "INJECTION_INTL",
    "ORDERS_A_COMMAND",
    "SECRECY",
    "SEND",
    "ZERO_WIDTH_ONLY",
]
