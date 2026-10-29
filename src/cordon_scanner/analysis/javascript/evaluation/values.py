"""What a JavaScript evaluation works with: its limits, the values it can produce (a string with
holes, a byte buffer, a small function, the unknown), and the tokens it reads."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

MAX_STEPS: Final = 40_000
MAX_STRING: Final = 20_000
#: Template literals nested inside `${}` deeper than this are read as code (see `tokens`).
MAX_TEMPLATE_DEPTH: Final = 16
MAX_REGEX: Final = 2_000
MAX_DEPTH: Final = 60
MAX_TEXT: Final = 600_000
#: What a decoded value has to be to count as something hidden: a module that reaches the system or
#: the network, a URL or host, a shell command, code. Bundles decode ordinary strings constantly.
#: Searched for whether it occurs: a host is tried only from the start of its run of `[a-z0-9-]`,
#: which finds one exactly when a start inside the run would, without re-reading the run from each
#: of its characters (that was quadratic on a long run of letters or dashes).
_HIDDEN_SIGNIFICANT: Final = re.compile(
    r"^(?:child_process|os|dns|net|https?|fs|vm|crypto|process|util|tls|dgram|worker_threads)$"
    r"|https?://|\b(?:curl|wget|powershell|cmd(?:\.exe)?|bash|sh -c|chmod|nc|certutil|rundll32)\b"
    r"|\brequire\s*\(|\beval\s*\(|\b(?:exec|spawn|execSync|userInfo|hostname|homedir|lookup|resolve4)\b"
    r"|\.(?:exe|dll|ps1|bat|sh|vbs)\b"
    r"|(?<![a-z0-9-])[a-z0-9-]+\.(?:com|net|org|io|xyz|top|ru|cn|site|online|me)\b"
)
#: A loop that builds a string one `String.fromCharCode` at a time over an array: the decoder a
#: small local function is (`JsEval.BUILTIN_DECODER_LOOP`).
BUILTIN_DECODER_LOOP: Final = re.compile(
    r"for\s*\([^)]{0,80}\)\s*\{?\s*[\w$]+\s*\+=\s*String\s*\.\s*fromCharCode\s*\(\s*([\w$]+)\s*\[\s*[\w$]+\s*\]\s*\)"
)
HOLE: Final = "_"
"""How an unknown piece of a string is written in the view."""


class Unknown:
    """A value the evaluator cannot know."""

    __slots__ = ()


UNKNOWN: Final = Unknown()


@dataclass
class Holey:
    """A string with unknown pieces: known text, holes written as `HOLE`."""

    text: str


@dataclass
class Buf:
    data: bytes


@dataclass
class Fn:
    params: list[str]
    body: list[Any]  # tokens of a single expression
    kind: str = "expr"  # "expr" or "charcodes" (a loop of fromCharCode over its argument)
    prelude: list[tuple[str, list[Any]]] = field(default_factory=list)
    """`const name = <tokens>;` statements evaluated, in order, before the returned expression."""


@dataclass
class Tok:
    kind: str  # str longstr num name punct tmpl regex
    value: Any
    start: int
    end: int
