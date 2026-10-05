"""The vulnerable functions an advisory's own text names, for ecosystems whose sources list none.

The Go vulnerability database lists vulnerable symbols for nearly every record; the PyPI and npm
sources essentially never do (measured: none of 247 records sampled across twelve popular
packages carried `affected_functions`). Their prose usually does -- "`yaml.load()` deserialises
arbitrary objects", "the `merge`, `mergeWith` and `defaultsDeep` functions" -- and that is what
this reads, at database build time, from the summary and details.

A name taken from prose can be incomplete: an advisory mentions the function its reporter found,
not every function that reaches the flaw. So these symbols carry a `text:` prefix and the
reachability tier uses them in one direction only -- to say first-party code calls a function
the advisory names, and to put that finding first. They never lower a finding: "calls none of
the functions this paragraph mentions" is not evidence the vulnerable code is unreachable.
"""

from __future__ import annotations

import re
from typing import Final

PREFIX: Final = "text:"
MAX_TEXT: Final = 20_000
MAX_SYMBOLS: Final = 20

_CODE_SPAN = re.compile(r"`([^`\n]{1,120})`")
# Bounded: advisory text comes from an external source, and nested unbounded repetition
# over it is a backtracking hazard the pattern validator refuses.
_CALL = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]{0,80}(?:\.[A-Za-z_$][\w$]{0,80}){1,8})[ \t]{0,4}\("
)
_LEADING = re.compile(r"^[A-Za-z_$][\w$]{0,80}(?:\.[A-Za-z_$][\w$]{0,80}){0,8}")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`])|\n\s*\n")
_ADVICE = re.compile(
    r"\b(?:instead|use|using\s+the\s+safe|is\s+safe|are\s+safe|safe\s+alternative|recommend\w*|workaround|mitigat\w*|upgrade|patched|fixed\s+in)\b",
    re.I,
)
_LIST_GLUE = re.compile(r"`[^`]{0,60}`|,|\b(?:and|or)\b|\s")
_NOT_NAMES: Final = frozenset(
    {"true", "false", "null", "none", "undefined", "this", "self", "new", "return", "import",
     "require", "async", "await", "function", "class", "object", "string", "number", "args", "kwargs"}
)  # fmt: skip


class AdvisoryTextSymbols:
    """`text:`-prefixed vulnerable function names read from an advisory's prose."""

    @staticmethod
    def import_names(ecosystem: str, package: str) -> tuple[str, list[str]]:
        """The canonical import name for a package, and every head a reference to it may use."""
        lowered = package.lower()
        if ecosystem == "npm":
            heads = [package]
            if lowered in ("lodash", "lodash-es", "underscore"):
                heads.append("_")
            return package, heads
        from cordon_scanner.detect.reachability import _IMPORT_ALIASES

        normalized = lowered.replace("_", "-")
        aliases = list(_IMPORT_ALIASES.get(normalized, ()))
        canonical = aliases[0] if aliases else normalized.replace("-", "_")
        return canonical, list(dict.fromkeys([canonical, *aliases, normalized.replace("-", "_")]))

    @classmethod
    def extract(cls, ecosystem: str, package: str, text: str) -> tuple[str, ...]:
        if ecosystem not in ("pypi", "npm") or not text:
            return ()
        canonical, heads = cls.import_names(ecosystem, package)
        found: list[str] = []

        def add(dotted: str) -> None:
            head, _, rest = dotted.partition(".")
            if head in heads and rest:
                found.append(f"{PREFIX}{canonical}.{rest}")

        for sentence in _SENTENCE.split(text[:MAX_TEXT]):
            # Advice names the fix, not the flaw: "use `yaml.safe_load` instead". Positive-only
            # use means a fix taken for the flaw would tell people the safe call is the bad one.
            if _ADVICE.search(sentence):
                continue
            for span in _CODE_SPAN.finditer(sentence):
                inner = span.group(1).strip()
                leading = _LEADING.match(inner)
                if leading is None:
                    continue
                name = leading.group(0)
                if "." in name:
                    add(name)
                elif (
                    len(name) >= 3
                    and not name.isupper()
                    and name.lower() not in _NOT_NAMES
                    and name not in heads
                    and (
                        inner.startswith(f"{name}(") or cls._named_as_function(sentence, span.end())
                    )
                ):
                    found.append(f"{PREFIX}{canonical}.{name}")
            for call in _CALL.finditer(sentence):
                add(call.group(1))
        return tuple(dict.fromkeys(found))[:MAX_SYMBOLS]

    @staticmethod
    def _named_as_function(sentence: str, end: int) -> bool:
        """Whether the words right after a code span call it a function: "`merge` function", or the
        end of a list -- "`merge`, `mergeWith`, and `defaultsDeep` functions". Anywhere else in the
        sentence is not enough: "the `backend` option ... calls" names a setting, not a function."""
        tail = _LIST_GLUE.sub("", sentence[end : end + 120]).lower()
        return tail.startswith(("function", "method"))

    @staticmethod
    def is_text(symbols: tuple[str, ...] | list[str]) -> bool:
        return bool(symbols) and all(s.startswith(PREFIX) for s in symbols)

    @staticmethod
    def matches(used: str, named: str) -> bool:
        """Whether a first-party reference is the function an advisory names.

        Exact after normalising npm subpath imports (`lodash/merge` is `lodash.merge`). A prefix is
        not a match: constructing `jinja2.Environment` is not calling `Environment.from_string`.
        """
        return used.replace("/", ".") == named.removeprefix(PREFIX)
