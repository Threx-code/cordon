"""The adversarial gate: a candidate must keep its catch when the code it caught is rewritten.

An attacker who knows a rule rewrites the same behaviour so the rule no longer sees it. So before a candidate is accepted, each
text it caught is rewritten in memory by four transforms and the candidate is run on the rewrite. Nothing is written out.

    rename     every identifier the text declares gets a new, meaningless name
    reencode   each quoted string is spelled with escape sequences instead of its characters
    split      each quoted string is cut in two and joined again (`"ab"` becomes `"a" + "b"`)
    minify     comments are dropped and runs of blanks are squeezed

A candidate whose catch under any transform falls below `MIN_RETAINED` of what it caught on the original text is rejected, and the
verdict says which transform beat it and by how much. A candidate that caught nothing is rejected too: there is nothing to
mutate, so nothing was shown."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Final

MIN_RETAINED: Final = 0.8
_IDENT = re.compile(r"\b(?:def|class|let|const|var|function)\s+([A-Za-z_][A-Za-z0-9_]*)")
_ASSIGN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", re.MULTILINE)
_STRING = re.compile(r"(\"[^\"\\\n]{2,}\"|'[^'\\\n]{2,}')")
_COMMENT = re.compile(r"(?m)(?:^|\s)(?:#|//)[^\n]*$")


class Mutations:
    @staticmethod
    def rename(text: str) -> str:
        names = list(dict.fromkeys(_IDENT.findall(text) + _ASSIGN.findall(text)))
        for i, name in enumerate(names):
            text = re.sub(rf"\b{re.escape(name)}\b", f"v{i}x", text)
        return text

    @staticmethod
    def reencode(text: str) -> str:
        def spelled(m: re.Match[str]) -> str:
            body = m.group(0)
            return body[0] + "".join(f"\\x{ord(c):02x}" for c in body[1:-1]) + body[-1]

        return _STRING.sub(spelled, text)

    @staticmethod
    def split(text: str) -> str:
        def cut(m: re.Match[str]) -> str:
            body = m.group(0)
            quote, inner = body[0], body[1:-1]
            mid = len(inner) // 2
            return f"{quote}{inner[:mid]}{quote} + {quote}{inner[mid:]}{quote}"

        return _STRING.sub(cut, text)

    @staticmethod
    def minify(text: str) -> str:
        lines = [re.sub(r"[ \t]+", " ", _COMMENT.sub("", line)).strip() for line in text.split("\n")]
        return "\n".join(line for line in lines if line)

    @classmethod
    def all(cls) -> dict[str, Callable[[str], str]]:
        return {"rename": cls.rename, "reencode": cls.reencode, "split": cls.split, "minify": cls.minify}


class AdversarialGate:
    @staticmethod
    def check(
        catch: Callable[[str], bool],
        texts: Iterable[str],
        transforms: Mapping[str, Callable[[str], str]] | None = None,
        minimum: float = MIN_RETAINED,
    ) -> dict[str, Any]:
        """The verdict on a candidate's catch over the texts it is claimed to catch. `catch(text)` is True when it fires."""
        transforms = transforms if transforms is not None else Mutations.all()
        caught = [t for t in texts if catch(t)]
        retained: dict[str, float] = {}
        for name, transform in transforms.items():
            kept = sum(1 for t in caught if catch(transform(t)))
            retained[name] = kept / len(caught) if caught else 0.0
        beaten = sorted(name for name, share in retained.items() if share < minimum)
        reasons = [f"under {name} it keeps {retained[name]:.0%} of its catch, below {minimum:.0%}" for name in beaten]
        if not caught:
            reasons = ["it caught none of the texts, so nothing was shown"]
        return {"accepted": not reasons, "caught": len(caught), "retained": retained, "beaten_by": beaten, "reasons": reasons}
