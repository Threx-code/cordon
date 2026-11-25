"""A position in a file's text becomes a byte span through `FileContent.byte_offset`, never through the encoded length of the text before it.

`text` is decoded past a UTF-8 byte-order mark and `raw` keeps it, so `len(text[:i].encode("utf-8"))` is three bytes short of the position in `raw` in a file that carries
one: the span began three bytes early, and the same file written with a mark reported other evidence (the coverage suite's encoding test found technique findings that folded
for plain files and not for marked ones). This holds the sites that still use the encoded length to the few that are meant to: the helper itself, and the fallbacks for a
text that is not the file's own.
"""

from __future__ import annotations

import re
from pathlib import Path

import cordon_scanner

ROOT = Path(cordon_scanner.__file__).parent
#: `len(name[: expr].encode(`: the byte length of everything before a position.
PREFIX_LENGTH = re.compile(r"len\(\s*[\w.]+\[\s*:\s*[^\]:]+\]\s*\.encode\(")
#: Each is the fallback of a conditional on `text is content.text`, or the definition of the helper, or a text with no mark by construction.
ALLOWED = {
    "foundation/content.py": 2,  # the helper, and the sentence that says not to
    "foundation/text/columns.py": 1,  # the implementation `FileContent.byte_offset` delegates to (it counts the mark)
    "detect/agents/installs/planting.py": 2,  # converted in the size-cap branch (PR 93)
    "detect/agents/findings.py": 1,
    "detect/agents/instructions.py": 1,
    "detect/agents/text_findings.py": 1,
    "detect/code/capability/javascript.py": 1,
    "analysis/javascript/front/resolve.py": 1,
}


class Sites:
    @staticmethod
    def found() -> dict[str, int]:
        found: dict[str, int] = {}
        for path in sorted(ROOT.rglob("*.py")):
            count = len(PREFIX_LENGTH.findall(path.read_text(encoding="utf-8")))
            if count:
                found[path.relative_to(ROOT).as_posix()] = count
        return found


class TestNoByteOffsetIgnoresAMark:
    def test_the_sites_are_the_few_that_are_meant_to(self) -> None:
        found = Sites.found()
        extra = {name: count for name, count in found.items() if count > ALLOWED.get(name, 0)}
        assert not extra, (
            "a position in text becomes a byte offset with the encoded length of the text before it, which a UTF-8 mark makes "
            f"three bytes short; use FileContent.byte_offset (or AgentFinding.byte_at): {extra}"
        )

    def test_the_pattern_sees_the_form_it_guards_against(self) -> None:
        assert PREFIX_LENGTH.search('start = len(text[: found.start()].encode("utf-8"))')
        assert PREFIX_LENGTH.search("return len(unit.content.text[: max(index, 0)].encode())")
        assert not PREFIX_LENGTH.search('end = start + len(text[first:last].encode("utf-8"))')
