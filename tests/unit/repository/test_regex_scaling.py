"""No compiled pattern in detect/ or analysis/ has a superlinear shape that is not listed.

The per-file budget cannot interrupt a running regular expression, so a pattern that is superlinear in
the way its code calls it lets one crafted line stall a scan into "incomplete" (review 98,
27-PERFORMANCE, 5). This is the static tier: every pattern's parse tree is read for the four shapes
`kits.regexkit.Shape` names, in milliseconds. A flagged pattern must be in one of `Listed`'s lists --
open (being fixed), a specification kept for code that replaced it, or proved linear -- and the timing
ladder in tests/perf/test_regex_ladder.py checks that each list says what is true.

The check is believed because it measures: known superlinear patterns, the forms the code had before
each fix, must be flagged, and their fixed forms must not be.
"""

from __future__ import annotations

import re

from kits.regexkit import Listed, Shape, Sources

#: The forms the code had before each fix, each measured superlinear, with the mode its code used.
SUPERLINEAR: dict[str, tuple[re.Pattern[str] | re.Pattern[bytes], bool]] = {
    "_SHELL_KEY": (re.compile(rb"(?m)^([ \t]*)-?[ \t]*(?:run|script|cmd)[ \t]*:[ \t]*(.*)$"), True),
    "ANY_CALL": (re.compile(r"[A-Za-z_$][\w.$\[\]'\"]*\s*\("), True),
    "_YAML_KEY": (re.compile(r"^\s*-?\s*(name|command|url|args)\s*:\s*(.*?)\s*$"), False),
    "_YAML_ITEM": (re.compile(r"^\s*-\s+(.+?)\s*$"), False),
    "_FILLED": (re.compile(r"([A-Za-z_]\w*)\s*\.\s*(?:append|write|add)\s*\("), True),
    "DIAGNOSTIC_STATEMENT": (re.compile(rb"(?ix)^[ \t]*(?:[@-]{0,2}[ \t]*(?:echo|print))"), False),
    "_POWERSHELL_FETCH_EXEC": (re.compile(r"(?i)\biex\s*[\(\s]\s*[\(\s]*(?:iwr|irm)\b"), True),
    "_SHELL_FETCH_EXEC": (
        re.compile(r"\bcurl\b[^\n]{0,200}-o\s*\S+[^\n]{0,80}&&[^\n]{0,80}\bsh\b"),
        True,
    ),
    "READ_ONLY_COMMAND": (re.compile(r"(?i)\s*(?:(?:ls|cat)\b[^;&|<>`$]*)\s*"), False),
    "_HIDDEN_SIGNIFICANT": (re.compile(r"[a-z0-9-]+\.(?:com|net|org)\b"), True),
    "_URL": (re.compile(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", re.I), True),
    "PLACEHOLDER": (re.compile(rb"(?i)example|<[^>]{3,}>"), True),
    "_VERSIONED_ROOT": (re.compile(r"^[^/]*?[-_]v?\d+(?:\.\d+){0,3}[^/]*/"), True),
    "_OBJECT": (re.compile(r"\{[\s\S]*\}"), True),
    "_SENTENCE": (re.compile(r"[^\n]{1,2000}?(?:[.!?](?!\w)|\n|$)"), True),
    "CD_INSIDE": (re.compile(r"cd\s+(?![/~$\\])(?!.*\.\.)[\w./@-]{1,200}"), False),
    "_PDF_STREAM": (re.compile(rb"<<(.{0,4096}?)>>\s*stream\r?\n", re.DOTALL), True),
}

#: Their fixed forms, each measured linear, in the same mode.
LINEAR: dict[str, tuple[re.Pattern[str] | re.Pattern[bytes], bool]] = {
    "ANY_CALL": (
        re.compile(
            r"(?<![\w.$\[\]'\"])(?:[^\WA-Za-z_]|[.\[\]'\"])*+([A-Za-z_$][\w.$\[\]'\"]*+\s*\()"
        ),
        True,
    ),
    "_FILLED": (
        re.compile(r"(?<!\w)[^\WA-Za-z_]*+([A-Za-z_]\w*+)\s*\.\s*(?:append|write|add)\s*\("),
        True,
    ),
    "DIAGNOSTIC_STATEMENT": (re.compile(rb"(?ix)^[ \t]*+(?:[@-]{0,2}[ \t]*(?:echo|print))"), False),
    "_POWERSHELL_FETCH_EXEC": (re.compile(r"(?i)\biex[\(\s]++(?:iwr|irm)\b"), True),
    "_HIDDEN_SIGNIFICANT": (re.compile(r"(?<![a-z0-9-])[a-z0-9-]+\.(?:com|net|org)\b"), True),
    "_URL": (re.compile(r"[a-z0-9.-]\.(?:com|net|org|io)\b", re.I), True),
    "_VERSIONED_ROOT": (re.compile(r"^(?=[^/]*?[-_]v?\d)[^/]*/"), True),
    "CD_INSIDE": (re.compile(r"cd\s++(?![/~$\\])(?!.*\.\.)[\w./@-]{1,200}"), False),
    "a literal": (re.compile(r"secret_key"), True),
    "a bounded run": (re.compile(r"\b[0-9a-f]{32}\b"), True),
}


class TestTheShapeCheck:
    def test_it_flags_every_form_measured_superlinear(self) -> None:
        missed = [name for name, (p, scanning) in SUPERLINEAR.items() if not Shape.of(p, scanning)]
        assert not missed

    def test_it_passes_their_fixed_forms(self) -> None:
        flagged = {name: Shape.of(p, scanning) for name, (p, scanning) in LINEAR.items()}
        assert not {name: why for name, why in flagged.items() if why}


class TestPatterns:
    def test_every_listed_label_names_a_pattern(self) -> None:
        labels = set(Sources.by_label())
        listed = set(Listed.OPEN) | set(Listed.SPECIFICATIONS) | set(Listed.LINEAR)
        assert listed <= labels, sorted(listed - labels)
        assert len(labels) > 500

    def test_a_pattern_is_flagged_exactly_when_it_is_listed(self) -> None:
        listed = set(Listed.OPEN) | set(Listed.SPECIFICATIONS) | set(Listed.LINEAR)
        flagged = {
            found.label: why[0]
            for found in Sources.patterns()
            if (why := Shape.of(found.pattern, scanning="search" in found.modes))
        }
        assert not {label: why for label, why in flagged.items() if label not in listed}, (
            "a superlinear shape: rewrite it, or time it with tests/perf/test_regex_ladder.py and list it"
        )
        assert not sorted(listed - set(flagged)), "no longer flagged: remove it from its list"

    def test_a_specification_is_called_by_nothing(self) -> None:
        by_label = Sources.by_label()
        called = [label for label in Listed.SPECIFICATIONS if by_label[label].called]
        assert not called, (
            "a pattern kept as a specification is slow; call the code that replaced it"
        )
