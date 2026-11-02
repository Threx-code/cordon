"""The built-in rule patterns' derivations, computed at release and read at load (item 74, cut 3).

Loading the bundled packs spent about 0.45 CPU s per process, and most of it was not compiling:
re.compile of all 242 combined patterns is 0.07 s. The rest is reading each pattern -- the safety
walk in `validate_pattern`, the exact-case prefilter and the required literals, three ways -- which
is deterministic in the pattern's text and the code that reads it.

```
  release:  every built-in pattern ──► the same PatternCompiler functions ──► derivations.json
              keyed by the pattern's sha256; the file names the derivation code's own digest and
              the Python it ran under

  load:     a pattern ──► its sha256 in the table, and the table's code digest and Python match?
              yes ──► the stored values (a "safe" verdict still compiles the pattern, as before)
              no  ──► derived live, exactly as before (a user's pack, a feed pack, an edited install)
```

The table can only make a load faster: it holds no pattern that failed validation, so a refusal is
always derived live, and a table whose code digest or Python differs is not read at all. A suite
test (tests/unit/rules/test_derivations.py) re-derives every built-in pattern and requires the table
to equal it, so a stale table fails CI rather than a user's scan.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Final

from cordon_scanner.foundation.once import OneOff

TABLE: Final = "derivations.json"
VERSION: Final = 1

#: The ways `RuleLoader._compile_regex` asks for required literals, by name: (shortest, adjacent).
LITERAL_FORMS: Final[dict[str, tuple[int, bool]]] = {
    "required": (3, False),
    "coarse": (2, False),
    "sharper": (3, True),
}


class PatternDerivations:
    """One process's view of the shipped table: stored derivations where they apply, else live."""

    @staticmethod
    def key(pattern: str) -> str:
        return hashlib.sha256(pattern.encode("utf-8", "surrogatepass")).hexdigest()

    @staticmethod
    def code_digest() -> str:
        """The derivation code's own digest: the module the stored values came from."""
        from cordon_scanner.rules import patterns

        return hashlib.sha256(Path(patterns.__file__).read_bytes()).hexdigest()

    @staticmethod
    def directory() -> Path:
        """Where the table ships: beside the bundled packs (`RuleLoader.builtin_pack_dir`)."""
        from cordon_scanner.foundation.paths import PackagePaths

        return PackagePaths.root() / "rules" / "builtin"

    @staticmethod
    def python() -> str:
        return f"{sys.version_info[0]}.{sys.version_info[1]}"

    @staticmethod
    @OneOff.cache
    def shipped() -> dict[str, Any]:
        """The table's entries, or {} when it is absent, unreadable, or from other code or Python."""
        try:
            doc = json.loads((PatternDerivations.directory() / TABLE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if (
            not isinstance(doc, dict)
            or doc.get("version") != VERSION
            or doc.get("python") != PatternDerivations.python()
            or doc.get("code") != PatternDerivations.code_digest()
            or not isinstance(doc.get("patterns"), dict)
        ):
            return {}
        entries: dict[str, Any] = doc["patterns"]
        return entries

    # ---- what the loader asks -------------------------------------------------------------------

    @staticmethod
    def validated(combined: str, *, rule_id: str) -> re.Pattern[bytes]:
        """`validate_pattern`, its safety walk skipped for a pattern the table records as safe."""
        from cordon_scanner.rules.patterns import PatternCompiler

        entry = PatternDerivations.shipped().get(PatternDerivations.key(combined))
        if isinstance(entry, dict) and entry.get("safe") is True:
            return re.compile(combined.encode("utf-8"), re.MULTILINE)
        return PatternCompiler.validate_pattern(combined, rule_id=rule_id)

    @staticmethod
    def prefilter(pattern: str) -> tuple[bytes, ...]:
        from cordon_scanner.rules.patterns import PatternCompiler

        stored = PatternDerivations._stored(pattern, "prefilter")
        if stored is not None:
            return stored
        return PatternCompiler._extract_prefilter(pattern.encode("utf-8"))

    @staticmethod
    def literals(pattern: str, form: str) -> tuple[bytes, ...]:
        from cordon_scanner.rules.patterns import PatternCompiler

        stored = PatternDerivations._stored(pattern, form)
        if stored is not None:
            return stored
        shortest, adjacent = LITERAL_FORMS[form]
        return PatternCompiler.required_literals(pattern, shortest=shortest, adjacent=adjacent)

    @staticmethod
    def _stored(pattern: str, field: str) -> tuple[bytes, ...] | None:
        entry = PatternDerivations.shipped().get(PatternDerivations.key(pattern))
        if not isinstance(entry, dict):
            return None
        value = entry.get(field)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return None
        try:
            return tuple(bytes.fromhex(v) for v in value)
        except ValueError:
            return None

    # ---- release time ---------------------------------------------------------------------------

    @staticmethod
    def derive(patterns: list[str], combined: list[str]) -> dict[str, Any]:
        """Every entry, computed live by the loader's own functions: the single patterns' literals
        and the combined alternations' safety verdicts (a refused one is left out)."""
        from cordon_scanner.foundation.errors import UnsafePatternError
        from cordon_scanner.rules.patterns import PatternCompiler

        out: dict[str, Any] = {}
        for pattern in sorted(set(patterns)):
            entry: dict[str, Any] = {
                "prefilter": [
                    v.hex() for v in PatternCompiler._extract_prefilter(pattern.encode("utf-8"))
                ]
            }
            for form, (shortest, adjacent) in LITERAL_FORMS.items():
                found = PatternCompiler.required_literals(
                    pattern, shortest=shortest, adjacent=adjacent
                )
                entry[form] = [v.hex() for v in found]
            out[PatternDerivations.key(pattern)] = entry
        for pattern in sorted(set(combined)):
            try:
                PatternCompiler.validate_pattern(pattern, rule_id="derivations")
            except UnsafePatternError:
                continue
            out.setdefault(PatternDerivations.key(pattern), {})["safe"] = True
        return out

    @staticmethod
    def document(singles: list[str], combined: list[str]) -> dict[str, Any]:
        """The table for these patterns (`RuleLoader.bundled_patterns`, at release)."""
        return {
            "version": VERSION,
            "python": PatternDerivations.python(),
            "code": PatternDerivations.code_digest(),
            "patterns": PatternDerivations.derive(singles, combined),
        }


__all__ = ["LITERAL_FORMS", "TABLE", "VERSION", "PatternDerivations"]
