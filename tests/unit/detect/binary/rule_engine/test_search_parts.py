"""The literal runs every match must hold are listed in one order, whatever the process's hash seed."""

from __future__ import annotations

import os
import subprocess
import sys

from cordon_scanner.detect.binary.rule_engine.lang import Rules


class Required:
    """A rule string's required literal runs (`Part.required`), as the scan compiles them."""

    PATTERN = r"/alpha.{2,9}gamma.{2,9}omega.{2,9}delta/"

    @staticmethod
    def of(pattern: str) -> list[bytes]:
        rules = Rules.compile("rule r { strings: $a = " + pattern + " condition: $a }")
        return list(rules.rules[0].strings[0].search.parts[0].required)


class TestRequiredLiterals:
    def test_longest_first_and_equal_lengths_by_their_bytes(self) -> None:
        assert Required.of(Required.PATTERN) == [b"alpha", b"delta", b"gamma", b"omega"]

    def test_the_order_is_the_same_under_another_hash_seed(self) -> None:
        code = (
            "from tests.unit.detect.binary.rule_engine.test_search_parts import Required;"
            "print(Required.of(Required.PATTERN))"
        )
        seen = set()
        for seed in ("1", "2", "3"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            out = subprocess.run(
                [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True
            )
            seen.add(out.stdout.strip())
        assert len(seen) == 1, seen
