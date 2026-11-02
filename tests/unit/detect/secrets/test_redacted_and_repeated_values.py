"""Release item 68, fix 5: a redacted key and a one-character filler are not credentials.

Two whole-value shapes, each measured on the MCP reference servers (modelling scratchpad mcpv/):

* A REDACTED KEY: some characters of a key, then a run of asterisks. langchain's `config.yaml` and
  `docker_config.yaml` ship nineteen of these ("sk-" and lowercase runs, then `******`); the part
  that would make the key usable is the part the mask replaced.
* ONE CHARACTER REPEATED, as the whole value: `description = "aaaaaaaaaaaaa"`.

Both go in `NOT_A_SECRET`, which is anchored at both ends, so a real key that merely contains or sits
beside such text is still a credential. Fixtures are synthetic: no value here is, or was derived from,
a working credential.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.secrets.names import NOT_A_SECRET
from cordon_scanner.foundation.config.settings import Config

# A synthetic key-shaped run, not sequential, not a word, not any provider's real key.
HEAD = "q7Zk3mWx9TpL2vRb8NcY4hJd6sFg"


class RedactedHelpers:
    @staticmethod
    def rules(tmp_path, name: str, text: str) -> set[str]:
        (tmp_path / name).write_text(text, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return {f.rule_id for f in found}


class TestARedactedKeyIsNotACredential:
    @pytest.mark.parametrize(
        "value",
        [
            f"{HEAD}******",
            f"sk-{HEAD}********",
            "sk-" + "*" * 32,
            "****",
        ],
    )
    def test_a_head_and_a_run_of_asterisks_is_excused(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode())

    @pytest.mark.parametrize(
        "value",
        [
            # A mask in the middle leaves the end of the key in the clear.
            f"{HEAD}****{HEAD}",
            # Fewer than four is not a mask.
            f"{HEAD}**",
            # Text after the run: not a redacted display of a key.
            f"{HEAD}****extra",
            # A real-format key with no mask at all.
            f"sk-{HEAD}Zq9",
        ],
    )
    def test_anything_else_is_not_excused_by_this_shape(self, value: str) -> None:
        assert not NOT_A_SECRET.match(value.encode())

    def test_a_redacted_assignment_in_config_reports_nothing(self, tmp_path) -> None:
        text = f'llm:\n  api_key: "{HEAD}********"\n'
        found = RedactedHelpers.rules(tmp_path, "config.yaml", text)
        assert not {r for r in found if r.startswith("SECRET.")}

    def test_a_real_format_key_with_a_placeholder_word_on_the_same_line_still_reports(
        self, tmp_path
    ) -> None:
        # The word is beside the key, not in it: it excuses nothing.
        text = f'API_KEY = "sk-{HEAD}Zq9Lw8Xc5Vb"  # example of the format\n'
        found = RedactedHelpers.rules(tmp_path, "settings.py", text)
        assert {r for r in found if r.startswith("SECRET.")}


class TestOneRepeatedCharacterIsNotACredential:
    @pytest.mark.parametrize("value", ["aaaaaaaaaaaaa", "0" * 16, "Z" * 12])
    def test_a_value_that_is_one_character_repeated_is_excused(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode())

    @pytest.mark.parametrize(
        "value",
        [
            # A prefix makes it a different value: this is a padded key (glpat-AAAA...).
            "glpat-" + "A" * 16,
            # Too short to say anything.
            "aaaa",
        ],
    )
    def test_a_padded_or_mixed_value_is_not_excused_by_this_shape(self, value: str) -> None:
        assert not NOT_A_SECRET.match(value.encode())
