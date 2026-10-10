"""A credential-shaped value on a REPL transcript line is an illustration, not an assignment.

Found scanning real repositories: Phoenix.Token's documentation signs with an example secret on
an `iex>` line, which Elixir's doctests run. Python's `>>>`, IPython's `In [n]:` and a shell
`$ ` were already read as transcripts; Elixir's and Ruby's prompts were not. Each value here is
built by `Support.assemble`, so this file does not carry what it tests for.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.secrets import SecretDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from support import Support


class TestReplTranscripts:
    CONTEXT = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))
    VALUE = Support.assemble("kjoy3o1zeid", "quwy1398juxzldjlksahdk3")

    def rules(self, line: str, path: str, language: str) -> list[str]:
        unit = FileUnit(
            content=FileContent.from_bytes(path, f"{line}\n".encode()), language=language
        )
        return [f.rule_id for f in SecretDetector().inspect(unit, self.CONTEXT)]

    @pytest.mark.parametrize(
        ("prompt", "path", "language"),
        [
            ("      iex> ", "lib/token.ex", "elixir"),
            ("iex(1)> ", "lib/token.ex", "elixir"),
            ("irb(main):001:0> ", "lib/token.rb", "ruby"),
            ("irb(main):001> ", "lib/token.rb", "ruby"),
            ("pry(main)> ", "lib/token.rb", "ruby"),
        ],
    )
    def test_a_value_on_a_prompt_line_is_not_reported(self, prompt, path, language) -> None:
        assignment = f'secret = "{self.VALUE}"'
        # The control: the same assignment as code is reported.
        assert "SECRET.GENERIC.ASSIGNMENT.001" in self.rules(assignment, path, language)
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in self.rules(
            prompt + assignment, path, language
        )
