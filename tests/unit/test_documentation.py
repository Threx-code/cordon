"""Whether the documentation describes this program.

Documentation drifts silently. Nothing fails when a command is renamed and the
guide is not, and the reader who tries the old name is the one who finds out.
Three things here had drifted: a git-hook command renamed to `cordon guard
install` while two documents still said `cordon install-hooks`, a detector whose
id is `advisory` written throughout as `malware_intel`, and `from cordon import
*` raising `AttributeError` because `__all__` listed a name the module does not
have.

These are cheap to check and the checks are precise, so they are checks rather
than a habit of proofreading. What is deliberately *not* checked is prose
accuracy, which no test can reach; the documents carry explicit
"designed, not yet implemented" labels for that, and the label is what the last
test here defends.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import cordon
from cordon.cli.main import CommandLine
from support import requires_workflows

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = [*sorted((ROOT / "docs").glob("*.md")), ROOT / "README.md"]

# Words that follow "cordon" in ordinary prose rather than naming a command.
PROSE = {
    "cannot",
    "can",
    "does",
    "did",
    "is",
    "was",
    "will",
    "would",
    "has",
    "and",
    "the",
    # `from cordon import Scanner` -- Python, not a subcommand.
    "import",
    # `rev-parse` in a git invocation quoted next to the tool's name.
    "rev",
}


def documented_commands() -> set[str]:
    found: set[str] = set()
    for document in DOCUMENTS:
        for match in re.finditer(r"\bcordon\s+([a-z][a-z-]{2,})\b", document.read_text()):
            found.add(match.group(1))
    return found - PROSE


class TestCommands:
    def real(self) -> set[str]:
        parser = CommandLine.build_parser()
        return {name for action in parser._actions if action.choices for name in action.choices}

    def test_every_documented_command_exists_or_is_labelled(self) -> None:
        """A command named in the documentation either works, or the document
        says plainly that it does not exist yet."""
        unimplemented = {"deps", "suppress", "completion", "bundle"}
        unknown = documented_commands() - self.real() - unimplemented
        assert not unknown, sorted(unknown)

    @pytest.mark.parametrize("command", sorted({"deps", "suppress", "completion", "bundle"}))
    def test_an_unimplemented_command_is_marked_as_such(self, command: str) -> None:
        """The label is the whole defence. Without it these read as features,
        and a reader who trusts the document is misled by it."""
        for document in DOCUMENTS:
            text = document.read_text()
            if not re.search(rf"\bcordon\s+{command}\b", text):
                continue
            assert "not yet implemented" in text, document.name

    def test_the_check_sees_real_commands(self) -> None:
        """A parser that yielded nothing would make the test above vacuous."""
        assert {"scan", "guard", "rules"} <= self.real()


class TestPublicApi:
    def test_a_star_import_works(self) -> None:
        """`__all__` listed `resolve`, which is a method on `ConfigResolver` and
        not a name in this module, so `from cordon import *` raised
        `AttributeError` on a clean install."""
        missing = [name for name in cordon.__all__ if not hasattr(cordon, name)]
        assert not missing, missing

    def test_every_exported_name_is_public(self) -> None:
        assert not [
            name for name in cordon.__all__ if name.startswith("_") and name != "__version__"
        ]


class TestPackaging:
    def test_the_readme_has_no_repository_relative_links(self) -> None:
        """The README is the PyPI project page, where a link relative to the
        repository resolves to nothing."""
        text = (ROOT / "README.md").read_text()
        relative = re.findall(r"\]\((?!https?://|#)([^)]+)\)", text)
        assert not relative, relative

    def test_the_changelog_names_the_current_version(self) -> None:
        text = (ROOT / "CHANGELOG.md").read_text()
        assert f"[{cordon.__version__}]" in text

    def test_the_action_default_matches_the_package_version(self) -> None:
        """The Action installs `cordon-scanner==$CORDON_VERSION`. A default that
        does not exist on PyPI fails every workflow that does not set it."""
        action = (ROOT / "action" / "action.yml").read_text()
        default = re.search(r"CORDON_VERSION:.*?'([^']+)'", action)
        assert default is not None
        assert default.group(1) == cordon.__version__


@requires_workflows
class TestWorkflowPinning:
    """Every action this project runs is pinned to a commit digest.

    A tag is mutable. `uses: some/action@v3` runs whatever that tag points at
    today, which makes every workflow -- including the release workflow that
    builds and signs the artefacts -- trust an upstream repository's ability to
    move a tag. For a security scanner that is not a theoretical concern: the
    scanner's own build is the highest-value target it has.

    Checked rather than reviewed because a pin is exactly the kind of thing a
    routine "bump the action version" commit silently undoes.
    """

    FILES = (
        ROOT / "action" / "action.yml",
        *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    )
    DIGEST = re.compile(r"uses:\s*\S+@([0-9a-f]{40})\b")
    USES = re.compile(r"uses:\s*(\S+)")

    def test_every_uses_is_a_digest(self) -> None:
        unpinned: list[str] = []
        for path in self.FILES:
            for line in path.read_text().splitlines():
                match = self.USES.search(line)
                if match and not self.DIGEST.search(line) and not match.group(1).startswith("./"):
                    unpinned.append(f"{path.name}: {line.strip()}")
        assert not unpinned, unpinned

    def test_the_check_sees_some_actions(self) -> None:
        """A pattern that matched nothing would pass this file forever."""
        total = sum(len(self.USES.findall(path.read_text())) for path in self.FILES)
        assert total >= 3, total
