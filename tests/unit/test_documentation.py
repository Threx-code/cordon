"""Whether the documentation describes this program.

Documentation drifts silently. Nothing fails when a command is renamed and the
guide is not, and the reader who tries the old name is the one who finds out.
Three things here had drifted: a git-hook command renamed to `cordon guard
install` while two documents still said `cordon install-hooks`, a detector whose
id is `advisory` written throughout as `malware_intel`, and `from cordon_scanner import
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

import cordon_scanner
from cordon_scanner.cli.main import CommandLine
from support import requires_workflows

PROGRAM = CommandLine.PROGRAM

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
    # `from cordon_scanner import Scanner` -- Python, not a subcommand.
    "import",
    # `rev-parse` in a git invocation quoted next to the tool's name.
    "rev",
}


INVOCATION = re.compile(rf"(?<![\w.-]){re.escape(PROGRAM)}[ \t]+([a-z][a-z-]{{2,}})\b")
r"""A command line in the documentation.

Built from the program name rather than spelled out, so that renaming the
command cannot quietly turn this sweep into one that matches nothing. That is
exactly what happened when `cordon` became `cordon-scanner`: the hard-coded
pattern wanted whitespace after `cordon`, met a hyphen, matched nothing in any
document, and every test below went green while checking no documentation at
all.

Spaces and tabs, not `\s`: a subcommand is on the same line as the program. `\s`
spans the newline in

    pip install cordon-scanner
    cordon-scanner scan .

and reads the package name on one line as a subcommand of the other."""


def documented_commands() -> set[str]:
    found: set[str] = set()
    for document in DOCUMENTS:
        for match in INVOCATION.finditer(document.read_text(encoding="utf-8")):
            found.add(match.group(1))
    return found - PROSE


class TestCommands:
    def real(self) -> set[str]:
        parser = CommandLine.build_parser()
        return {name for action in parser._actions if action.choices for name in action.choices}

    def test_every_documented_command_exists_or_is_labelled(self) -> None:
        """A command named in the documentation either works, or the document
        says plainly that it does not exist yet."""
        unimplemented = {"deps", "suppress", "completion"}
        unknown = documented_commands() - self.real() - unimplemented
        assert not unknown, sorted(unknown)

    @pytest.mark.parametrize("command", sorted({"deps", "suppress", "completion"}))
    def test_an_unimplemented_command_is_marked_as_such(self, command: str) -> None:
        """The label is the whole defence. Without it these read as features,
        and a reader who trusts the document is misled by it."""
        for document in DOCUMENTS:
            text = document.read_text(encoding="utf-8")
            if not re.search(rf"\bcordon\s+{command}\b", text):
                continue
            assert "not yet implemented" in text, document.name

    def test_the_check_sees_real_commands(self) -> None:
        """A parser that yielded nothing would make the test above vacuous."""
        assert {"scan", "guard", "rules"} <= self.real()

    def test_the_documentation_sweep_finds_command_lines(self) -> None:
        """So does a document sweep that matches nothing, which is the failure
        this test exists for: the sweep was anchored on the program name, the
        program was renamed, and the pattern silently stopped matching."""
        found = documented_commands()
        assert {"scan", "rules"} <= found, sorted(found)


class TestExtras:
    """An extra named in the documentation must exist, or be roadmap.

    This drifted twice. `[intel]` was described in the architecture document
    and declared nowhere, and `[ast]` was declared and implemented nowhere --
    two packages added to every installation for a feature that did not exist,
    with a comment promising a degradation finding that could not be produced.
    Checked rather than reviewed, because the failure is invisible: nothing
    breaks when an extra is named that no longer exists.
    """

    ROADMAP = ("04-OPERATIONS.md",)
    """Documents with an explicit phase plan, where naming a future extra is
    the point rather than a mistake."""

    def declared(self) -> set[str]:
        import tomllib

        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        return set(data["project"].get("optional-dependencies", {}))

    def test_every_named_extra_exists_or_is_roadmap(self) -> None:
        declared = self.declared()
        unknown: list[str] = []
        for document in [*DOCUMENTS, ROOT / "CONTRIBUTING.md"]:
            if not document.exists() or document.name in self.ROADMAP:
                continue
            text = document.read_text(encoding="utf-8")
            for match in re.finditer(r"`\[([a-z][a-z0-9_-]*)\]`", text):
                name = match.group(1)
                if name in declared:
                    continue
                # Named while explaining that it does not exist is fine; that
                # is what the architecture document now does.
                window = text[max(0, match.start() - 400) : match.end() + 400]
                if "never" in window or "not exist" in window or "Phase" in window:
                    continue
                unknown.append(f"{document.name}: [{name}]")
        assert not unknown, unknown

    def test_the_check_sees_the_real_extras(self) -> None:
        assert self.declared() == {"dev"}, self.declared()


class TestPublicApi:
    def test_a_star_import_works(self) -> None:
        """`__all__` listed `resolve`, which is a method on `ConfigResolver` and
        not a name in this module, so `from cordon_scanner import *` raised
        `AttributeError` on a clean install."""
        missing = [name for name in cordon_scanner.__all__ if not hasattr(cordon_scanner, name)]
        assert not missing, missing

    def test_every_exported_name_is_public(self) -> None:
        assert not [
            name
            for name in cordon_scanner.__all__
            if name.startswith("_") and name != "__version__"
        ]


class TestPackaging:
    def test_the_readme_has_no_repository_relative_links(self) -> None:
        """The README is the PyPI project page, where a link relative to the
        repository resolves to nothing."""
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        relative = re.findall(r"\]\((?!https?://|#)([^)]+)\)", text)
        assert not relative, relative

    def test_the_changelog_names_the_current_version(self) -> None:
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert f"[{cordon_scanner.__version__}]" in text

    def test_the_action_does_not_hard_code_a_version(self) -> None:
        """The version the Action installs comes from its hash pin, so a
        hard-coded default is a second place to update and a second place to
        get wrong. It used to name a version that was not on PyPI, which failed
        every workflow that did not override it."""
        action = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        assert "CORDON_VERSION: ${{ env.CORDON_VERSION || '' }}" in action


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
    USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.M)
    """`uses:` as a YAML key, not the word anywhere on a line.

    The looser form matched `echo "Point uses: at a release tag"` inside a
    shell block and reported the prose as an unpinned action."""

    def test_every_uses_is_a_digest(self) -> None:
        unpinned: list[str] = []
        for path in self.FILES:
            for line in path.read_text(encoding="utf-8").splitlines():
                match = self.USES.search(line)
                if match and not self.DIGEST.search(line) and not match.group(1).startswith("./"):
                    unpinned.append(f"{path.name}: {line.strip()}")
        assert not unpinned, unpinned

    def test_the_check_sees_some_actions(self) -> None:
        """A pattern that matched nothing would pass this file forever."""
        total = sum(len(self.USES.findall(path.read_text(encoding="utf-8"))) for path in self.FILES)
        assert total >= 3, total


@requires_workflows
class TestActionInstallIsVerified:
    """How the Action gets the scanner onto the runner.

    Pinning the Action to a commit SHA -- which its callers are told to do, and
    which `TestWorkflowPinning` enforces for the Actions this project itself
    runs -- covers `action.yml` and nothing else. It says nothing about what pip
    then downloads, so a compromised index or release account replaces the
    scanner in every workflow using the Action and no pin detects it.

    `--require-hashes` against a pin generated at release time closes that, and
    the absence of a pin is refused rather than installed, because the scanner
    is the one dependency a supply-chain scan cannot take on trust.
    """

    ACTION = ROOT / "action" / "action.yml"
    PIN = ROOT / "action" / "requirements.txt"

    def body(self) -> str:
        return self.ACTION.read_text(encoding="utf-8")

    def test_the_install_requires_hashes(self) -> None:
        assert "--require-hashes" in self.body()

    def test_a_missing_pin_is_refused_by_default(self) -> None:
        text = self.body()
        assert 'if [ "$ALLOW_UNVERIFIED" != "true" ]' in text
        assert "carries no hash pin" in text

    def test_the_escape_hatch_is_an_input_and_says_what_it_costs(self) -> None:
        """An unverified install has to be asked for in the workflow file, where
        it is reviewable, rather than happening because a file was absent."""
        text = self.body()
        assert "allow-unverified-install:" in text
        assert 'default: "false"' in text.split("allow-unverified-install:", 1)[1][:600]

    def test_an_unverified_install_announces_itself(self) -> None:
        assert "::warning::Installing Cordon without verifying it" in self.body()

    def test_a_version_override_cannot_disagree_with_the_pin(self) -> None:
        """A pin for one version and a request for another verifies nothing, so
        the two disagreeing is an error rather than a silent preference."""
        assert "does not match" in self.body() or "pins a different version" in self.body()

    def test_the_release_workflow_generates_the_pin(self) -> None:
        release = ROOT / ".github" / "workflows" / "release.yml"
        text = release.read_text(encoding="utf-8")
        assert "pin_action_requirements.py" in text
        assert "--from-dist" in text, "the pin must come from the artefacts being published"
        assert "--from-pypi --check" in text, "and be confirmed against what the index serves"

    def test_the_pin_if_present_matches_this_version(self) -> None:
        """Skipped until a release generates one. Asserted rather than assumed
        once it exists: a pin naming an older version pins the wrong artefact
        and the Action installs nothing at all."""
        if not self.PIN.exists():
            pytest.skip("no release has generated a pin yet")
        text = self.PIN.read_text(encoding="utf-8")
        assert f"cordon-scanner=={cordon_scanner.__version__} " in text
        assert text.count("--hash=sha256:") >= 2, "wheel and sdist both need a digest"


class TestConfigurationFilename:
    """The name a user writes their configuration into.

    A data filename, not an installed name, and it moved by accident. The
    rename from `cordon` to `cordon_scanner` was applied with a pattern that
    matched module paths in strings, and `"cordon.yaml"` in `CONFIG_FILENAMES`
    looks exactly like one. Discovery started looking for `cordon_scanner.yaml`
    while every document still said `cordon.yaml`, and the tests were rewritten
    by the same pattern, so the suite agreed with the break and stayed green.

    The consequence for a user is the quiet kind: the configuration file the
    README told them to write is simply never read, and the scan runs on
    defaults while appearing to honour their settings.

    So the accepted names are pinned here against the documentation rather than
    against another copy of themselves.
    """

    def documented(self) -> set[str]:
        names: set[str] = set()
        for document in [*DOCUMENTS, ROOT / "README.md"]:
            if not document.exists():
                continue
            names.update(re.findall(r"\b\.?cordon\.ya?ml\b", document.read_text(encoding="utf-8")))
        return names

    def test_every_documented_name_is_accepted(self) -> None:
        from cordon_scanner.core.config import CONFIG_FILENAMES

        unknown = self.documented() - set(CONFIG_FILENAMES)
        assert not unknown, unknown

    def test_the_documented_names_are_not_empty(self) -> None:
        """A sweep that found nothing would let the names move again."""
        assert "cordon.yaml" in self.documented()

    def test_the_accepted_names_are_what_they_should_be(self) -> None:
        from cordon_scanner.core.config import CONFIG_FILENAMES

        assert set(CONFIG_FILENAMES) == {
            "cordon.yaml",
            "cordon.yml",
            ".cordon.yaml",
            ".cordon.yml",
        }

    def test_a_documented_config_is_actually_discovered(self, tmp_path) -> None:
        """The end-to-end form. The names agreeing is not the same as discovery
        working."""
        from cordon_scanner.core.config import ConfigResolver

        (tmp_path / "cordon.yaml").write_text(
            "scan:\n  severity_threshold: critical\n", encoding="utf-8"
        )
        config = ConfigResolver.resolve(root=tmp_path)
        assert str(config.severity_threshold) == "critical"
        assert config.from_untrusted_source
