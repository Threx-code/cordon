"""PythonDecodedRun: a run no decoded value in the file reaches is not a run of it (review 98 real
skills: qwen-image-gen, render-imessage-chat, se-dev-plugin-review). Every way a decoded value can
reach a run, or leave the file's sight, keeps the pairing."""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.analysis.python.py_decoded import PythonDecodedRun
from cordon_scanner.foundation.config.settings import Config

DECODE = "b64" + "decode"
RUN = "r" + "un"
COMPOSITES = ("SUSPECT.DECODE_EXEC.001", "MALWARE.INSTALL.DECODED_LAUNCH.001")


class DecodedHelpers:
    @staticmethod
    def line_of(source: str, needle: str) -> int:
        return next(i for i, line in enumerate(source.splitlines(), 1) if needle in line)

    @staticmethod
    def excused(source: str) -> bool:
        """Whether the file's only spawn (the line holding `subprocess.`) is excused."""
        line = DecodedHelpers.line_of(source, "subprocess." + RUN)
        return line in PythonDecodedRun.unreached_runs(source)


line_of, excused = DecodedHelpers.line_of, DecodedHelpers.excused


HEAD = "import base64, subprocess\n"


class TestUnreached:
    def test_a_fixture_decoded_to_compare_beside_a_cli_run(self) -> None:
        source = HEAD + (
            f"raw = base64.{DECODE}('aGVsbG8=')\n"
            "path.write_bytes(raw)\n"
            "assert path.read_bytes() == raw\n"
            f"done = subprocess.{RUN}(args, capture_output=True)\n"
        )
        assert excused(source)

    def test_a_decoded_value_returned_to_a_caller_that_does_not_run_it(self) -> None:
        source = HEAD + (
            f"def fetch(r):\n    return base64.{DECODE}(r['content'])\n"
            "def git(args):\n"
            f"    return subprocess.{RUN}(args, capture_output=True)\n"
            "text = fetch(response).decode()\n"
            "git(['status'])\n"
        )
        assert excused(source)

    def test_sound_effects_decoded_and_written_beside_another_program(self) -> None:
        source = HEAD + (
            f"items = [(n, base64.{DECODE}(f['b'])) for n, f in files.items()]\n"
            "for name, data in items:\n"
            "    open(out + '/' + name, 'wb').write(data)\n"
            f"subprocess.{RUN}(['ffmpeg', '-i', clip, mixed])\n"
        )
        assert excused(source)


class TestReached:
    def test_the_decoded_command_itself(self) -> None:
        source = HEAD + f"cmd = base64.{DECODE}(blob).decode()\nsubprocess.{RUN}(cmd, shell=True)\n"
        assert not excused(source)

    def test_through_a_function_of_the_file(self) -> None:
        source = HEAD + (
            f"def go(c):\n    subprocess.{RUN}(c, shell=True)\ngo(base64.{DECODE}(blob))\n"
        )
        assert not PythonDecodedRun.unreached_runs(source) & {line_of(source, "subprocess.")}

    def test_written_to_a_path_that_is_then_run(self) -> None:
        source = HEAD + (
            f"data = base64.{DECODE}(blob)\n"
            "with open(target, 'wb') as f:\n    f.write(data)\n"
            f"subprocess.{RUN}([target])\n"
        )
        assert not excused(source)

    def test_written_to_a_literal_path_run_by_the_same_literal(self) -> None:
        source = HEAD + (
            f"open('/tmp/u', 'wb').write(base64.{DECODE}(blob))\nsubprocess.{RUN}(['/tmp/u'])\n"
        )
        assert not excused(source)

    def test_handed_to_something_that_may_run_it(self) -> None:
        # A loader this does not know to be inert: no run in the file is excused.
        source = HEAD + (
            f"obj = loader.loads(base64.{DECODE}(blob))\n"
            f"subprocess.{RUN}(['git', 'status', here])\n"
        )
        assert not excused(source)


class TestEndToEnd:
    @staticmethod
    def rules(tmp_path, setup: str) -> set[str]:
        (tmp_path / "setup.py").write_text(setup, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    def test_an_unrelated_run_beside_a_decode_does_not_pair(self, tmp_path) -> None:
        setup = HEAD + (
            "from setuptools import setup\n"
            f"icon = base64.{DECODE}('aGVsbG8=')\n"
            "assert len(icon) == 5\n"
            "def check(where):\n"
            f"    subprocess.{RUN}(['git', 'status', where])\n"
            "check(here)\n"
            "setup(name='x')\n"
        )
        assert not set(COMPOSITES) & self.rules(tmp_path, setup)

    def test_a_decoded_command_run_at_install_still_blocks(self, tmp_path) -> None:
        setup = HEAD + (
            "from setuptools import setup\n"
            f"subprocess.{RUN}(base64.{DECODE}(BLOB).decode(), shell=True)\n"
            "setup(name='x')\n"
        )
        assert set(COMPOSITES) & self.rules(tmp_path, setup)
