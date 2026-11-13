"""PythonDecodedRun: a run no decoded value in the file reaches is not a run of it (review 98 real
skills: qwen-image-gen, render-imessage-chat, se-dev-plugin-review). Every way a decoded value can
reach a run, or leave the file's sight, keeps the pairing."""

from __future__ import annotations

import pytest

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


class TestADecodedImage:
    """A decoded screenshot or generated picture saved under an image name is not a value every later
    use of its path carries (review 98, the windows-qa-engineer public skill): the program the file
    starts beside it is not running it. Renaming the image, or running it by name, keeps the pair."""

    SAVE = (
        "def capture(out, encoded):\n"
        "    shot = out / 'notepad.png'\n"
        f"    shot.write_bytes(base64.{DECODE}(encoded))\n"
        "    report.update(screenshot=str(shot))\n"
        "    print(json.dumps(report))\n"
        "    out.mkdir(parents=True, exist_ok=True)\n"
    )

    def test_a_program_started_beside_a_saved_screenshot(self) -> None:
        source = HEAD + self.SAVE + f"app = subprocess.{RUN}(['notepad.exe'])\n"
        assert excused(source)

    def test_the_image_run_by_its_name(self) -> None:
        source = HEAD + self.SAVE + f"subprocess.{RUN}(['python', 'notepad.png'])\n"
        assert not excused(source)

    def test_the_image_renamed_before_a_run(self) -> None:
        source = (
            HEAD
            + self.SAVE
            + (
                "os.rename('notepad.png', 'notepad.exe')\n"
                f"app = subprocess.{RUN}(['notepad.exe'])\n"
            )
        )
        assert not excused(source)

    @pytest.mark.parametrize(
        "name",
        ["'notepad.png' + suffix + '.exe'", "('notepad.png' if small else ext)", "name_from(x)"],
        ids=["another-extension", "an-extension-chosen", "a-name-computed"],
    )
    def test_a_file_whose_name_does_not_end_as_an_image(self, name: str) -> None:
        source = (
            HEAD
            + self.SAVE.replace("'notepad.png'", name)
            + (f"app = subprocess.{RUN}(['notepad.exe'])\n")
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


class TestAnExcuseCoversOnlyTheRunsItModelled:
    """The excuse is taken by line, so a line it excuses must hold no run it did not model. A name
    bound to `eval("exec")` runs its argument, and the flow, which reads runs by name, does not see
    one there: the `eval` of a literal beside it was excused, and with it the run of the decoded
    value on the same line (half B, 50 packages whose `__init__.py` does this at import)."""

    EXEC = "ex" + "ec"

    @staticmethod
    def rules(tmp_path, init: str) -> set[str]:
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text(init, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    def test_a_name_bound_to_exec_runs_the_decoded_value_on_the_excused_line(
        self, tmp_path
    ) -> None:
        init = f"import base64\ngo = eval('{self.EXEC}'); go(base64.{DECODE}('cHJpbnQoMSk='))\n"
        assert set(COMPOSITES) & self.rules(tmp_path, init)

    def test_a_literal_eval_beside_an_unrelated_decode_stays_excused(self, tmp_path) -> None:
        init = (
            "import base64\n"
            f"n = eval('1 + 1'); icon = base64.{DECODE}('aGVsbG8=')\n"
            "assert len(icon) == n + 3\n"
        )
        assert not set(COMPOSITES) & self.rules(tmp_path, init)


class TestCompressedCodeRun:
    """Code compressed rather than encoded and handed to `exec` is the same loader:
    `exec(zlib.decompress(blob))` (half B, 10 packages at import). Only an execution pairs with a
    decompression: a process started beside an unpacked archive is the self-updater the rule's own
    measurement excludes."""

    EXEC = "ex" + "ec"

    @staticmethod
    def rules(tmp_path, init: str) -> set[str]:
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text(init, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    def test_compressed_code_handed_to_exec(self, tmp_path) -> None:
        import zlib

        blob = zlib.compress(b"print(1)")
        init = f"import zlib\n{self.EXEC}(zlib.decompress({blob!r}))\n"
        assert "SUSPECT.DECODE_EXEC.001" in self.rules(tmp_path, init)

    def test_a_loader_written_as_text_by_a_code_packer_does_not_pair(self, tmp_path) -> None:
        # A packer compresses code and compiles a stub that will decompress it later: the word is in
        # the stub's text, and nothing here decompresses (pyc-zipper 1.0.8, benign rescan).
        init = (
            "import marshal, zlib\n"
            "def pack(code):\n"
            "    data = zlib.compress(marshal.dumps(code))\n"
            f"    stub = 'import marshal, zlib; {self.EXEC}(marshal.loads(zlib.decompress(%r)))' % data\n"
            "    return compile(stub, '<packed>', 'exec')\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" not in self.rules(tmp_path, init)

    def test_an_archive_unpacked_beside_a_process_start_does_not_pair(self, tmp_path) -> None:
        init = (
            "import zlib, subprocess\n"
            "data = zlib.decompress(packed)\n"
            "open('tool.tar', 'wb').write(data)\n"
            f"subprocess.{RUN}(['tar', '-xf', 'tool.tar'])\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" not in self.rules(tmp_path, init)

    def test_the_word_in_a_string_and_a_results_key_do_not_pair(self, tmp_path) -> None:
        # An evaluation script: a real decompression, the word in a literal, and a results dict
        # keyed by it -- none of which runs anything (paper-preflight 0.8, 0.8.0 benign).
        init = (
            "import gzip, json\n"
            "text = gzip.decompress(raw).decode()\n"
            f"HINT = 'the checker calls {self.EXEC} (x) on each case'\n"
            "payload = {}\n"
            f"payload['{self.EXEC}'] = json.loads(text)\n"
            f"total = payload['{self.EXEC}'].get('n', 0)\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" not in self.rules(tmp_path, init)


class TestAMethodNamedLikeTheBuiltin:
    """`model.eval()` and `session.exec(query)` are methods, not the builtins (0.8.0 benign:
    otter-ai, aiperture): beside a decode they are not a loader. The builtin reached through its
    module, beside the same decode, still is."""

    EXEC = "ex" + "ec"

    @staticmethod
    def rules(tmp_path, init: str) -> set[str]:
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text(init, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    def test_a_model_put_in_eval_mode_beside_a_decoded_image(self, tmp_path) -> None:
        init = (
            "import base64\n"
            f"image = base64.{DECODE}(request_body)\n"
            "model.eval()\n"
            f"rows = session.{self.EXEC}(select(User)).all()\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" not in self.rules(tmp_path, init)

    def test_the_builtin_through_its_module_still_pairs(self, tmp_path) -> None:
        init = f"import base64, builtins\nbuiltins.{self.EXEC}(base64.{DECODE}(BLOB))\n"
        assert "SUSPECT.DECODE_EXEC.001" in self.rules(tmp_path, init)


class TestAValueOnlyMeasuredOrLogged:
    """A decoded value only counted, matched, logged or read as a mapping is not handed to anything
    that may run it (0.8.0 benign: a checksum `sum(ord(c) ...)` over a decoded licence, a regex over a
    decoded report, a logger line). A call that may run it -- one this does not know, `map` with a
    function, a fetch of it -- still excuses nothing."""

    @pytest.mark.parametrize(
        "use",
        [
            "total = sum(ord(c) for c in chr(65) + raw.decode())",
            "n = int(raw[:4]) + abs(-1) + max(range(3))",
            "found = re.search(r'v[0-9]+', raw.decode())",
            "log.info('got %d bytes', len(raw)); logging.debug(raw)",
            "size = math.ceil(len(raw) / 8); head = struct.unpack('>I', raw[:4])",
            "meta = json.loads(raw); name = meta.get('name'); keys = list(meta.keys())",
        ],
        ids=["builtins", "numbers", "regex", "logs", "math-struct", "mapping-reads"],
    )
    def test_a_run_beside_it_is_excused(self, use: str) -> None:
        source = (
            "import base64, subprocess, re, logging, math, struct, json\n"
            f"raw = base64.{DECODE}(blob)\n{use}\n"
            f"done = subprocess.{RUN}(['git', 'status'], capture_output=True)\n"
        )
        assert excused(source)

    @pytest.mark.parametrize(
        "use",
        [
            "list(map(exec, raw.decode().splitlines()))",
            "requests.get(raw.decode())",
            "plugin.info(raw)",
            "handler(raw).get('x')",
        ],
        ids=["map-with-a-function", "fetched", "a-non-logger-info", "a-call-of-it"],
    )
    def test_a_call_that_may_run_it_excuses_nothing(self, use: str) -> None:
        source = (
            "import base64, subprocess, requests\n"
            f"raw = base64.{DECODE}(blob)\n{use}\n"
            f"done = subprocess.{RUN}(['git', 'status'], capture_output=True)\n"
        )
        assert not excused(source)
