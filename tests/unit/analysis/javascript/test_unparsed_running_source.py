"""A JavaScript file that runs when a published package is loaded and that no reader can take to its end is a gap or is said, never silence (BP-15-19).

The Python side has done this since 09 3a (`analysis/python/unparsed_source.py`): a running file that does not parse is a content gap when it
names anything that could run its pieces, and `SOURCE.BROKEN` (said) when it names nothing. A JavaScript entry file whose brackets do not
close was passed over without a word. Inert inputs written here: a package whose `main` is the file.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

GAP = "OPERATIONAL.SOURCE.UNPARSED"
BROKEN = "OPERATIONAL.SOURCE.BROKEN"
RUNNING = "SUSPECT.SOURCE.UNPARSED_RUNNING.001"


class Package:
    """A package written for the test: scanned as a folder whose install hook runs the file, or as a published tarball whose `main` is it."""

    @staticmethod
    def manifest(main: str = "index.js", hook: bool = True) -> bytes:
        document = {"name": "x", "version": "1.0.0", "main": main}
        if hook:
            document["scripts"] = {"postinstall": f"node {main}"}
        return json.dumps(document).encode()

    @staticmethod
    def scan(folder: Path, files: dict[str, bytes], main: str = "index.js"):
        (folder / "package.json").write_bytes(Package.manifest(main))
        for name, body in files.items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(folder)

    @staticmethod
    def scan_tarball(folder: Path, files: dict[str, bytes], main: str = "index.js"):
        path = folder / "x-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as archive:
            for name, body in {"package.json": Package.manifest(main, hook=False), **files}.items():
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(path)

    @staticmethod
    def rules(result) -> set[str]:
        return {f.rule_id for f in result.active}


class TestAnEntryFileThatDoesNotClose:
    def test_with_an_act_in_it_is_a_gap_and_a_running_finding(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"eval(atob('x'))\nfunction f( {\n"})
        assert result.content_complete is False
        assert GAP in {rule for rule, _ in result.content_gaps}
        assert RUNNING in Package.rules(result)

    def test_two_hundred_thousand_open_parentheses_with_nothing_to_act_is_said(
        self, tmp_path: Path
    ) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"(" * 200_000})
        assert BROKEN in Package.rules(result)
        assert GAP not in {rule for rule, _ in result.content_gaps}

    def test_two_hundred_thousand_open_brackets_with_an_act_is_a_gap(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"require('child_process');" + b"[" * 200_000}
        )
        assert GAP in {rule for rule, _ in result.content_gaps}

    def test_a_close_of_the_wrong_kind_is_one_too(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"fetch('https://h.invalid/a');\nconst x = (1];\n"}
        )
        assert GAP in {rule for rule, _ in result.content_gaps}

    def test_a_close_with_nothing_open_is_one_too(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"eval('1');\n})\n"})
        assert GAP in {rule for rule, _ in result.content_gaps}


class TestWhatIsLeftAlone:
    @pytest.mark.parametrize(
        "body",
        [
            b"module.exports = (a, b) => a + b;\n",
            b"const s = '(' + \"[\" ;\nconst r = /[(]/;\nconst t = `${s}(`;\nmodule.exports = [s, r, t];\n",
            b"// ( [ {\n/* ) ] } */\nmodule.exports = {};\n",
            b"const f = async function* () { yield `a${`b${1}`}`; };\nmodule.exports = f;\n",
            b"if (a) { b(); } else { c(); }\nlabel: for (;;) { break label; }\n",
        ],
    )
    def test_a_file_that_closes_every_bracket_is_not_reported(
        self, tmp_path: Path, body: bytes
    ) -> None:
        result = Package.scan(tmp_path, {"index.js": body})
        assert GAP not in {rule for rule, _ in result.content_gaps}
        assert not Package.rules(result) & {BROKEN, RUNNING}

    def test_a_file_nothing_runs_is_not_reported_however_broken(self, tmp_path: Path) -> None:
        result = Package.scan(
            tmp_path, {"index.js": b"module.exports = 1;\n", "unused.js": b"eval(" + b"(" * 50}
        )
        assert not Package.rules(result) & {BROKEN, RUNNING}
        assert GAP not in {rule for rule, _ in result.content_gaps}


class TestAPublishedPackagesMain:
    def test_a_main_that_does_not_close_and_names_an_act_is_a_gap(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"eval(atob('x'));\nfunction f( {\n"})
        assert GAP in {rule for rule, _ in result.content_gaps}
        assert RUNNING in Package.rules(result)

    def test_a_main_that_does_not_close_and_names_nothing_is_said(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(tmp_path, {"index.js": b"(" * 200_000})
        assert BROKEN in Package.rules(result)

    def test_a_main_that_closes_is_not_reported(self, tmp_path: Path) -> None:
        result = Package.scan_tarball(
            tmp_path, {"index.js": b"module.exports = (a, b) => a + b;\n"}
        )
        assert not Package.rules(result) & {BROKEN, RUNNING} and GAP not in {
            r for r, _ in result.content_gaps
        }
