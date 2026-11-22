"""What runs when a consumer imports a published Python package is graded as code that runs unasked
(reviews/pypi-98/10). Every importable module counts, not only the top-level `__init__.py`: a consumer
imports the module that holds the API, and its top level runs then. A function body importing never
calls keeps its grade. The payload decodes to `print(1)`, is assembled at run time and never runs here."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from support import Support

RULE = "SUSPECT.DECODE_EXEC.001"


class ImportKit:
    PAYLOAD = Support.assemble(
        "import base64\n",
        "def _boot():\n    ex",
        "ec(base64.b64",
        "decode('cHJpbnQoMSk='))\n",
    )

    @staticmethod
    def sdist(tmp_path: Path, files: dict[str, str], name: str = "acme") -> Path:
        root = f"{name}-1.0.0"
        members = {
            f"{root}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n",
            f"{root}/setup.py": f"from setuptools import setup\nsetup(name='{name}')\n",
            f"{root}/acme/__init__.py": "",
            **{f"{root}/{k}": v for k, v in files.items()},
        }
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / f"{root}.tar.gz"
        path.write_bytes(buf.getvalue())
        return path

    @staticmethod
    def graded(target: Path) -> list:
        config = Config.default().with_overrides(use_cache=False, offline=True)
        return [f for f in Scanner(config).scan(target).findings if f.rule_id == RULE]


class TestRunsAtImport:
    def test_a_release_named_like_a_test_is_still_imported(self, tmp_path) -> None:
        """`requests_test_test2-2.33.0/src/requests/models.py`: `test` is in the release's own name,
        the root folder an sdist is named after, not a directory of tests -- and it had made every
        module of the release test material, so importing it reached nothing."""
        target = ImportKit.sdist(
            tmp_path, {"acme/client.py": ImportKit.PAYLOAD + "_boot()\n"}, name="acme_test_test2"
        )
        [finding] = ImportKit.graded(target)
        assert finding.severity >= Severity.HIGH
        assert any("imported" in e for e in finding.explanation.escalations)

    def test_a_module_that_runs_it_at_import_is_graded_as_unasked(self, tmp_path) -> None:
        target = ImportKit.sdist(tmp_path, {"acme/client.py": ImportKit.PAYLOAD + "_boot()\n"})
        [finding] = ImportKit.graded(target)
        assert finding.severity >= Severity.HIGH
        assert any("imported" in e for e in finding.explanation.escalations)

    def test_a_body_importing_never_calls_keeps_its_grade(self, tmp_path) -> None:
        target = ImportKit.sdist(tmp_path, {"acme/client.py": ImportKit.PAYLOAD})
        assert all(
            not any("imported" in e for e in f.explanation.escalations)
            for f in ImportKit.graded(target)
        )

    def test_a_test_module_is_not_what_a_consumer_imports(self, tmp_path) -> None:
        target = ImportKit.sdist(
            tmp_path, {"tests/test_client.py": ImportKit.PAYLOAD + "_boot()\n"}
        )
        assert all(
            not any("imported" in e for e in f.explanation.escalations)
            for f in ImportKit.graded(target)
        )
