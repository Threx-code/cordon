"""A `setup.py` is an install hook; only what it runs is escalated (review 98, FP-5).

poetry-core writes a `setup.py` that inlines the whole README as `long_description`, and every
suspicious finding in an install hook used to become HIGH -- so `pfzy` and `grpc-interceptor` were
blocked as obfuscated. The long lines are inert: base64 of digest bytes.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

LONG = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 120
#: High-entropy and harmless: base64 of digest bytes, which decodes to nothing that runs. A real
#: inlined README reaches the same entropy; this makes the rule fire in both tests for certain.
NOISE = base64.b64encode(
    b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(200))
).decode()


class SetupKit:
    @staticmethod
    def longline(tmp_path: Path, setup_py: str):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("p-1.0.0/PKG-INFO", "Metadata-Version: 2.1\nName: p\nVersion: 1.0.0\n"),
                ("p-1.0.0/setup.py", setup_py),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tar.gz"
        target.write_bytes(buffer.getvalue())
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.LONGLINE.001"]


class TestALongLineInSetupPy:
    def test_an_inlined_readme_is_not_escalated(self, tmp_path: Path) -> None:
        setup = f"from setuptools import setup\nsetup_kwargs = {{'long_description': '{NOISE}'}}\nsetup(**setup_kwargs)\n"
        found = SetupKit.longline(tmp_path, setup)
        assert found, "the rule must fire, or this test proves nothing"
        assert all(f.severity < Severity.HIGH for f in found)

    def test_an_executed_one_still_is(self, tmp_path: Path) -> None:
        setup = f"from setuptools import setup\nexec(\"_ = '{NOISE}'\")\nsetup(name='p')\n"
        found = SetupKit.longline(tmp_path, setup)
        assert found and all(f.severity >= Severity.HIGH for f in found)

    def test_one_assigned_and_executed_later_still_is(self, tmp_path: Path) -> None:
        setup = (
            f"from setuptools import setup\nblob = \"_ = '{NOISE}'\"\nexec(blob)\nsetup(name='p')\n"
        )
        found = SetupKit.longline(tmp_path, setup)
        assert found and all(f.severity >= Severity.HIGH for f in found)
