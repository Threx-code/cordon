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
from typing import ClassVar

from cordon_scanner import Scanner
from cordon_scanner.engine.pipeline.hooks import BuildRoots
from cordon_scanner.foundation.config.settings import Config
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


# pip builds an sdist by running the `setup.py` beside its `PKG-INFO` and no other
# (`BuildRoots.not_a_build_root`): a deeper one is not install-time code unless the root one imports it.
class RootKit:
    PROFILE: ClassVar[str] = (
        "import os\n"
        "with open(os.path.expanduser('~/.bashrc'), 'a') as profile:\n"
        "    profile.write('export PATH=$PATH:/opt/demo/bin\\n')\n"
    )
    PKG_INFO: ClassVar[bytes] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"

    @staticmethod
    def sdist(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, body in files.items():
                data = body.encode() if isinstance(body, str) else body
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / "demo-1.0.tar.gz"
        path.write_bytes(buffer.getvalue())
        return path

    @staticmethod
    def persistence(path: Path) -> list[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(path)
        return [
            f.location.path for f in result.findings if f.rule_id == "MALWARE.INSTALL.PERSIST.001"
        ]


class TestTheBuildRoot:
    @staticmethod
    def noted(*paths: str) -> set[str]:
        seen: set[str] = set()
        for path in paths:
            BuildRoots.note(path, seen)
        return seen

    def test_only_the_setup_beside_pkg_info_is_the_build_script(self) -> None:
        seen = self.noted(
            "demo-1.0/PKG-INFO", "demo-1.0/demo.egg-info/PKG-INFO", "demo-1.0/setup.py"
        )
        assert not BuildRoots.not_a_build_root("demo-1.0", seen)
        assert BuildRoots.not_a_build_root("demo-1.0/Lib/site-packages/numpy/core", seen)
        assert BuildRoots.not_a_build_root("demo-1.0/src/demo", seen)

    def test_an_egg_info_pkg_info_is_not_an_sdist_root(self) -> None:
        seen = self.noted("demo-1.0/demo.egg-info/PKG-INFO")
        assert not BuildRoots.not_a_build_root("demo-1.0/tools", seen), (
            "no sdist root: nothing changes"
        )

    def test_a_repository_without_pkg_info_keeps_every_setup(self) -> None:
        seen = self.noted("tools/__init__.py")
        assert not BuildRoots.not_a_build_root("build/helpers", seen)
        assert BuildRoots.not_a_build_root("tools", seen), "a package directory is still not a root"


class TestAScanOfAnSdist:
    def test_a_profile_written_by_the_root_setup_still_blocks(self, tmp_path: Path) -> None:
        path = RootKit.sdist(tmp_path, {"PKG-INFO": RootKit.PKG_INFO, "setup.py": RootKit.PROFILE})
        assert RootKit.persistence(path)

    def test_the_same_code_in_a_nested_setup_module_is_not_install_time(
        self, tmp_path: Path
    ) -> None:
        path = RootKit.sdist(
            tmp_path,
            {
                "PKG-INFO": RootKit.PKG_INFO,
                "pyproject.toml": '[project]\nname = "demo"\nversion = "1.0"\n',
                "cli/setup.py": RootKit.PROFILE,
            },
        )
        assert RootKit.persistence(path) == []
