"""DataDog's unpacked releases repacked as the artefact the registry served (review 98)."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))

from run import Harness


class AsPublishedHelpers:
    @staticmethod
    def sample(tmp_path: Path, members: dict[str, str]) -> Path:
        archive = tmp_path / "sample.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for name, text in members.items():
                bundle.writestr(name, text)
        return archive


class TestAsPublished:
    def test_an_npm_package_folder_becomes_a_tarball(self, tmp_path) -> None:
        archive = AsPublishedHelpers.sample(
            tmp_path,
            {
                "x/package_info-x-1.0.0.json": "{}",
                "x/package/package.json": '{"name": "x", "version": "1.0.0"}',
                "x/package/index.js": "module.exports = 1;\n",
            },
        )
        out = Harness._datadog_as_published(archive, tmp_path / "work")
        assert out is not None and out.name.endswith(".tgz")
        with tarfile.open(out) as tgz:
            assert sorted(tgz.getnames()) == ["package/index.js", "package/package.json"]

    def test_a_wheel_tree_with_doubled_paths_becomes_a_wheel(self, tmp_path) -> None:
        archive = AsPublishedHelpers.sample(
            tmp_path,
            {
                "s/m/__init__.py/m/__init__.py": "x = 1\n",
                "s/m-1.0.dist-info/METADATA/m-1.0.dist-info/METADATA": "Name: m\n",
            },
        )
        out = Harness._datadog_as_published(archive, tmp_path / "work")
        assert out is not None and out.name == "m-1.0-py3-none-any.whl"
        with zipfile.ZipFile(out) as wheel:
            assert sorted(wheel.namelist()) == ["m-1.0.dist-info/METADATA", "m/__init__.py"]

    def test_anything_else_stays_a_folder(self, tmp_path) -> None:
        archive = AsPublishedHelpers.sample(tmp_path, {"skill/SKILL.md": "# s\n"})
        out = Harness._datadog_as_published(archive, tmp_path / "work")
        assert out is not None and out.is_dir()
