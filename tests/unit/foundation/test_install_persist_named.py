"""`MALWARE.INSTALL.PERSIST.001` is for a foothold written, not one named (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config

RULE = "MALWARE.INSTALL.PERSIST.001"


class PersistHelpers:
    @staticmethod
    def rules(tmp_path, files: dict[str, str]) -> set[str]:
        for name, text in files.items():
            (tmp_path / name).write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestNamedNotWritten:
    @pytest.mark.parametrize(
        "setup",
        [
            'from setuptools import setup\nsetup(name="x", install_requires=["python-crontab>=2"])\n',
            'from setuptools import setup\nsetup(name="x", long_description="Add it to ~/.zshrc")\n',
            "import logging\nfrom setuptools import setup\n"
            'logging.warning("then add eval to ~/.bashrc")\nsetup(name="x")\n',
        ],
    )
    def test_a_setup_script_naming_a_profile_is_not_planting_one(self, tmp_path, setup) -> None:
        assert RULE not in PersistHelpers.rules(tmp_path, {"setup.py": setup})

    def test_a_setup_script_writing_one_is(self, tmp_path) -> None:
        setup = (
            "import os\nfrom setuptools import setup\n"
            'open(os.path.expanduser("~/.bashrc"), "a").write("alias ll=ls\\n")\n'
            'setup(name="x")\n'
        )
        assert RULE in PersistHelpers.rules(tmp_path, {"setup.py": setup})

    def test_a_container_build_changes_the_image_not_the_host(self, tmp_path) -> None:
        dockerfile = (
            "FROM debian:12\nRUN useradd -m app && echo 'export X=1' >> /home/app/.profile\n"
        )
        assert RULE not in PersistHelpers.rules(tmp_path, {"Dockerfile": dockerfile})
