"""setup() is packaging metadata, not a filesystem write (census D).

A persistence word that reaches `setup()` as metadata -- a `long_description` string, a package
name -- is named, not planted; `pip install` runs no write there. The one `setup()` argument that
does place files at install is `data_files`, which pip copies to the directory each `(dir, [files])`
pair names, so a unit dropped there stays a finding. The foothold is the write, not `setup()`.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

RULE = "MALWARE.INSTALL.PERSIST.001"


class TestSetupMetadataNotAWrite:
    @staticmethod
    def rules(tmp_path: Path, setup: str) -> set[str]:
        (tmp_path / "setup.py").write_text(setup, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}

    def test_long_description_in_a_kwargs_dict_is_not_planting(self, tmp_path: Path) -> None:
        # poetry-style setup.py: the README is a long_description string unpacked into setup().
        # boltlight, backend.ai-cli carry a systemd mention there and planted nothing.
        setup = (
            "from setuptools import setup\n"
            "kwargs = {'name': 'x', 'long_description': 'Run it as a systemd/user unit.'}\n"
            "setup(**kwargs)\n"
        )
        assert RULE not in self.rules(tmp_path, setup)

    def test_data_files_placing_a_unit_is_still_a_write(self, tmp_path: Path) -> None:
        # data_files is the one setup() argument that copies files to a target dir at install, so a
        # systemd unit dropped there is a real foothold and stays a finding.
        setup = (
            "from setuptools import setup\n"
            "setup(name='x', data_files=[('/usr/lib/systemd/system', ['deploy/x.service'])])\n"
        )
        assert RULE in self.rules(tmp_path, setup)

    def test_an_executable_write_in_setup_still_plants(self, tmp_path: Path) -> None:
        # The foothold is the write, not setup(): open(.bashrc, "a") stays a finding (djanga shape).
        setup = (
            "import os\n"
            "from setuptools import setup\n"
            'open(os.path.expanduser("~/.bashrc"), "a").write("~/.drv &\\n")\n'
            "setup(name='x')\n"
        )
        assert RULE in self.rules(tmp_path, setup)
