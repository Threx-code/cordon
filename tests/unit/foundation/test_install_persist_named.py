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


class TestNamedInCodeNotWritten:
    """A setup.py's literals followed to where they go (`analysis/python/py_persist.py`): a profile
    named and only read, listed, matched or shown is no foothold; one that reaches a write, a copy
    or a process is (review 98, real skills)."""

    @pytest.mark.parametrize(
        "body",
        [
            # The profiles a key is looked up in, read.
            'PROFILES = [".zshrc", ".bashrc", ".profile"]\n'
            "for p in PROFILES:\n"
            "    f = os.path.join(os.path.expanduser('~'), p)\n"
            "    if os.path.exists(f):\n"
            "        text = open(f).read()\n",
            # A scanner's table of what it looks for.
            'PATTERNS = {r"LaunchAgents|LaunchDaemons": "macOS persistence"}\n'
            "hits = [n for p, n in PATTERNS.items() if re.search(p, source)]\n",
            # The crontab listed, as evidence.
            'out = subprocess.run(["crontab", "-l"], capture_output=True).stdout\n',
            # Advice in an error.
            'raise RuntimeError("set MINIMAX_KEY in ~/.zshrc or ~/.bashrc")\n',
            # The crontab's listing saved to an evidence file: a process's output is not its
            # command.
            'r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)\n'
            "with open('evidence/crontab.txt', 'w') as f:\n"
            "    f.write(r.stdout or 'no crontab')\n",
            # Read-only commands from a table, each run and written as its evidence's header.
            'SOURCES = [{"cmd": ["crontab -l", "ls /etc/cron.d/"]}]\n'
            "for s in SOURCES:\n"
            "    for c in s['cmd']:\n"
            "        p = subprocess.run(c.split(), capture_output=True, text=True)\n"
            "        open('out.txt', 'w').write(f'# Command: {c}\\n' + p.stdout)\n",
            # A pattern table kept in the file's own record and counted.
            "from dataclasses import dataclass\n"
            "@dataclass\n"
            "class Finding:\n"
            "    pattern: str\n"
            'TABLE = {r"crontab\\s+-": "Crontab modification"}\n'
            "found = [Finding(p) for p in TABLE if re.search(p, source)]\n"
            "print(sum(1 for f in found if f.pattern))\n",
        ],
    )
    def test_a_location_named_and_never_written(self, tmp_path, body) -> None:
        setup = f"import os, re, subprocess\nfrom setuptools import setup\n{body}setup(name='x')\n"
        assert RULE not in PersistHelpers.rules(tmp_path, {"setup.py": setup})

    @pytest.mark.parametrize(
        "body",
        [
            # A list of footholds, each appended to.
            'TARGETS = ["/etc/profile", "~/.bashrc"]\n'
            "for t in TARGETS:\n"
            "    with open(os.path.expanduser(t), 'a') as f:\n"
            "        f.write('x\\n')\n",
            # A helper of the file's own that writes what it is given.
            "def put(path, line):\n"
            "    open(path, 'a').write(line)\n"
            "put(os.path.expanduser('~/.zshrc'), 'x')\n",
            # A unit copied into place.
            "shutil.copy('agent.plist', os.path.expanduser('~/Library/LaunchAgents/a.plist'))\n",
            # A crontab installed through a process.
            "subprocess.run('(crontab -l; echo \"@reboot x\") | crontab -', shell=True)\n",
            # A path held on an object and written later.
            "class I:\n"
            "    def __init__(self):\n"
            "        self.rc = os.path.expanduser('~/.bash_profile')\n"
            "    def go(self):\n"
            "        with open(self.rc, mode='a') as f:\n"
            "            f.write('x')\n"
            "I().go()\n",
            # Built into a class of the file that does its own work with it.
            "class Unit:\n"
            "    def __init__(self, where):\n"
            "        open(where, 'w').write('[Install]')\n"
            "Unit('/etc/systemd/system/agent.service')\n",
            # A table command that acts: `find -exec` is not a listing.
            'CMDS = ["find /etc/cron.d -name x -exec cp payload {} +"]\n'
            "for c in CMDS:\n"
            "    subprocess.run(c, shell=True)\n",
            # A table command that installs.
            'CMDS = ["crontab -", "ls /tmp"]\n'
            "for c in CMDS:\n"
            "    subprocess.run(c.split(), input='@reboot x')\n",
        ],
    )
    def test_a_location_written_still_blocks(self, tmp_path, body) -> None:
        setup = (
            f"import os, shutil, subprocess\nfrom setuptools import setup\n{body}setup(name='x')\n"
        )
        assert RULE in PersistHelpers.rules(tmp_path, {"setup.py": setup})
