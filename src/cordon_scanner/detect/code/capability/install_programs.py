"""Programs an install has no reason to start (install-time acts, group B, 2026-11-10).

A `setup.py` or a wired install command runs build tooling: compilers, build systems, git,
package managers, interpreters. Across 50,010 benign PyPI sdists, 1,300 setup.py files start a
program and none starts a desktop application or a command whose whole output is who and where
the machine is. A calculator or an editor started at install is a proof that the install runs the
author's code on the installer's desktop; `id`, `whoami` and `hostname` at install are the first
step of a reconnaissance callback. Either is the install doing something that is not installing.
The program is read from the command the analyser resolved, through a shell wrapper (`cmd /c`,
`sh -c`, `start`), and only where the install hook reaches the line.
"""

from __future__ import annotations

import dataclasses
import posixpath
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.py_identity import IDENTITY_COMMANDS
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.analysis.python.pyfacts import AstHit
    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.detect.code.capability.hits import CapabilityHit


class InstallPrograms:
    """Whether a command started at install starts a program no install needs."""

    FACT: ClassVar[str] = "AST.PY.INSTALL_FOREIGN_PROGRAM"
    RULE: ClassVar[str] = "MALWARE.INSTALL.FOREIGN_PROGRAM.001"
    #: Desktop applications: an install has a terminal, never a reason to open a window.
    DESKTOP: ClassVar[frozenset[str]] = frozenset(
        {"calc", "notepad", "mspaint", "wordpad", "write", "gnome-calculator", "kcalc", "xcalc",
         "gedit", "kate", "textedit", "calculator"}
    )  # fmt: skip
    #: Commands that list who, where and what the machine is, and what is on it: the reconnaissance
    #: that `id` and `whoami` start. Across the 7,800 benign setup.py files of the gate none starts
    #: one (`echo` is not here: three of them print a message and it stays a harmless command).
    RECON: ClassVar[frozenset[str]] = frozenset(
        {"ls", "dir", "cat", "type", "set", "pwd", "printenv", "ipconfig", "ifconfig", "netstat", "arp", "route", "ps",
         "tasklist", "systeminfo", "ver", "uname", "lsb_release", "who", "w", "last", "users",
         "df", "mount", "nslookup", "net", "tree", "getent", "lscpu", "lsblk", "lsusb", "dmidecode"}
    )  # fmt: skip
    #: Wrappers whose argument is the program that really runs.
    WRAPPERS: ClassVar[frozenset[str]] = frozenset(
        {"cmd", "sh", "bash", "zsh", "powershell", "pwsh", "start", "nohup", "env", "open"}
    )
    WRAPPER_FLAGS: ClassVar[frozenset[str]] = frozenset({"/c", "/k", "-c", "-a", "/b", "-command"})

    @classmethod
    def program(cls, command: str) -> str | None:
        """The program a command starts, past any shell wrapper, lower-cased, without `.exe`."""
        words = command.replace("\\", "/").split()
        for word in words:
            raw = word.strip("\"'").lower()
            if not raw or raw in cls.WRAPPER_FLAGS:
                continue
            name = posixpath.basename(raw).removesuffix(".exe")
            if name in cls.WRAPPERS:
                continue
            return name
        return None

    @classmethod
    def hits(
        cls,
        facts: Sequence[tuple[CapabilityHit, AstHit]],
        path: str,
        ctx: ScanContext,
        loaded: Callable[[], frozenset[int]],
    ) -> list[CapabilityHit]:
        """The fact beside each process start of a foreign program where the install reaches, or
        at the module level of an import entry. The command written out whole is the evidence
        here, not an excuse (`fixed`)."""
        out: list[CapabilityHit] = []
        lines: frozenset[int] | None = None
        for labelled, hit in facts:
            if hit.capability is not Capability.SPAWN or not cls.foreign(hit.command):
                continue
            if not ctx.install_hook_reaches(path, hit.line):
                if path not in ctx.import_entry_paths:
                    continue
                lines = loaded() if lines is None else lines
                if hit.line not in lines:
                    continue
            out.append(dataclasses.replace(labelled, rule_id=cls.FACT, fixed=False))
        return out

    @classmethod
    def foreign(cls, command: str | None) -> bool:
        """A desktop application, an identity command or a command that surveys the machine."""
        program = cls.program(command) if command else None
        return program is not None and (
            program in cls.DESKTOP or program in IDENTITY_COMMANDS or program in cls.RECON
        )


__all__ = ["InstallPrograms"]
