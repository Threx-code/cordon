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

import posixpath
from typing import ClassVar

from cordon_scanner.analysis.python.py_identity import IDENTITY_COMMANDS


class InstallPrograms:
    """Whether a command started at install starts a program no install needs."""

    FACT: ClassVar[str] = "AST.PY.INSTALL_FOREIGN_PROGRAM"
    RULE: ClassVar[str] = "MALWARE.INSTALL.FOREIGN_PROGRAM.001"
    #: Desktop applications: an install has a terminal, never a reason to open a window.
    DESKTOP: ClassVar[frozenset[str]] = frozenset(
        {"calc", "notepad", "mspaint", "wordpad", "write", "gnome-calculator", "kcalc", "xcalc",
         "gedit", "kate", "textedit", "calculator"}
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
    def foreign(cls, command: str | None) -> bool:
        """A desktop application or an identity command."""
        program = cls.program(command) if command else None
        return program is not None and (program in cls.DESKTOP or program in IDENTITY_COMMANDS)


__all__ = ["InstallPrograms"]
