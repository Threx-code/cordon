"""A program started so that the user does not see it.

A program that registers itself to start at login and runs with no window is one the user did not
choose to keep: a `.vbs` launched through `wscript`, `CREATE_NO_WINDOW` or
`DETACHED_PROCESS` creation flags, `pythonw`, `nohup ... &`, PowerShell's `-WindowStyle Hidden`. A desktop
application that autostarts shows a window; a tray tool shows an icon. Hidden is the stealth part, so
this records the lines (not `STARTF_USESHOWWINDOW` or `SW_HIDE` on a startup-info structure: 27 and 5 of the 16,274 benign
units set them to keep a console from flashing) that ask for it, and `persist_runs.py` relates them to a persistence write.

`lines` returns the line of each name, string or flag that asks for a hidden launch.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

#: The script hosts and hidden-window forms, without the creation flags and without `pythonw` alone: a tool
#: that registers its own console entry point with `pythonw` is not starting a script it brought.
SCRIPT_HOST_TEXT: Final = re.compile(
    r"(?i)\bwscript(?:\.exe)?\b|\bcscript(?:\.exe)?\b|\.(?:vbs|wsf|hta)\b|\bwindowstyle[ =]{1,3}hidden\b"
)
HIDDEN_TEXT: Final = re.compile(
    r"(?i)\bpythonw(?:\.exe)?\b|\bwscript(?:\.exe)?\b|\bcscript(?:\.exe)?\b|\.vbs\b|\bnohup\b"
    r"|\bwindowstyle[ =]{1,3}hidden\b|\bstart /b\b"
)


class HiddenLaunch:
    """The hidden-launch requests in one syntax tree."""

    NAMES: ClassVar[frozenset[str]] = frozenset({"CREATE_NO_WINDOW", "DETACHED_PROCESS"})

    @classmethod
    def script_host_lines(cls, tree: ast.AST) -> list[int]:
        """The lines that name a script host or ask for a hidden window with a script: a `.vbs` run by
        `wscript`, `-WindowStyle Hidden`."""
        return sorted(
            {
                n.lineno
                for n in ast.walk(tree)
                if isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and SCRIPT_HOST_TEXT.search(n.value)
            }
        )

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        out: set[int] = set()
        for node in ast.walk(tree):
            if (
                (isinstance(node, ast.Name) and node.id in cls.NAMES)
                or (isinstance(node, ast.Attribute) and node.attr in cls.NAMES)
                or (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and HIDDEN_TEXT.search(node.value)
                )
            ):
                out.add(node.lineno)
        return sorted(out)


__all__ = ["HiddenLaunch"]
