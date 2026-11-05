"""The names Python code uses for what the analyser looks for: shells, interpreters and runners,
fetch tools and where they download to, base64 decoders, persistence paths, the calls and names that
need no source, write methods, model commits, the size of code a file writes, and the builtin and
reflective names resolution treats specially.
"""

from __future__ import annotations

import re

REFLECTIVE = frozenset({"getattr", "__import__", "globals", "vars", "locals"})
"""Names whose whole purpose is to reach something by a computed name.

Resolved when the name is constant, and reported as dynamic dispatch when it is
not."""


BUILTIN_MODULES = frozenset({"builtins", "__builtin__", "__builtins__"})


WRITE_METHODS = frozenset({"write", "write_text", "write_bytes", "writelines"})


#: Names and attributes the interpreter or platform provides, never an attacker: a command built
#: only from these and literals cannot be running a decoded or downloaded value (`safe_spawn_lines`).
SOURCE_FREE_NAMES = frozenset({"__file__"})


SOURCE_FREE_DOTTED = frozenset(
    {
        "sys.executable",
        "sys.prefix",
        "sys.base_prefix",
        "sys.platform",
        "sys.version",
        "os.sep",
        "os.linesep",
        "os.pathsep",
        "os.name",
        "os.curdir",
    }
)


#: Calls and string methods that return a source-free value when handed only source-free arguments.
SOURCE_FREE_CALLS = frozenset(
    {
        "str",
        "repr",
        "os.getcwd",
        "os.path.join",
        "os.path.dirname",
        "os.path.abspath",
        "os.path.basename",
        "os.path.normpath",
        "os.path.expanduser",
        "shlex.quote",
        "posixpath.join",
        "ntpath.join",
    }
)


SOURCE_FREE_METHODS = frozenset(
    {
        "join",
        "format",
        "upper",
        "lower",
        "strip",
        "rstrip",
        "lstrip",
        "replace",
        "removeprefix",
        "removesuffix",
    }
)
"""Character codes folded from one `map(chr, [...])`; a longer literal list is not read."""


MODEL_COMMIT = re.compile(r"[0-9a-f]{40}")
"""A model repository revision that is a commit, rather than a branch or tag that moves."""


EXECUTABLE_NAME = re.compile(
    r"(?i)\.(?:exe|scr|com|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|msi|dll|sh|app)\b"
)
"""File names that a launch runs as a program."""


PERSISTENCE_PATH = re.compile(
    r"(?:^|/)\.(?:profile|bashrc|bash_profile|bash_login|zshrc|zprofile|zlogin)$"
    r"|LaunchAgents/[^/]{1,200}\.plist$|/crontabs?/|systemd/user/[^/]{1,200}\.service$"
)
"""Files that run their contents at the next login, boot or schedule."""


DOWNLOAD_TO = re.compile(
    r"""(?i)\b(?:curl(?:\.exe)?|wget|invoke-webrequest|iwr)\b[^\n]{0,400}?"""
    r"""\s(?:-o|--output|--output-document|-outfile)\s{1,4}"""
    r"""(?P<target>"[^"]{1,300}"|'[^']{1,300}'|\S{1,300})"""
)
"""A command that downloads to a named file, and that file."""


FETCH_TOOL = re.compile(r"(?i)^\s{0,8}(?:curl|wget|invoke-webrequest|iwr)\b")
"""A command whose output is the download."""


SHELL_NAMES = frozenset(
    {"powershell", "powershell.exe", "pwsh", "sh", "bash", "zsh", "dash", "cmd", "cmd.exe"}
)


RUNNER_WORDS = frozenset(
    {
        "start-process",
        "saps",
        "invoke-item",
        "ii",
        "&",
        # And the wrappers that run the program that follows them. Not `start`, `open` or
        # `xdg-open`: a downloaded report opened for the user is opened, not run.
        "nohup",
        "exec",
        "setsid",
    }
)
"""Verbs whose first argument is the program they run."""


INTERPRETER_NAMES = frozenset(
    {
        "python",
        "python3",
        "python2",
        "python.exe",
        "pythonw",
        "pythonw.exe",
        "py",
        "sh",
        "bash",
        "zsh",
        "dash",
        "node",
        "perl",
        "ruby",
        "php",
        "pwsh",
        "powershell",
        "powershell.exe",
        "cmd",
        "cmd.exe",
        "wscript",
        "cscript",
        "msiexec",
        "rundll32",
        "start",
    }
)
"""Programs whose first non-option argument is the code they run."""


BASE64_DECODERS = frozenset(
    {
        "base64.b64decode",
        "base64.standard_b64decode",
        "base64.urlsafe_b64decode",
        "base64.decodebytes",
    }
)


WRITTEN_CODE_MIN = 16


WRITTEN_CODE_MAX = 64 * 1024
"""A literal shorter than this holds no call worth reading; one longer is not analysed again,
which bounds the cost of a file built from large embedded payloads."""


__all__ = [
    "BASE64_DECODERS",
    "BUILTIN_MODULES",
    "DOWNLOAD_TO",
    "EXECUTABLE_NAME",
    "FETCH_TOOL",
    "INTERPRETER_NAMES",
    "MODEL_COMMIT",
    "PERSISTENCE_PATH",
    "REFLECTIVE",
    "RUNNER_WORDS",
    "SHELL_NAMES",
    "SOURCE_FREE_CALLS",
    "SOURCE_FREE_DOTTED",
    "SOURCE_FREE_METHODS",
    "SOURCE_FREE_NAMES",
    "WRITE_METHODS",
    "WRITTEN_CODE_MAX",
    "WRITTEN_CODE_MIN",
]
