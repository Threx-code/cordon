"""What an MCP server's tool does with the arguments the agent passes it, read as text in every SDK language.

A tool receives its arguments from the agent, and the agent fills them from what the user and the model decided. Three
things a handler can do with them mark a server that works for someone else:

```
  starts the program its input names      execFile(input, ...)   subprocess.run([input, ...])   exec.Command(input)
  runs its input as a shell command       exec.Command("sh", "-c", input)    Command::new("sh").arg("-c").arg(input)
  sends its input to an address in the code, with no credential and no configured value, as the body of a POST
                                          fetch("https://host/in", { method: "POST", body: input })
```

The parameter names are read from the handler as each SDK writes them (a destructured callback, a decorated function, a
request-arguments lookup, a `#[tool(param)]` field); the use of one of them in a call is read from the text around it.
A tool that says in its name or description that it runs commands is doing its job; this reader reports the others.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final

_SAYS_COMMANDS: Final = re.compile(
    r"(?i)exec|run|shell|command|terminal|bash|\bcmd\b|script|process|subprocess|powershell|eval|console|ssh"
)
_DESTRUCTURED: Final = re.compile(
    r"(?:async\s{0,3})?\(\s{0,20}\{\s{0,20}([\w,:=][\w\s,:=]{0,199})\}\s{0,20}(?:,[^)]{0,40})?\)\s{0,20}=>"
)
_ARGUMENTS_BOUND: Final = re.compile(
    r"const\s{1,5}\{\s{0,20}([\w:][\w\s,:]{0,199})\}\s{0,20}=\s{0,20}(?:request\.params\.)?arguments\b"
)
_PY_TOOL: Final = re.compile(
    r"@(?:\w{1,30}\.)?tool\([^)\n]{0,200}\)[ \t]{0,10}\r?\n[ \t]{0,40}(?:async[ \t]{1,3})?def[ \t]{1,3}\w{1,60}\(([^)]{0,300})\)"
)
_GO_ARGUMENT: Final = re.compile(
    r"(?<![\w.])(\w{1,40})(?:\s{0,3},\s{0,3}\w{1,40})?\s{0,3}:?=\s{0,3}(?:req|request)\.(?:Params\.Arguments\[|Require\w+\(|Get\w+\()"
)
_RS_PARAM: Final = re.compile(r"#\[tool\((?:param|aggr)[^)]{0,40}\)\]\s*(?:mut\s+)?(\w+)\s*:")
_REGISTER: Final = re.compile(
    r"server\.tool\(|registerTool\(|\.AddTool\(|@(?:\w+\.)?tool\(|#\[tool\("
)
_STRINGS: Final = re.compile(r"\"([^\"\n]{0,300})\"|'([^'\n]{0,300})'")
_DOCSTRING: Final = re.compile(r"\"\"\"([^\"]{0,300})\"\"\"")
_FUNCTION: Final = re.compile(r"\b(?:def|fn)\s+(\w{1,60})")
_LOCAL: Final = r"(?!(?:127\.|localhost|10\.|192\.168\.|0\.0\.0\.0))"
_AUTH: Final = re.compile(
    r"(?i)authorization|bearer|api[_-]?key|x-api|token|secret|password|process\.env|os\.environ|getenv|env::var|"
    r"\.env\b|config\.|settings\."
)


class McpInputFlows:
    """`scan(text)`: (rule id, character offset) of each use of a tool's arguments that marks a server working for
    someone else."""

    PROGRAM: ClassVar[str] = "SUSPECT.MCP.INPUT_PROGRAM.001"
    SHELL: ClassVar[str] = "SUSPECT.MCP.INPUT_SHELL.001"
    DROPPED: ClassVar[str] = "SUSPECT.MCP.INPUT_DROPPED.001"

    @staticmethod
    def parameters(text: str) -> set[str]:
        """The names of the arguments the tools of a source file receive."""
        names: set[str] = set()
        for found in _DESTRUCTURED.finditer(text):
            names |= {
                part.split(":")[-1].split("=")[0].strip() for part in found.group(1).split(",")
            }
        for found in _ARGUMENTS_BOUND.finditer(text):
            names |= {part.split(":")[-1].strip() for part in found.group(1).split(",")}
        for found in _PY_TOOL.finditer(text):
            for part in found.group(1).split(","):
                name = part.split(":")[0].split("=")[0].strip()
                if name and name not in ("self", "cls", "ctx", "context"):
                    names.add(name)
        names |= {found.group(1) for found in _GO_ARGUMENT.finditer(text)}
        names |= {found.group(1) for found in _RS_PARAM.finditer(text)}
        return {
            n
            for n in names
            if re.fullmatch(r"[A-Za-z_]\w{0,40}", n) and n not in ("_", "ctx", "req", "request")
        }

    @classmethod
    def scan(cls, text: str) -> list[tuple[str, int]]:
        """Each such use of a tool's arguments in the file, at most three of each kind."""
        if len(text) > 2_000_000:
            return []
        names = cls.parameters(text)
        if not names:
            return []
        word = "(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\b"
        out: list[tuple[str, int]] = []
        out += [(cls.PROGRAM, o) for o in cls._program(text, word)[:3]]
        out += [(cls.SHELL, o) for o in cls._shell(text, word)[:3]]
        out += [(cls.DROPPED, o) for o in cls._dropped(text, word)[:3]]
        return out

    @staticmethod
    def _says(text: str, at: int) -> bool:
        """Whether the tool whose handler holds the call says, in its name or description, that it runs commands: the
        strings of its registration (up to where its callback or its signature begins) and a docstring after it."""
        marks = list(_REGISTER.finditer(text, max(at - 1500, 0), at))
        if not marks:
            return False
        head = text[marks[-1].start() : min(marks[-1].start() + 400, at)]
        ends = [
            i
            for i in (head.find("=>"), head.find(") -> "), head.find(")]"), head.find("):"))
            if i > 0
        ]
        said = " ".join(a or b for a, b in _STRINGS.findall(head[: min(ends)] if ends else head))
        docstring = _DOCSTRING.search(head)
        name = _FUNCTION.search(head)
        return bool(
            _SAYS_COMMANDS.search(said)
            or (docstring is not None and _SAYS_COMMANDS.search(docstring.group(1)))
            or (name is not None and _SAYS_COMMANDS.search(name.group(1)))
        )

    @classmethod
    def _program(cls, text: str, word: str) -> list[int]:
        """The program started, without a shell, is a value the agent passes."""
        shapes = re.compile(
            r"\b(?:execFile\w{0,8}|spawn\w{0,4})\(\s*"
            + word
            + r"|subprocess\.(?:run|Popen|call|check_output|check_call)\(\s*\[\s*"
            + word
            + r"|\bos\.exec\w{1,3}\(\s*"
            + word
            + r"|\bexec\.Command(?:Context)?\(\s*(?:ctx\s*,\s*)?"
            + word
            + r"|\bCommand::new\(\s*&?"
            + word
        )
        return [m.start() for m in shapes.finditer(text) if not cls._says(text, m.start())]

    @classmethod
    def _shell(cls, text: str, word: str) -> list[int]:
        """The shell is handed a value the agent passes: Go, Rust and the other languages the handler readers of
        JavaScript and Python do not cover."""
        shapes = re.compile(
            r"\bexec\.Command(?:Context)?\(\s*(?:ctx\s*,\s*)?\"(?:sh|bash|cmd|powershell)\"\s*,\s*\"(?:-c|/c|-Command)\"\s*,\s*[^)\n]{0,40}"
            + word
            + r"|\bCommand::new\(\s*\"(?:sh|bash|cmd|powershell)\"\s*\)\s*\.args?\(\s*\[?\s*\"(?:-c|/c|-Command)\"[^;\n]{0,80}"
            + word
        )
        return [m.start() for m in shapes.finditer(text) if not cls._says(text, m.start())]

    @classmethod
    def _dropped(cls, text: str, word: str) -> list[int]:
        """The argument is the body of a request to an address in the code, and nothing in the call says who is
        asking (no credential, no configured value): a drop, not a call to a service."""
        shapes = re.compile(
            r"(?:\bfetch\(|requests\.(?:post|put)\(|http\.Post\(|\.(?:post|put)\(|urlopen\(\s*(?:urllib\.request\.)?Request\()"
            r"\s*[\"'`]https?://" + _LOCAL + r"[\w.-]{3,80}[^\n]{0,400}"
        )
        out = []
        for m in shapes.finditer(text):
            window = text[m.start() : m.end() + 300]
            body = re.search(
                r"(?:body\s*[:=]\s*(?:JSON\.stringify\(\s*)?|data\s*=\s*|json\s*=\s*|NewReader\(\s*|\.body\(\s*)\W{0,3}"
                + word,
                window,
            )
            if body is not None and not _AUTH.search(window):
                out.append(m.start())
        return out


__all__ = ["McpInputFlows"]
