"""Whether what a file reads from a credential store can reach its network call.

`SUSPECT.EXFIL.CREDENTIAL_STORE.001` pairs a read of a credential store with an outbound call
within two hundred lines. Theft is the store's content carried into the call; a dotfiles script
that installs a tool with `curl | bash` forty lines after reading `~/.ssh/config` for a host name
carries nothing. Measured on the review-98 corpora: the rule was the only blocking finding on
181 of 227 benign units it fired on, and on 11 of 147 malware samples.

The test is textual and language-agnostic on purpose: it reads shell, Python, JavaScript, Go,
Ruby and Nix strings alike, and errs towards a flow. A name assigned on a line that reads the
store is tainted; a name assigned from a tainted one is tainted, as is a loop variable over one,
a `with ... as` target, a callback parameter, and a function that returns one. A flow is a
tainted name, or the store read itself, on the network call's line or the few lines its
arguments run on. Anything this cannot follow -- a name it never saw assigned -- is no flow,
and the finding is recorded below the gate rather than dropped.
"""

from __future__ import annotations

import re

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_ASSIGNED = re.compile(
    r"^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?|const\s+|let\s+|var\s+|my\s+)?"
    r"(?P<target>[A-Za-z_$][\w$.,\s{}\[\]'\"]{0,120}?)\s*(?::=|(?<![=!<>+\-*/%&|^])=(?![=>~]))"
)
"""What a line assigns: `x = ...`, `a, b := ...`, `const {a, b} = ...`, `name=$(cat ...)`."""

_BOUND = re.compile(
    r"\bas\s{1,4}(?P<as>[A-Za-z_]\w{0,60})"
    r"|\bfor\s{1,4}(?:\(\s{0,4}(?:const|let|var)\s{1,4})?"
    r"(?P<for>[A-Za-z_]\w{0,60}(?:\s{0,4},\s{0,4}[A-Za-z_]\w{0,60}){0,8})\s{1,4}(?:in|of)\b"
    r"|\(?\s{0,4}(?P<arrow>[A-Za-z_]\w{0,60}(?:\s{0,4},\s{0,4}[A-Za-z_]\w{0,60}){0,8})\s{0,4}\)?\s{0,4}=>"
    r"|\bfunction\s{0,4}\(\s{0,4}(?P<callback>[A-Za-z_]\w{0,60})"
    r"|\bread\s{1,4}(?:-\w{1,10}\s{1,4}){0,4}(?P<read>[A-Za-z_]\w{0,60})"
)
"""Names a line binds other than by assignment."""

_FUNCTION = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|func|sub)\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)"
    r"|^\s*(?P<shell>[A-Za-z_][\w-]*)\s*\(\s*\)\s*\{"
    r"|^\s*(?:const|let|var)\s+(?P<arrowfn>[A-Za-z_]\w*)\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>"
)
"""Where a function's body begins, and its name."""

_ARGUMENT = re.compile(r"(?<![\w.$])([A-Za-z_]\w*)(?![\w$]|\s*[.(])")
"""A bare name, not a callee (`f(`), not a receiver (`os.`), not an attribute (`.path`)."""

_FILLED = re.compile(
    r"([A-Za-z_]\w*)\s*\.\s*(?:append|extend|write|writelines|writerow|writerows|update|add|"
    r"insert|push|put|setdefault|set|concat|join)\s*\("
)
"""The receiver of a call that puts something into it."""

_PATH_LITERAL = re.compile(
    r"\"([^\"\n:]{1,200}[./\\][^\"\n:]{1,200})\"|'([^'\n:]{1,200}[./\\][^'\n:]{1,200})'"
)
"""A quoted file name or path (no scheme, so no URL)."""

_LITERAL_MARK = "\x00"
"""Prefix that keeps a path literal apart from an identifier in the tainted set."""

_KEYWORDS = frozenset(
    {
        "if", "else", "for", "while", "in", "of", "return", "const", "let", "var", "def",
        "function", "func", "true", "false", "True", "False", "None", "null", "nil", "self",
        "this", "and", "or", "not", "is", "with", "as", "then", "do", "done", "fi", "echo",
        "local", "export", "await", "async", "new", "import", "from", "string", "str",
    }
)  # fmt: skip

CALL_SPAN = 4
"""Lines a network call's arguments may run on after the line it starts on."""


class StoreFlow:
    """The flow test. See the module docstring."""

    @staticmethod
    def reaches(text: str, store_lines: list[int], egress_lines: list[int]) -> bool:
        """Whether anything read on a store line (1-based) can reach a call on an egress line."""
        lines = text.split("\n")
        if not store_lines or not egress_lines:
            return False
        # A call on the line that reads the store, or the line beside it: `cat ~/.aws/credentials |
        # curl -d @- ...`, `requests.post(u, files={"f": open(STORE)})`.
        if any(abs(s - e) <= 1 for s in store_lines for e in egress_lines):
            return True
        tainted: set[str] = set()
        for number in store_lines:
            if 1 <= number <= len(lines):
                tainted |= StoreFlow._names_bound(lines[number - 1])
                tainted |= StoreFlow._enclosing_function_if_returned(
                    lines, number, lines[number - 1]
                )
        for _ in range(6):
            grown = set(tainted)
            for index, line in enumerate(lines, start=1):
                if not StoreFlow._mentions(line, grown):
                    continue
                grown |= StoreFlow._names_bound(line)
                grown |= StoreFlow._enclosing_function_if_returned(lines, index, line)
            if grown == tainted:
                break
            tainted = grown
        if not tainted:
            return False
        for number in egress_lines:
            call = lines[max(0, number - 1) : min(len(lines), number + CALL_SPAN)]
            if any(StoreFlow._mentions(line, tainted) for line in call):
                return True
        return False

    @staticmethod
    def _mentions(line: str, names: set[str]) -> bool:
        if not names:
            return False
        if any(token in names for token in _IDENTIFIER.findall(line)):
            return True
        return any(
            _LITERAL_MARK + (found.group(1) or found.group(2)) in names
            for found in _PATH_LITERAL.finditer(line)
        )

    @staticmethod
    def _names_bound(line: str) -> set[str]:
        names: set[str] = set()
        assigned = _ASSIGNED.match(line)
        if assigned:
            names |= set(_IDENTIFIER.findall(assigned.group("target")))
        for bound in _BOUND.finditer(line):
            for group in bound.groupdict().values():
                if group:
                    names |= set(_IDENTIFIER.findall(group))
        # And the plain names the line hands a call: `shutil.copy(profile, staging)` puts the
        # store's content in `staging`, `fs.writeFileSync(out, data)` in `out`. A callee, a
        # module or an attribute is not a value the line fills.
        for argument in _ARGUMENT.finditer(line):
            names.add(argument.group(1))
        # A collection or a file the line fills: `rows.append(row)`, `out.write(data)`.
        for receiver in _FILLED.finditer(line):
            names.add(receiver.group(1))
        # And a file named by a literal, which carries the content to whatever opens it later:
        # `open("passwords.txt", "w")` here, `files={"f": open("passwords.txt", "rb")}` there.
        for literal in _PATH_LITERAL.finditer(line):
            names.add(_LITERAL_MARK + (literal.group(1) or literal.group(2)))
        return {name for name in names if name not in _KEYWORDS}

    @staticmethod
    def _enclosing_function_if_returned(lines: list[str], number: int, line: str) -> set[str]:
        """The name of the function a line returns from, when it returns what it reads."""
        if not re.search(r"\breturn\b|\becho\b|\bprint\b|\bresolve\s*\(", line):
            return set()
        for index in range(number - 1, -1, -1):
            found = _FUNCTION.match(lines[index])
            if found:
                name = found.group("name") or found.group("shell") or found.group("arrowfn")
                return {name} if name and name not in _KEYWORDS else set()
        return set()
