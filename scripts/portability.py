#!/usr/bin/env python3
"""Code that works on the machine it was written on and nowhere else, found before a push.

Every one of these reached CI from a green local run, and each failed only on another
platform: Windows (the platform code page, backslash paths, files another process holds),
macOS (`~/Library/Application Support`), or a runner whose environment differs from a
developer's (`XDG_CONFIG_HOME`, pytest's import path). Each check names the incident it
exists for, so a finding can be judged rather than obeyed.

    python scripts/portability.py            # report and exit 1 on any finding
    python scripts/portability.py --list     # what each check looks for

Standard library only, and read-only: it parses source, it never runs it.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNED = ("src", "tests", "scripts", "bench")
SKIPPED_PARTS = {"cases", "corpus", "__pycache__", "data", ".dist", "results"}

TEXT_IO = {"read_text", "write_text"}
POSIX_ONLY = {"resource", "fcntl", "termios", "pwd", "grp", "tty", "pty", "crypt"}
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
YAML_BREAK = re.compile(r"\^---(?!\[ \\t\]\*(?:\\r\?|\(\?:[^)]*\)\?\\r\?))[^\"']*\$")


@dataclass(frozen=True)
class Finding:
    check: str
    path: str
    """Repository-relative, with `/` separators."""
    line: int
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}  [{self.check}]  {self.detail}"


CHECKS = {
    "default-encoding": (
        "Text read or written without `encoding=`: the platform's code page on Windows "
        "(cp1252), so a UTF-8 file is misread and a non-ASCII character cannot be written "
        "(18 conformance tests, `UnicodeEncodeError: 'charmap'`)."
    ),
    "native-path-text": (
        "`str()` of a relative path, compared with or stored as text: backslashes on "
        "Windows where reports and manifests use `/` (the damaged-file test, 54 failures; "
        "the guard manifest's `.github\\workflows\\...`). Use `.as_posix()`."
    ),
    "posix-only-import": (
        "A POSIX-only module imported at module level: the whole test module fails to "
        "import on Windows (`No module named 'resource'`). Import it inside the test with "
        "`pytest.importorskip`."
    ),
    "tests-package-import": (
        "`from tests.x import`: works under `python -m pytest`, fails under `pytest`, "
        'which puts `tests/` itself on the path (`pythonpath = ["tests"]`).'
    ),
    "yaml-break-crlf": (
        "A `^---` document break whose pattern does not allow `\\r` before the line end: a "
        "CRLF checkout is read as one document (pnpm 10 lockfiles, Kubernetes manifests)."
    ),
    "invisible-characters": (
        "A literal bidi or zero-width character in source: Cordon reports it in its own "
        "image (SUSPECT.OBFUSCATION.BIDI.001). Write it as an escape."
    ),
}


class Source:
    @staticmethod
    def files() -> Iterator[Path]:
        for top in SCANNED:
            base = ROOT / top
            if not base.is_dir():
                continue
            for path in sorted(base.rglob("*.py")):
                if SKIPPED_PARTS.intersection(path.relative_to(ROOT).parts):
                    continue
                yield path


class Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[Finding] = []
        self.is_test = "tests" in path.split("/")
        self.depth = 0
        self.parents: dict[int, ast.AST] = {}

    def visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.parents[id(child)] = node
        super().visit(node)

    def add(self, check: str, node: ast.AST, detail: str) -> None:
        self.findings.append(Finding(check, self.path, getattr(node, "lineno", 0), detail))

    # -- default encoding ---------------------------------------------------------------

    @staticmethod
    def _keywords(node: ast.Call) -> set[str]:
        return {k.arg for k in node.keywords if k.arg}

    @staticmethod
    def _binary_mode(node: ast.Call, position: int) -> bool:
        mode = None
        if len(node.args) > position and isinstance(node.args[position], ast.Constant):
            mode = node.args[position].value
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = keyword.value.value
        return isinstance(mode, str) and "b" in mode

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        keywords = self._keywords(node)
        if isinstance(func, ast.Attribute) and func.attr in TEXT_IO:
            positional_encoding = func.attr == "read_text" and len(node.args) >= 1
            positional_encoding |= func.attr == "write_text" and len(node.args) >= 2
            if "encoding" not in keywords and not positional_encoding:
                self.add("default-encoding", node, f"`.{func.attr}()` without encoding=")
        elif isinstance(func, ast.Name) and func.id == "open":
            # The builtin only. `x.open()` is as often a URL opener, an archive member or an OLE
            # stream as a file, and none of those take an encoding.
            # `len(node.args) < 4`: encoding is open()'s fourth positional argument.
            if not self._binary_mode(node, 1) and "encoding" not in keywords and len(node.args) < 4:
                self.add("default-encoding", node, "text-mode `open()` without encoding=")
        # str(x.relative_to(...)), unless the caller already turns separators into `/`.
        if (
            not self._separators_normalised(node)
            and isinstance(func, ast.Name)
            and func.id == "str"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Attribute)
            and node.args[0].func.attr == "relative_to"
        ):
            self.add("native-path-text", node, "`str(...relative_to(...))`; use `.as_posix()`")
        self.generic_visit(node)

    def _separators_normalised(self, node: ast.Call) -> bool:
        parent = self.parents.get(id(node))
        return (
            isinstance(parent, ast.Attribute)
            and parent.attr == "replace"
            and "os.sep" in ast.unparse(self.parents.get(id(parent), parent))
        )

    # -- imports ------------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._import(node, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._import(node, node.module)

    def _import(self, node: ast.AST, module: str) -> None:
        top = module.split(".")[0]
        if top in POSIX_ONLY and self.depth == 0 and self.is_test:
            self.add("posix-only-import", node, f"`import {module}` at module level")
        if top == "tests" and self.is_test:
            self.add("tests-package-import", node, f"`{module}`: import it without `tests.`")


class Portability:
    @staticmethod
    def text_checks(path: str, text: str) -> list[Finding]:
        found: list[Finding] = []
        for number, line in enumerate(text.splitlines(), 1):
            # Shipped code and tooling only: tests and benchmarks hold these characters on
            # purpose, as the input a detector is tested against.
            if INVISIBLE.search(line) and path.split("/")[0] in ("src", "scripts"):
                found.append(
                    Finding(
                        "invisible-characters", path, number, "write the character as \\u escape"
                    )
                )
            # Shipped parsers only: a test quotes such a pattern to show what is caught.
            pattern_line = "---" in line and ("re.compile" in line or "re.split" in line)
            pattern_line = pattern_line and path.startswith("src/")
            if pattern_line and YAML_BREAK.search(line):
                found.append(Finding("yaml-break-crlf", path, number, "allow `\\r?` before `$`"))
        return found

    @staticmethod
    def check(text: str, path: str) -> list[Finding]:
        """Every finding in one file's source, `path` being where it sits in the repository."""
        try:
            tree = ast.parse(text, filename=path)
        except SyntaxError as exc:
            return [Finding("syntax", path, exc.lineno or 0, str(exc.msg))]
        visitor = Visitor(path)
        visitor.visit(tree)
        return [*visitor.findings, *Portability.text_checks(path, text)]

    @staticmethod
    def run() -> list[Finding]:
        findings: list[Finding] = []
        for path in Source.files():
            relative = path.relative_to(ROOT).as_posix()
            findings.extend(Portability.check(path.read_text(encoding="utf-8"), relative))
        return findings

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
        parser.add_argument("--list", action="store_true", help="describe each check")
        parser.add_argument("--summary", action="store_true", help="counts per check only")
        args = parser.parse_args()
        if args.list:
            for name, description in CHECKS.items():
                print(f"{name}\n    {description}\n")
            return 0
        findings = Portability.run()
        if args.summary:
            counts: dict[str, int] = {}
            for f in findings:
                counts[f.check] = counts.get(f.check, 0) + 1
            for name, count in sorted(counts.items()):
                print(f"{count:6d}  {name}")
        else:
            for finding in findings:
                print(finding.render())
        if findings:
            print(f"\n{len(findings)} portability finding(s); `--list` explains each check.")
            return 1
        print("portability: nothing found")
        return 0


if __name__ == "__main__":
    sys.exit(Portability.main())
