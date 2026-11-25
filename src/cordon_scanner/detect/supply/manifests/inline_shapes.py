"""Inline install programs that are one of a few closed, harmless shapes (reviews/mcp-98/47).

An install hook that carries its program inline (`node -e "..."`) is a finding on its own, because a program the capability
rules label nothing in is the one an attacker writes to say something or to wait. Four shapes of such a program are written by
legitimate packages and do nothing else, and each is recognised here by a CLOSED reading, not by the absence of a capability:

```
  no_op            process.exit(0)                                  the fallback that lets an install go on
  version_guard    compares process.version(s) with a number, may say so on the console, may exit
  chmod_own        require('fs').chmodSync('<path of the package>', 0o755)   (a few, in a try/catch)
  guarded_import   checks that a file of the package exists, exits if not, else imports it
```

The program is cut into tokens (identifiers, numbers, quoted strings without an escape or a `${`, and the punctuation of a
statement); anything the cut does not cover, any identifier outside the shape's own list, any string that looks like an address or
a shell expansion, and any path that leaves the package makes it NOT one of the shapes and the finding stays. A banner (a program
that only prints) is not a shape: it is the program a malicious package writes to say something.
"""

from __future__ import annotations

import re
from typing import Final

_TOKEN: Final = re.compile(
    r"""\s+|(?P<id>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<num>0[oO][0-7]{1,6}|[0-9]{1,6})"""
    r"""|(?P<str>'[^'\\\n$`]{0,160}'|"[^"\\\n$`]{0,160}")|(?P<op>[(){}\[\].,;:?<>=!+\-|&*])"""
)
_MAX_TOKENS: Final = 120
_FS_MODULES: Final = frozenset({"fs", "node:fs"})
_PATH: Final = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9_@./-]{0,119}")

#: The words a version guard may use, besides the names it declares itself.
_GUARD_WORDS: Final = frozenset(
    {
        "process", "version", "versions", "node", "slice", "split", "Number", "parseInt", "exit",
        "console", "error", "warn", "log", "if", "else", "const", "let", "var", "true", "false",
    }
)  # fmt: skip
_CONSOLE_METHODS: Final = frozenset({"error", "warn", "log"})
_DECLARES: Final = frozenset({"const", "let", "var"})
_COMPARISONS: Final = frozenset({"<", ">"})

#: The reading of a loader, over tokens written `S` for a string and `N` for a number.
_CHMOD: Final = re.compile(
    r"^(?:try\{)?(?:require\(S\)\.chmodSync\(S,N\);?){1,4}(?:\}catch(?:\([a-z]+\))?\{\})?;?$"
)
_IMPORT_AFTER_TRY: Final = re.compile(
    r"^try\{require\(S\)\.(?:accessSync|existsSync)\(S\)\}catch(?:\([a-z]+\))?\{process\.exit\(N\)\};?(?:import|require)\(S\);?$"
)
_IMPORT_AFTER_AND: Final = re.compile(r"^require\(S\)\.existsSync\(S\)&&(?:import|require)\(S\);?$")
_IMPORT_AFTER_IF: Final = re.compile(
    r"^if\(require\(S\)\.existsSync\(S\)\)\{?(?:import|require)\(S\);?\}?;?$"
)


class InlineShapes:
    """`kind(source)`: which closed shape an inline Node program is, or None."""

    @classmethod
    def kind(cls, source: str) -> str | None:
        tokens = cls._tokens(source)
        if not tokens:
            return None
        text = "".join(cls._shape(kind, value) for kind, value in tokens)
        if text in ("process.exit(N)", "process.exit(N);"):
            return (
                "no_op" if cls._number(tokens[-3 if text.endswith(";") else -2][1]) == 0 else None
            )
        if cls._version_guard(tokens):
            return "version_guard"
        strings = [value[1:-1] for kind, value in tokens if kind == "str"]
        if _CHMOD.match(text) and cls._chmod_ok(strings):
            return "chmod_own"
        if (
            _IMPORT_AFTER_TRY.match(text)
            or _IMPORT_AFTER_AND.match(text)
            or _IMPORT_AFTER_IF.match(text)
        ) and cls._import_ok(text, tokens, strings):
            return "guarded_import"
        return None

    # -- the cut --------------------------------------------------------------------------------

    @staticmethod
    def _tokens(source: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        at = 0
        while at < len(source):
            match = _TOKEN.match(source, at)
            if match is None:
                return []
            at = match.end()
            kind = match.lastgroup
            if kind is None:
                continue
            found.append((kind, match.group()))
            if len(found) > _MAX_TOKENS:
                return []
        return found

    @staticmethod
    def _shape(kind: str, value: str) -> str:
        return {"str": "S", "num": "N"}.get(kind, value)

    @staticmethod
    def _number(value: str) -> int:
        return int(value[2:], 8) if value[:2] in ("0o", "0O") else int(value)

    @staticmethod
    def _safe_string(value: str) -> bool:
        return "://" not in value and "..\\" not in value and not value.startswith(("/", "~"))

    # -- the shapes -----------------------------------------------------------------------------

    @classmethod
    def _version_guard(cls, tokens: list[tuple[str, str]]) -> bool:
        declared: set[str] = set()
        for index, (kind, value) in enumerate(tokens[:-1]):
            if kind == "id" and value in _DECLARES and tokens[index + 1][0] == "id":
                declared.add(tokens[index + 1][1])
        words = [value for kind, value in tokens if kind == "id"]
        if any(word not in _GUARD_WORDS and word not in declared for word in words):
            return False
        flat = [value for _kind, value in tokens]
        reads_version = any(
            flat[i] == "process" and flat[i + 1] == "." and flat[i + 2] in ("version", "versions")
            for i in range(len(flat) - 2)
        )
        exits = any(
            flat[i] == "process" and flat[i + 1] == "." and flat[i + 2] == "exit"
            for i in range(len(flat) - 2)
        )
        compares = any(value in _COMPARISONS for _kind, value in tokens)
        strings_ok = all(cls._safe_string(value[1:-1]) for kind, value in tokens if kind == "str")
        # A bracket is an index (`[0]`) and never a computed name: `process['mainModule']['require']` runs code with no
        # identifier outside the list.
        for index, (_kind, value) in enumerate(tokens):
            if value == "[" and not (
                index + 2 < len(tokens)
                and tokens[index + 1][0] == "num"
                and tokens[index + 2][1] == "]"
            ):
                return False
        return (
            reads_version and exits and compares and strings_ok and cls._console_only_methods(flat)
        )

    @staticmethod
    def _console_only_methods(flat: list[str]) -> bool:
        """`console.` is followed by a printing method and `process.` by a property the guard reads or `exit`."""
        for i in range(len(flat) - 2):
            if flat[i] == "console" and flat[i + 1] == "." and flat[i + 2] not in _CONSOLE_METHODS:
                return False
            if (
                flat[i] == "process"
                and flat[i + 1] == "."
                and flat[i + 2] not in ("version", "versions", "exit")
            ):
                return False
        return True

    @classmethod
    def _chmod_ok(cls, strings: list[str]) -> bool:
        """Pairs of (module, path): `fs`, then a path of the package, repeated."""
        if len(strings) % 2 or not strings:
            return False
        modules, paths = strings[0::2], strings[1::2]
        return all(module in _FS_MODULES for module in modules) and all(
            cls._package_path(path) for path in paths
        )

    @classmethod
    def _import_ok(cls, text: str, tokens: list[tuple[str, str]], strings: list[str]) -> bool:
        """`fs`, the file checked, the file loaded: the same file, spelled with or without `./`, inside the package; and the
        exit it falls back to is a clean one."""
        if len(strings) != 3 or strings[0] not in _FS_MODULES:
            return False
        checked, loaded = strings[1], strings[2]
        if not cls._package_path(checked) or not cls._package_path(loaded):
            return False
        if re.sub(r"^(?:\./)+", "", loaded) != re.sub(
            r"^(?:\./)+", "", checked
        ) or not loaded.startswith("./"):
            return False
        numbers = [value for kind, value in tokens if kind == "num"]
        return all(cls._number(value) == 0 for value in numbers)

    @classmethod
    def _package_path(cls, path: str) -> bool:
        stem = re.sub(r"^(?:\./)+", "", path)
        return (
            bool(_PATH.fullmatch(stem))
            and cls._safe_string(path)
            and ".." not in stem.split("/")
            and "node_modules" not in stem.split("/")
        )


__all__ = ["InlineShapes"]
