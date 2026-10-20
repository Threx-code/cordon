"""YAML for machine-written data files: lockfiles and package metadata.

`core/config.py`'s `RestrictedYamlParser` reads configuration, where it refuses what a config
should never need (duplicate keys, colons in keys). Lockfiles are different input: generated,
large, and full of keys that are quoted because they contain colons --
`"lodash@npm:^4.17.20, lodash@npm:^4.17.21":` in every Yarn 4 lockfile, and pnpm's
`resolution: {integrity: ..., tarball: ...}` flow mappings. Line-matching those formats lost the
edges, the scopes and the platform fields; this reads them as the documents they are.

Still hostile-input YAML, so the same hazards stay unreachable:

* no anchors, aliases, tags or merge keys -- the billion-laughs shape and the deserialisation
  gadgets have nothing to hook into, and meeting one is a parse error, not a silent misread;
* depth is bounded (`MAX_DEPTH`), so nesting is a parse error rather than a stack overflow;
* scalars stay strings. `1.10` is a version, never the float `1.1`; only `true`, `false`, `null`
  and `~` are interpreted, because lockfiles use them as flags.

Duplicate keys keep the first value and are counted (`DataYaml.duplicates`) rather than refused:
a generated file does not contain them, and when a hostile one does the parser must not decide
for the attacker which copy a reader sees.
"""

from __future__ import annotations

import re
from typing import Any, Final

MAX_DEPTH: Final = 64
MAX_FLOW_CONTINUATION: Final = 200
#: A plain key ends at the first colon followed by a space or the end of the line; a colon inside
#: a word (`lodash@npm:4.17.21`, `https://...`) is part of it.
_KEY_END: Final = re.compile(r":(?=\s|$)")
#: A block scalar's header (YAML 1.2 §8.1.1): `|` or `>`, an indentation indicator and a chomping
#: indicator in either order, each optional, then an optional comment -- `|2` is how Helm's
#: index.yaml writes an annotation whose first line is indented.
_BLOCK_SCALAR: Final = re.compile(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?(?:[ \t]+#.*)?")
#: What YAML 1.2 (§5.1, c-printable) does not allow in a stream.
_UNPRINTABLE: Final = re.compile(
    "[^\x09\x0a\x0d\x20-\x7e\x85\xa0-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]"
)
#: Where a line ends in a block scalar's header: after `key:`, or after a sequence entry's dash.
_HEADER: Final = re.compile(r"(?:^-|:)[ \t]+([|>]\S*)$")


class DataYamlError(ValueError):
    """The document is not YAML this reader accepts. The message names the line."""


class DataYaml:
    """`DataYaml.load(text)` -> the document (mappings, lists, strings, bools, None)."""

    @staticmethod
    def load(text: str, *, source: str = "<data>") -> Any:
        unprintable = _UNPRINTABLE.search(text)
        if unprintable:
            # YAML 1.2 §5.1: a stream holds printable characters only. A NUL or a stray control
            # byte is a damaged file, not a key.
            raise DataYamlError(
                f"{source}:{text.count(chr(10), 0, unprintable.start()) + 1}: "
                f"a character YAML does not allow (U+{ord(unprintable.group()):04X})"
            )
        reader = _Reader(text, source)
        return reader.document()


class _Reader:
    def __init__(self, text: str, source: str) -> None:
        self.source = source
        self.lines: list[tuple[int, str, int]] = []
        #: A block scalar's text by its header's line number, read from the raw lines in the first
        #: pass: its lines are text, so neither a comment nor a bracket in them is the document's.
        self.blocks: dict[int, str] = {}
        #: How many empty lines come before a line, where a wrapped scalar folds them into
        #: line feeds (YAML 1.2 §6.5): `a: one`, an empty line, `two` reads "one\ntwo".
        self.gaps: dict[int, int] = {}
        self.duplicates = 0
        pending: list[str] = []
        pending_indent = 0
        pending_number = 0
        # A quoted scalar that goes on over the following lines, folded as it is read: its lines
        # are text, so neither a comment nor a bracket nor an empty line in them is the document's.
        quoting = ""
        quoted = ""
        quoted_at = (0, 0, 0)  # (indent, line number, where the scalar starts in `quoted`)
        empty = 0
        raws = text.splitlines()
        position = 0
        while position < len(raws):
            raw = raws[position]
            position += 1
            number = position
            stripped = raw.strip()
            if quoting:
                if not stripped:
                    empty += 1
                    continue
                if empty:
                    quoted += "\n" * empty
                elif quoting == '"' and _Reader._escapes_break(quoted):
                    quoted = quoted[:-1]  # `\` at the end of a line escapes the line break
                else:
                    quoted += " "
                quoted += stripped
                empty = 0
                scalar = quoted[quoted_at[2] :]
                end = _Reader._closing_quote(scalar, quoting)
                if end >= 0:
                    tail = _Reader._strip_comment(scalar[end + 1 :])
                    self.lines.append(
                        (
                            quoted_at[0],
                            quoted[: quoted_at[2]] + scalar[: end + 1] + tail,
                            quoted_at[1],
                        )
                    )
                    quoting = ""
                continue
            if pending:
                pending.append(stripped)
                if _Reader._balanced(" ".join(pending)) or len(pending) > MAX_FLOW_CONTINUATION:
                    self.lines.append((pending_indent, " ".join(pending), pending_number))
                    pending = []
                continue
            if not stripped:
                empty += 1
                continue
            if stripped.startswith("#") or stripped in ("---", "..."):
                continue
            if stripped.startswith("%"):
                continue  # a directive (`%YAML 1.2`), which changes nothing this reader does
            if empty:
                self.gaps[number] = empty
                empty = 0
            indent = len(raw) - len(raw.lstrip(" "))
            content = _Reader._strip_comment(stripped)
            opened = _Reader._open_quote(content)
            if opened >= 0:
                quoting, quoted, quoted_at = content[opened], content, (indent, number, opened)
                continue
            header = _HEADER.search(content)
            if header and _BLOCK_SCALAR.fullmatch(header.group(1)) and not pending:
                self.blocks[number], position = _Reader._block_text(
                    raws,
                    position,
                    _Reader._parent_column(indent, content),
                    header.group(1),
                    final_newline=text.endswith(("\n", "\r")),
                )
                self.lines.append((indent, content, number))
                continue
            if _Reader._opens_flow(content) and not _Reader._balanced(content):
                pending, pending_indent, pending_number = [content], indent, number
                continue
            self.lines.append((indent, content, number))
        if pending:
            raise DataYamlError(f"{source}:{pending_number}: unterminated flow collection")
        if quoting:
            raise DataYamlError(f"{source}:{quoted_at[1]}: unterminated quoted string")

    # -- lines ---------------------------------------------------------------------------------

    @staticmethod
    def _strip_comment(text: str) -> str:
        quote = ""
        escaped = False
        for index, character in enumerate(text):
            if quote:
                # In double quotes a backslash escapes the next character (`\"` closes nothing).
                if quote == '"' and character == "\\" and not escaped:
                    escaped = True
                    continue
                if character == quote and not escaped:
                    quote = ""
                escaped = False
                continue
            if character in "'\"" and (index == 0 or text[index - 1] in " :,[{-"):
                quote = character
            elif character == "#" and index > 0 and text[index - 1] in " \t":
                return text[:index].rstrip()
        return text

    @staticmethod
    def _value_start(content: str) -> int:
        """Where the line's value starts: after any sequence dashes and after its key; -1 for a
        line whose key is a quoted string left open."""
        rest = content
        while rest == "-" or rest.startswith(("- ", "-\t")):
            rest = rest[1:].lstrip(" \t")
        offset = len(content) - len(rest)
        if rest[:1] in ("'", '"'):
            end = _Reader._closing_quote(rest, rest[0])
            if end < 0:
                return offset
            after = rest[end + 1 :].lstrip()
            if not after.startswith(":"):
                return offset
            value = after[1:].lstrip()
            return len(content) - len(value)
        match = _KEY_END.search(rest)
        if match is None or not rest[: match.start()].strip() or rest[:1] in ("[", "{"):
            return offset
        value = rest[match.end() :].lstrip()
        return len(content) - len(value)

    @staticmethod
    def _open_quote(content: str) -> int:
        """Where the line's value opens a quoted scalar it does not close (`description: "Port
        is the port to be used in`), or -1."""
        start = _Reader._value_start(content)
        value = content[start:]
        if value[:1] in ("'", '"') and _Reader._closing_quote(value, value[0]) < 0:
            return start
        return -1

    @staticmethod
    def _escapes_break(text: str) -> bool:
        """Whether a double-quoted line ends in an escaping backslash (an odd run of them)."""
        return (len(text) - len(text.rstrip("\\"))) % 2 == 1

    @staticmethod
    def _opens_flow(content: str) -> bool:
        """Whether the line's value is a flow collection (`key: [a,`, `- {a: 1,`): only one can go
        on over the lines below. A bracket in plain text (`type FooStatus struct{`) opens nothing."""
        rest = content
        while rest == "-" or rest.startswith(("- ", "-\t")):
            rest = rest[1:].lstrip(" \t")
        if rest[:1] in ("[", "{"):
            return True
        if rest[:1] in ("'", '"'):
            end = _Reader._closing_quote(rest, rest[0])
            if end < 0:
                return False
            after = rest[end + 1 :].lstrip()
            return after.startswith(":") and after[1:].lstrip()[:1] in ("[", "{")
        match = _KEY_END.search(rest)
        return match is not None and rest[match.end() :].lstrip()[:1] in ("[", "{")

    @staticmethod
    def _balanced(text: str) -> bool:
        depth = 0
        quote = ""
        escaped = False
        for character in text:
            if quote:
                if quote == '"' and character == "\\" and not escaped:
                    escaped = True
                    continue
                if character == quote and not escaped:
                    quote = ""
                escaped = False
                continue
            if character in "'\"":
                quote = character
            elif character in "[{":
                depth += 1
            elif character in "]}":
                depth -= 1
        return depth <= 0

    # -- blocks --------------------------------------------------------------------------------

    def document(self) -> Any:
        if not self.lines:
            return None
        value, index = self.block(0, self.lines[0][0], 0)
        if index != len(self.lines):
            raise DataYamlError(f"{self.source}:{self.lines[index][2]}: unexpected indentation")
        return value

    def block(self, start: int, indent: int, depth: int) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise DataYamlError(
                f"{self.source}:{self.lines[start][2]}: nested deeper than {MAX_DEPTH}"
            )
        content = self.lines[start][1]
        if content[0] in "[{":
            # `test:` and, below it, `["CMD", "curl", ...]`: the value is the flow collection.
            return self.scalar(content, self.lines[start][2], depth), start + 1
        if content == "-" or content.startswith("- "):
            return self.sequence(start, indent, depth)
        return self.mapping(start, indent, depth)

    def key(self, content: str, number: int) -> tuple[str, str]:
        if content[0] in "'\"":
            end = _Reader._closing_quote(content, content[0])
            if end < 0:
                raise DataYamlError(f"{self.source}:{number}: unterminated quoted key")
            key = _Reader._unquote(content[: end + 1], number, self.source)
            rest = content[end + 1 :].lstrip()
            if not rest.startswith(":"):
                raise DataYamlError(f"{self.source}:{number}: expected ':' after a quoted key")
            return key, rest[1:].strip()
        if content[0] in "&*!" or content.startswith("<<"):
            raise DataYamlError(
                f"{self.source}:{number}: anchors, aliases, tags and merge keys are not read"
            )
        if content.startswith("? "):
            raise DataYamlError(f"{self.source}:{number}: complex keys are not read")
        match = _KEY_END.search(content)
        if not match or not content[: match.start()].strip():
            raise DataYamlError(f"{self.source}:{number}: expected 'key: value'")
        return content[: match.start()].strip(), content[match.end() :].strip()

    def mapping(self, start: int, indent: int, depth: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        index = start
        while index < len(self.lines):
            line_indent, content, number = self.lines[index]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise DataYamlError(f"{self.source}:{number}: unexpected indentation")
            if content == "-" or content.startswith("- "):
                break
            key, rest = self.key(content, number)
            value: Any
            if _BLOCK_SCALAR.fullmatch(rest):
                value, index = self.block_scalar(index)
            elif rest:
                rest, index = self.continued(rest, index, indent)
                value = self.scalar(rest, number, depth)
            else:
                index += 1
                if (
                    index < len(self.lines)
                    and self.lines[index][0] > indent
                    and self.plain_below(index)
                ):
                    # `description:` and the text on the lines below it, wrapped: one scalar.
                    text, index = self.continued(self.lines[index][1], index, indent)
                    value = self.scalar(text, number, depth)
                elif index < len(self.lines) and self.lines[index][0] > indent:
                    value, index = self.block(index, self.lines[index][0], depth + 1)
                elif (
                    index < len(self.lines)
                    and self.lines[index][0] == indent
                    and (self.lines[index][1] == "-" or self.lines[index][1].startswith("- "))
                ):
                    value, index = self.sequence(index, indent, depth + 1)
                else:
                    value = None
            if key in result:
                self.duplicates += 1
                continue
            result[key] = value
        return result, index

    def sequence(self, start: int, indent: int, depth: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        index = start
        while index < len(self.lines):
            line_indent, content, number = self.lines[index]
            if line_indent < indent or not (content == "-" or content.startswith("- ")):
                break
            if line_indent > indent:
                raise DataYamlError(f"{self.source}:{number}: unexpected indentation in a sequence")
            item = content[1:].strip()
            if _BLOCK_SCALAR.fullmatch(item):
                text, index = self.block_scalar(index)
                result.append(text)
                continue
            if item == "-" or item.startswith("- "):
                # `- - x`: an entry that is itself a sequence, aligned after the outer dash.
                inner = indent + (len(content) - len(item))
                self.lines[index] = (inner, item, number)
                nested, index = self.sequence(index, inner, depth + 1)
                result.append(nested)
                continue
            if not item:
                index += 1
                if index < len(self.lines) and self.lines[index][0] > indent:
                    value, index = self.block(index, self.lines[index][0], depth + 1)
                    result.append(value)
                else:
                    result.append(None)
                continue
            if _Reader._opens_mapping(item):
                # `- key: value` starts a mapping whose keys align with `key`.
                inner = indent + (len(content) - len(item))
                self.lines[index] = (inner, item, number)
                value, index = self.mapping(index, inner, depth + 1)
                result.append(value)
                continue
            item, index = self.continued(item, index, indent)
            result.append(self.scalar(item, number, depth))
        return result, index

    def continued(self, text: str, index: int, indent: int) -> tuple[str, int]:
        """A plain scalar that goes on over the following, further-indented lines (`description:
        PostgreSQL is ...` wrapped at eighty columns): the lines folded into one, as YAML folds
        them -- a line break a space, each empty line a line feed. Returns the text and the index
        after it. (A quoted scalar's lines were folded as they were read.)"""
        index += 1
        if text[0] in "[{|>&*!'\"":
            return text, index
        while index < len(self.lines) and self.lines[index][0] > indent:
            line = self.lines[index][1]
            if _KEY_END.search(line):
                # `a: b` then an indented `c: d`: a plain scalar holds no `key: value`, so this is a
                # mapping where YAML allows none -- an error, as YAML itself has it.
                raise DataYamlError(
                    f"{self.source}:{self.lines[index][2]}: mapping values are not allowed here"
                )
            gap = self.gaps.get(self.lines[index][2], 0)
            text += ("\n" * gap if gap else " ") + line
            index += 1
        return text, index

    def plain_below(self, index: int) -> bool:
        """Whether the indented line at `index` begins a plain scalar rather than a block: neither
        a sequence item, nor a key, nor a flow collection or a block-scalar indicator."""
        line = self.lines[index][1]
        return not (
            line == "-"
            or line.startswith("- ")
            or line[0] in "[{|>&*!"
            or _Reader._opens_mapping(line)
        )

    @staticmethod
    def _opens_mapping(item: str) -> bool:
        if item[0] in "'\"":
            end = _Reader._closing_quote(item, item[0])
            return end > 0 and item[end + 1 :].lstrip().startswith(":")
        if item[0] in "[{":
            return False
        match = _KEY_END.search(item)
        return match is not None and bool(item[: match.start()].strip())

    def block_scalar(self, index: int) -> tuple[str, int]:
        """The block scalar headed at `index`, read in the first pass; the index after it."""
        return self.blocks.get(self.lines[index][2], ""), index + 1

    @staticmethod
    def _parent_column(indent: int, content: str) -> int:
        """The column a block scalar's content must be indented past: its key's (`- key: |`), or
        its sequence entry's dash (`- |`)."""
        column, rest = indent, content
        while rest.startswith("-") and rest[1:2] in (" ", "\t"):
            after = rest[1:].lstrip(" \t")
            if _BLOCK_SCALAR.fullmatch(after):
                return column
            column += len(rest) - len(after)
            rest = after
        return column

    @staticmethod
    def _block_text(
        raws: list[str], start: int, parent: int, header: str, *, final_newline: bool
    ) -> tuple[str, int]:
        """A block scalar's text (YAML 1.2 §8.1), from the raw line after its header: content
        indented past `parent` by the indentation indicator or, without one, as far as its first
        non-empty line; literal (`|`) lines kept, folded (`>`) ones joined as YAML folds them, and
        the final line breaks chomped (clip, `-` strip, `+` keep) -- PyYAML's
        `scan_block_scalar`. Returns the text and the raw index after it."""
        indicator = re.search(r"[1-9]", header)
        chomping = "-" if "-" in header else "+" if "+" in header else ""
        folded = header.startswith(">")
        index = start

        def blank(line: str, indent: int | None) -> bool:
            # Spaces only, up to the content's indentation (any number, before it is known).
            spaces = len(line) - len(line.lstrip(" "))
            return line[spaces:] == "" and (indent is None or spaces <= indent)

        indent: int
        if indicator:
            indent = parent + int(indicator.group())
        else:
            probe = index
            while probe < len(raws) and blank(raws[probe], None):
                probe += 1
            first = raws[probe] if probe < len(raws) else ""
            indent = max(len(first) - len(first.lstrip(" ")), parent + 1)
        chunks: list[str] = []
        breaks: list[str] = []
        line_break = ""
        while index < len(raws) and blank(raws[index], indent):
            breaks.append("\n")
            index += 1
        while index < len(raws) and len(raws[index]) - len(raws[index].lstrip(" ")) >= indent:
            chunks.extend(breaks)
            line = raws[index][indent:]
            leading_non_space = line[:1] not in (" ", "\t")
            chunks.append(line)
            index += 1
            line_break = "\n" if index < len(raws) or final_newline else ""
            breaks = []
            while index < len(raws) and blank(raws[index], indent):
                breaks.append("\n")
                index += 1
            following = raws[index] if index < len(raws) else None
            if following is None or len(following) - len(following.lstrip(" ")) < indent:
                break
            if folded and leading_non_space and following[indent:][:1] not in (" ", "\t"):
                if not breaks:
                    chunks.append(" ")
            else:
                chunks.append(line_break)
        if chomping != "-":
            chunks.append(line_break)
        if chomping == "+":
            chunks.extend(breaks)
        return "".join(chunks), index

    # -- scalars and flow ----------------------------------------------------------------------

    def scalar(self, text: str, number: int, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise DataYamlError(f"{self.source}:{number}: nested deeper than {MAX_DEPTH}")
        text = text.strip()
        if not text:
            return None
        if text[0] in "'\"":
            return _Reader._unquote(text, number, self.source)
        if text[0] == "[":
            inner = text[1:-1] if text.endswith("]") else None
            if inner is None:
                raise DataYamlError(f"{self.source}:{number}: unterminated flow sequence")
            return [
                self.scalar(p, number, depth + 1) for p in _Reader._split_flow(inner) if p.strip()
            ]
        if text[0] == "{":
            inner = text[1:-1] if text.endswith("}") else None
            if inner is None:
                raise DataYamlError(f"{self.source}:{number}: unterminated flow mapping")
            mapping: dict[str, Any] = {}
            for pair in _Reader._split_flow(inner):
                if not pair.strip():
                    continue
                key, value = _Reader._flow_pair(pair.strip())
                key_text = _Reader._unquote(key, number, self.source) if key[:1] in "'\"" else key
                mapping.setdefault(
                    key_text, self.scalar(value, number, depth + 1) if value else None
                )
            return mapping
        if text[0] in "&*!" or text.startswith("<<"):
            raise DataYamlError(
                f"{self.source}:{number}: anchors, aliases, tags and merge keys are not read"
            )
        lowered = text.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered in ("null", "~"):
            return None
        return text

    @staticmethod
    def _flow_pair(pair: str) -> tuple[str, str]:
        if pair[0] in "'\"":
            end = _Reader._closing_quote(pair, pair[0])
            rest = pair[end + 1 :].lstrip()
            return pair[: end + 1], rest[1:].strip() if rest.startswith(":") else ""
        match = re.match(r"^(.*?):(?:\s+|$)", pair)
        if match:
            return match.group(1).strip(), pair[match.end() :].strip()
        return pair, ""

    @staticmethod
    def _split_flow(inner: str) -> list[str]:
        parts: list[str] = []
        depth = 0
        quote = ""
        current: list[str] = []
        for character in inner:
            if quote:
                current.append(character)
                if character == quote:
                    quote = ""
                continue
            if character in "'\"":
                quote = character
            elif character in "[{":
                depth += 1
            elif character in "]}":
                depth -= 1
            elif character == "," and depth == 0:
                parts.append("".join(current))
                current = []
                continue
            current.append(character)
        parts.append("".join(current))
        return parts

    @staticmethod
    def _closing_quote(text: str, quote: str) -> int:
        index = 1
        while index < len(text):
            character = text[index]
            if quote == '"' and character == "\\":
                index += 2
                continue
            if character == quote:
                if quote == "'" and index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                return index
            index += 1
        return -1

    @staticmethod
    def _unquote(text: str, number: int, source: str) -> str:
        quote = text[0]
        end = _Reader._closing_quote(text, quote)
        if end < 0:
            raise DataYamlError(f"{source}:{number}: unterminated quoted string")
        body = text[1:end]
        if quote == "'":
            return body.replace("''", "'")
        out: list[str] = []
        index = 0
        escapes = {
            "n": "\n",
            "t": "\t",
            "r": "\r",
            '"': '"',
            "\\": "\\",
            "/": "/",
            "0": "\0",
            " ": " ",
        }
        while index < len(body):
            character = body[index]
            if character == "\\" and index + 1 < len(body):
                nxt = body[index + 1]
                if nxt in escapes:
                    out.append(escapes[nxt])
                    index += 2
                    continue
                if nxt in "xuU":
                    width = {"x": 2, "u": 4, "U": 8}[nxt]
                    digits = body[index + 2 : index + 2 + width]
                    try:
                        out.append(chr(int(digits, 16)))
                    except ValueError:
                        out.append(body[index : index + 2 + width])
                    index += 2 + width
                    continue
            out.append(character)
            index += 1
        return "".join(out)


__all__ = ["DataYaml", "DataYamlError"]
