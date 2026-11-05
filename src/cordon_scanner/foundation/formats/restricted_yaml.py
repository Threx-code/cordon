"""The YAML subset Cordon reads its own configuration and rule files in: mappings, sequences,
scalars and comments, nested to a fixed depth, and nothing that runs code or reaches outside the
document (no tags, anchors, aliases or merge keys).

A configuration file is read from the repository being scanned, which may be hostile, so the parser
accepts only what a configuration needs and refuses the rest with the line it stopped at.
"""

from __future__ import annotations

from typing import Any

from cordon_scanner.foundation.errors import ConfigError

MAX_NESTING = 32
"""Ceiling on configuration nesting depth.

Far above anything a real configuration uses -- the deepest key in this
project's own schema is four levels -- and far below the interpreter's recursion
limit. What it bounds is a file written to overflow the stack rather than to
configure anything."""


class RestrictedYamlParser:
    """A YAML parser for the subset a configuration file needs, and no more.

    Not a dependency and not a subset by accident. Constraint C1 rules out
    third-party runtime dependencies, and the parts of YAML deliberately left
    unimplemented are the parts that make a config file a hazard:

    * **Anchors and aliases** (`&a`, `*a`). A small file expands to gigabytes --
      the billion-laughs shape. Unimplemented, so unreachable.
    * **Tags** (`!!python/object`). The mechanism behind every YAML
      deserialisation CVE. There is no tag handling to exploit.
    * **Merge keys**, multi-document streams, and flow-mapping nesting. Each is
      one more construct a reviewer has to hold in their head to know what a
      security configuration actually says.

    The parser is recursive-descent over an indentation-token stream, and
    depth is bounded, so a deeply nested file is a configuration error rather
    than a stack overflow. The scan target is untrusted input and its
    configuration file is part of it, which is why this reads like a parser for
    hostile input and not like a convenience loader.
    """

    @staticmethod
    def _load_yaml_subset(text: str, *, source: str) -> dict[str, Any]:
        lines = RestrictedYamlParser._tokenize(text, source=source)
        if not lines:
            return {}
        value, index = RestrictedYamlParser._parse_block(lines, 0, lines[0][0], source=source)
        if index != len(lines):
            raise _YamlError(f"{source}:{lines[index][2]}: unexpected indentation")
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise _YamlError(f"{source}: top level must be a mapping")
        return value

    @staticmethod
    def _tokenize(text: str, *, source: str) -> list[tuple[int, str, int]]:
        """Return (indent, content, line_number) for each significant line."""
        out: list[tuple[int, str, int]] = []
        for number, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise _YamlError(
                    f"{source}:{number}: tab in indentation",
                    hint="YAML indentation must use spaces.",
                )
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in {"---", "..."}:
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            out.append((indent, stripped, number))
        return out

    @staticmethod
    def _parse_block(
        lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str, depth: int = 0
    ) -> tuple[Any, int]:
        RestrictedYamlParser._check_depth(depth, source=source, number=0)
        if start >= len(lines):
            return None, start
        if lines[start][1].startswith("- "):
            return RestrictedYamlParser._parse_sequence(
                lines, start, indent, source=source, depth=depth
            )
        return RestrictedYamlParser._parse_mapping(lines, start, indent, source=source, depth=depth)

    @staticmethod
    def _check_depth(depth: int, *, source: str, number: int) -> None:
        """Refuse a document nested past `MAX_NESTING`.

        The class docstring already promised this -- "depth is bounded, so a
        deeply nested file is a configuration error rather than a stack
        overflow" -- and no depth parameter existed anywhere in the class. An
        audit fed the scanner a 400 KB config of nine hundred progressively
        indented keys and got `RecursionError`, exit 2, and a message blaming
        the maintainers.

        Exit 2 is worse than it looks. It means "the scanner broke", and
        pipelines routinely treat a broken tool as skippable in a way they do
        not treat a finding -- so a repository could refuse to be scanned and
        have that read as an infrastructure problem. `MAX_CONFIG_BYTES` did not
        help: one space per level costs n^2/2 bytes for block nesting and one
        byte per level for flow nesting, so hundreds of levels fit easily.
        """
        if depth > MAX_NESTING:
            raise _YamlError(f"{source}:{number}: nested more than {MAX_NESTING} levels deep")

    @staticmethod
    def _parse_mapping(
        lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str, depth: int = 0
    ) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        index = start
        while index < len(lines):
            line_indent, content, number = lines[index]
            if line_indent < indent:
                break
            if line_indent > indent:
                raise _YamlError(f"{source}:{number}: unexpected indentation")
            if content.startswith("- "):
                break

            key, _, rest = content.partition(":")
            if not _:
                raise _YamlError(f"{source}:{number}: expected 'key: value'")
            key = RestrictedYamlParser._unquote(key.strip())
            if key in result:
                # Last-win, silently, was a scanner-blinding primitive. A hostile
                # config could put the benign value first, where a reviewer
                # reads it, and the real one fifty lines further down:
                #
                #     scan:
                #       exclude: []          # what the reviewer reads
                #       ...
                #       exclude: ["**/*"]    # what takes effect
                #
                # This parser already refuses a misspelled key for the same
                # reason. A duplicate is the same failure in a better costume.
                raise _YamlError(
                    f"{source}:{number}: duplicate key {key!r}; "
                    f"a later value would silently replace the earlier one"
                )
            rest = rest.strip()

            if rest.startswith("#"):
                rest = ""
            if rest in {"|", ">", "|-", ">-"}:
                value, index = RestrictedYamlParser._parse_block_scalar(
                    lines, index + 1, indent, rest, source=source
                )
                result[key] = value
                continue
            if rest:
                result[key] = RestrictedYamlParser._scalar(rest, number=number, source=source)
                index += 1
                continue

            # Nested block: whatever is indented further than this key.
            index += 1
            if index < len(lines) and lines[index][0] > indent:
                child_indent = lines[index][0]
                value, index = RestrictedYamlParser._parse_block(
                    lines, index, child_indent, source=source, depth=depth + 1
                )
                result[key] = value
            elif (
                index < len(lines)
                and lines[index][0] == indent
                and lines[index][1].startswith("- ")
            ):
                # A sequence at the same indentation as its key. Common and legal.
                sequence, index = RestrictedYamlParser._parse_sequence(
                    lines, index, indent, source=source, depth=depth + 1
                )
                result[key] = sequence
            else:
                result[key] = None
        return result, index

    @staticmethod
    def _opens_inline_mapping(item: str) -> bool:
        """Whether a sequence item begins an inline mapping.

        The test used to be `":" in item`, and every URL is a sequence item
        containing a colon. So every `references:` entry in every shipped rule
        was parsed into a single-key dict and stringified, and the tool's own
        output carried

            refs  {'https': '//cwe.mitre.org/data/definitions/522.html'}

        for the whole rule set -- in the terminal report and in SARIF `helpUri`
        alike.

        A mapping key is a bare word. Requiring the text before the first colon
        to look like one, and requiring the colon to be followed by a space or
        end of line, distinguishes `name: value` from `https://host/path`
        without needing to know what a URL is.
        """
        if not item or item.startswith(("'", '"')):
            return False
        head, sep, rest = item.partition(":")
        if not sep:
            return False
        if rest and not rest.startswith(" "):
            # `https://...` and `10:30` -- a mapping always has a space after
            # the colon, or nothing at all.
            return False
        return bool(head) and all(c.isalnum() or c in "_-." for c in head)

    @staticmethod
    def _parse_sequence(
        lines: list[tuple[int, str, int]], start: int, indent: int, *, source: str, depth: int = 0
    ) -> tuple[list[Any], int]:
        result: list[Any] = []
        index = start
        while index < len(lines):
            line_indent, content, number = lines[index]
            if line_indent < indent or not content.startswith("- "):
                break
            if line_indent > indent:
                raise _YamlError(f"{source}:{number}: unexpected indentation in sequence")

            item = content[2:].strip()
            if RestrictedYamlParser._opens_inline_mapping(item):
                # An inline mapping opening a sequence item. Re-parse the item and
                # any following lines indented past the dash as one mapping.
                synthetic: list[tuple[int, str, int]] = [(indent + 2, item, number)]
                index += 1
                while index < len(lines) and lines[index][0] > indent:
                    synthetic.append(lines[index])
                    index += 1
                value, consumed = RestrictedYamlParser._parse_mapping(
                    synthetic, 0, indent + 2, source=source
                )
                if consumed != len(synthetic):
                    raise _YamlError(f"{source}:{number}: could not parse sequence item")
                result.append(value)
                continue

            result.append(RestrictedYamlParser._scalar(item, number=number, source=source))
            index += 1
        return result, index

    @staticmethod
    def _parse_block_scalar(
        lines: list[tuple[int, str, int]], start: int, indent: int, style: str, *, source: str
    ) -> tuple[str, int]:
        """Parse a literal (``|``) or folded (``>``) block scalar.

        Both chomping indicators are honoured, because they are not equivalent:
        ``|`` clips to a single trailing newline while ``|-`` strips it entirely.
        Collapsing them means a value silently differs from what the author wrote,
        which for a security configuration is exactly the class of surprise this
        parser exists to avoid.
        """
        parts: list[str] = []
        index = start
        while index < len(lines) and lines[index][0] > indent:
            parts.append(lines[index][1])
            index += 1

        # Literal keeps line breaks; folded joins lines with a single space.
        text = "\n".join(parts) if style.startswith("|") else " ".join(parts)

        # Chomping: "-" strips the trailing newline, the default clips to one.
        if style.endswith("-") or not text:
            return text, index
        return text + "\n", index

    @staticmethod
    def _scalar(text: str, *, number: int, source: str, depth: int = 0) -> Any:
        # Flow collections nest too, and cost one byte per level rather than the
        # n^2/2 of block indentation -- so `[[[[...]]]]` reaches the stack limit
        # inside a document far below `MAX_CONFIG_BYTES`.
        RestrictedYamlParser._check_depth(depth, source=source, number=number)
        text = text.strip()

        # Strip a trailing comment, but not one inside quotes.
        if text and text[0] not in {"'", '"'}:
            hash_at = text.find(" #")
            if hash_at != -1:
                text = text[:hash_at].strip()

        if not text:
            return None
        if text.startswith(("'", '"')):
            return RestrictedYamlParser._unquote(text)
        if text.startswith("["):
            if not text.endswith("]"):
                raise _YamlError(f"{source}:{number}: unterminated flow sequence")
            inner = text[1:-1].strip()
            if not inner:
                return []
            return [
                RestrictedYamlParser._scalar(p, number=number, source=source, depth=depth + 1)
                for p in RestrictedYamlParser._split_flow(inner)
            ]
        if text.startswith("{"):
            if not text.endswith("}"):
                raise _YamlError(f"{source}:{number}: unterminated flow mapping")
            inner = text[1:-1].strip()
            if not inner:
                return {}
            mapping: dict[str, Any] = {}
            for pair in RestrictedYamlParser._split_flow(inner):
                k, sep, v = pair.partition(":")
                if not sep:
                    raise _YamlError(f"{source}:{number}: expected 'key: value' in flow mapping")
                mapping[RestrictedYamlParser._unquote(k.strip())] = RestrictedYamlParser._scalar(
                    v.strip(), number=number, source=source, depth=depth + 1
                )
            return mapping

        lowered = text.lower()
        if lowered in {"true", "yes", "on"}:
            return True
        if lowered in {"false", "no", "off"}:
            return False
        if lowered in {"null", "~"}:
            return None
        # NOTE: "none" is deliberately NOT a null literal. The YAML 1.2 core schema
        # does not treat it as one, and `evidence: none` is a legitimate enum value
        # in this configuration -- mapping it to null makes that setting unreachable
        # while appearing to work.

        # Anchors, aliases and type tags are deliberately unsupported. Each is a
        # documented hazard in untrusted YAML, and a clear error beats a silent
        # misparse of something a user believed was in effect.
        if text[0] in {"&", "*", "!"}:
            raise _YamlError(
                f"{source}:{number}: YAML anchors, aliases and tags are not supported",
                hint="Cordon parses a restricted YAML subset deliberately. Write the value inline.",
            )

        try:
            return int(text)
        except ValueError:
            pass
        try:
            return float(text)
        except ValueError:
            pass
        return text

    @staticmethod
    def _split_flow(text: str) -> list[str]:
        """Split a flow collection on commas that are not inside quotes or brackets."""
        parts: list[str] = []
        depth = 0
        quote: str | None = None
        current: list[str] = []
        for ch in text:
            if quote:
                current.append(ch)
                if ch == quote:
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
                current.append(ch)
            elif ch in "[{":
                depth += 1
                current.append(ch)
            elif ch in "]}":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            parts.append("".join(current).strip())
        return [p for p in parts if p]

    @staticmethod
    @staticmethod
    def _unescape(body: str) -> str:
        """Resolve double-quoted escapes in one pass."""
        out: list[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char == "\\" and index + 1 < len(body):
                nxt = body[index + 1]
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, "\\" + nxt))
                index += 2
                continue
            out.append(char)
            index += 1
        return "".join(out)

    @staticmethod
    def _unquote(text: str) -> str:
        text = text.strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
            body = text[1:-1]
            if text[0] == '"':
                # Scanned once, left to right, rather than by three sequential
                # replaces. The replace chain handled the backslash escape
                # *last*, so `"\\n"` -- an escaped backslash followed by `n` --
                # became a newline instead of a literal backslash-n. Cosmetic
                # while values are patterns and severities; a correctness trap
                # the moment a quoted value carries a Windows path.
                return RestrictedYamlParser._unescape(body)
            return body.replace("''", "'")
        return text


class _YamlError(ConfigError):
    pass


__all__ = ["MAX_NESTING", "RestrictedYamlParser"]
