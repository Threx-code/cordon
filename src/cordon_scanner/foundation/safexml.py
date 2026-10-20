"""A small XML reader for build descriptors: POMs, .csproj and .props files, NuGet.Config, Gradle
verification metadata.

Python's XML parsers carry documented hazards on untrusted input -- entity expansion (billion
laughs), external entities, quadratic blowup -- and every one of these files is attacker-
controlled like everything else in a scan. Regular expressions avoided the hazards and lost the
structure: a `<dependency>` flattened into tag/value pairs let the `<groupId>` of an `<exclusion>`
inside it overwrite the dependency's own.

This reads elements, attributes and text and nothing else:

* a DOCTYPE, an entity declaration or a processing instruction other than the XML declaration
  is refused (`SafeXmlError`): no entity is ever defined, so none can expand;
* only the five predefined entities and numeric character references are decoded;
* depth and element count are bounded, so a hostile document is an error, not a hang.

Namespaces are kept as written (`<x:Package>` is `x:Package`); `local` strips a prefix for callers
that match on local names, which is what MSBuild and Maven files need.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final

MAX_DEPTH: Final = 64
MAX_ELEMENTS: Final = 200_000
_NAME: Final = re.compile(r"[A-Za-z_:][\w.:\-]{0,200}")
_ATTRIBUTE: Final = re.compile(r"""([A-Za-z_:][\w.:\-]{0,200})\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_ENTITY: Final = re.compile(r"&(#x[0-9A-Fa-f]{1,6}|#[0-9]{1,7}|lt|gt|amp|quot|apos);")
_PREDEFINED: Final = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}


class SafeXmlError(ValueError):
    """The document is not XML this reader accepts. The message names where."""


@dataclass
class Element:
    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: list[Element] = field(default_factory=list)
    text: str = ""
    line: int = 0

    @property
    def local(self) -> str:
        return self.tag.rpartition(":")[2]

    def find(self, *path: str) -> Element | None:
        """The first descendant along `path` of local names (`find("build", "plugins")`)."""
        current: Element | None = self
        for step in path:
            if current is None:
                return None
            current = next((c for c in current.children if c.local == step), None)
        return current

    def find_all(self, *path: str) -> list[Element]:
        """Every element at the end of `path`, through every matching branch."""
        level = [self]
        for step in path:
            level = [c for e in level for c in e.children if c.local == step]
        return level

    def value(self, *path: str, default: str = "") -> str:
        found = self.find(*path)
        return found.text.strip() if found is not None else default


class SafeXml:
    @staticmethod
    def parse(text: str, *, source: str = "<xml>") -> Element:
        reader = _Reader(text, source)
        return reader.document()


class _Reader:
    def __init__(self, text: str, source: str) -> None:
        self.text = text
        self.source = source
        self.position = 0
        self.count = 0

    def line(self) -> int:
        return self.text.count("\n", 0, self.position) + 1

    def fail(self, message: str) -> SafeXmlError:
        return SafeXmlError(f"{self.source}:{self.line()}: {message}")

    @staticmethod
    def decode(text: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name.startswith("#x"):
                return chr(int(name[2:], 16))
            if name.startswith("#"):
                return chr(int(name[1:]))
            return _PREDEFINED[name]

        return _ENTITY.sub(replace, text)

    def document(self) -> Element:
        root: Element | None = None
        stack: list[Element] = []
        text = self.text
        while self.position < len(text):
            start = text.find("<", self.position)
            if start < 0:
                trailing = text[self.position :]
                if stack:
                    stack[-1].text += self.decode(trailing)
                elif trailing.strip():
                    raise self.fail("text outside the root element")
                self.position = len(text)
                break
            if stack and start > self.position:
                stack[-1].text += self.decode(text[self.position : start])
            elif not stack and text[self.position : start].strip():
                raise self.fail("text before the root element")
            self.position = start
            if text.startswith("<!--", start):
                end = text.find("-->", start + 4)
                if end < 0:
                    raise self.fail("unterminated comment")
                self.position = end + 3
                continue
            if text.startswith("<![CDATA[", start):
                end = text.find("]]>", start + 9)
                if end < 0:
                    raise self.fail("unterminated CDATA section")
                if stack:
                    stack[-1].text += text[start + 9 : end]
                self.position = end + 3
                continue
            if text.startswith("<?", start):
                end = text.find("?>", start + 2)
                if end < 0:
                    raise self.fail("unterminated processing instruction")
                instruction = text[start + 2 : end]
                if not (instruction == "xml" or re.match(r"xml\s", instruction)):
                    raise self.fail(
                        "processing instructions other than the XML declaration are refused"
                    )
                self.position = end + 2
                continue
            if text.startswith("<!", start):
                # DOCTYPE, ENTITY, ELEMENT, ATTLIST: the hazards live here, and no build
                # descriptor needs one.
                raise self.fail("DTDs and entity declarations are refused")
            end = self._tag_end(start)
            body = text[start + 1 : end]
            self.position = end + 1
            if body.startswith("/"):
                name = body[1:].strip()
                # Messages name lines, never content: an element name is the document's text.
                if not stack or stack[-1].tag != name:
                    raise self.fail("a closing tag does not match the element it closes")
                stack.pop()
                continue
            closing = body.endswith("/")
            body = body[:-1] if closing else body
            name_match = _NAME.match(body)
            if not name_match:
                raise self.fail("malformed element name")
            self.count += 1
            if self.count > MAX_ELEMENTS:
                raise self.fail(f"more than {MAX_ELEMENTS} elements")
            element = Element(
                tag=name_match.group(0),
                attributes={
                    m.group(1): self.decode(
                        m.group(2) if m.group(2) is not None else m.group(3) or ""
                    )
                    for m in _ATTRIBUTE.finditer(body[name_match.end() :])
                },
                line=self.line(),
            )
            if stack:
                stack[-1].children.append(element)
            elif root is None:
                root = element
            else:
                raise self.fail("a second root element")
            if not closing:
                stack.append(element)
                if len(stack) > MAX_DEPTH:
                    raise self.fail(f"nested deeper than {MAX_DEPTH}")
        if stack:
            raise self.fail(f"the element opened on line {stack[-1].line} is never closed")
        if root is None:
            raise self.fail("no root element")
        return root

    def _tag_end(self, start: int) -> int:
        quote = ""
        index = start + 1
        text = self.text
        while index < len(text):
            character = text[index]
            if quote:
                if character == quote:
                    quote = ""
            elif character in "\"'":
                quote = character
            elif character == ">":
                return index
            elif character == "<":
                raise self.fail("'<' inside a tag")
            index += 1
        raise self.fail("unterminated tag")


__all__ = ["Element", "SafeXml", "SafeXmlError"]
