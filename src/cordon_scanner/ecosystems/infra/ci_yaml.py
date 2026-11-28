"""CI pipeline YAML made plain enough for the hostile-input reader, which refuses anchors, aliases, tags and merge keys.

GitLab, Woodpecker, Bitbucket and CircleCI files use them everywhere (`image: *golang`, `<<: *defaults`, `!reference [...]`).
`CiYaml.plain` rewrites the text the way YAML would read it, by indentation and name only, nothing evaluated: a scalar alias
becomes the value its anchor names, a `<<: *name` merge becomes the keys of the anchor's mapping that the mapping does not
set itself, and a tag or a reference the text cannot resolve is dropped with its line. The reader then sees ordinary YAML.
"""

from __future__ import annotations

import re
from typing import ClassVar

MAX_DEPTH = 6
MAX_LINES = 200_000


class CiYaml:
    SCALAR_ANCHOR: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<lead>\s*(?:-\s+)?(?:[^\s:#&*!][^:]*:\s+)?)&(?P<name>[\w.-]+)\s+(?P<value>[^\s#].*)$"
    )
    MAPPING_ANCHOR: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<lead>\s*(?:-\s+)?(?:[^\s:#&*!][^:]*:\s*)?)&(?P<name>[\w.-]+)\s*(?:#.*)?$"
    )
    ALIAS: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<lead>\s*(?:-\s+)?(?:[^\s:#&*!][^:]*:\s+)?)\*(?P<name>[\w.-]+)\s*(?:#.*)?$"
    )
    MERGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?P<indent>\s*)<<:\s*(?P<names>\*[\w.-]+|\[[^\]]*\])\s*(?:#.*)?$"
    )
    KEY: ClassVar[re.Pattern[str]] = re.compile(r"^\s*(?:-\s+)?(?P<key>[^\s:#&*!-][^:]*):(?:\s|$)")
    TAG: ClassVar[re.Pattern[str]] = re.compile(r"(?<=[:\s-])![\w!<>:./-]+[ \t]*")

    @staticmethod
    def plain(text: str) -> str:
        lines = text.splitlines()[:MAX_LINES]
        blocks = CiYaml._blocks(lines)
        scalars: dict[str, str] = {}
        return "\n".join(CiYaml._rewrite(lines, blocks, scalars, 0)) + "\n"

    @staticmethod
    def indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    @staticmethod
    def _blocks(lines: list[str]) -> dict[str, list[str]]:
        """The lines under each `key: &name` header, indentation of the first line removed."""
        found: dict[str, list[str]] = {}
        for index, line in enumerate(lines):
            match = CiYaml.MAPPING_ANCHOR.match(line)
            if match is None:
                continue
            level = CiYaml.indent(line)
            body: list[str] = []
            for follower in lines[index + 1 :]:
                if follower.strip() and CiYaml.indent(follower) <= level:
                    break
                body.append(follower)
            first = next((CiYaml.indent(b) for b in body if b.strip()), 0)
            found.setdefault(match.group("name"), [b[first:] if b.strip() else "" for b in body])
        return found

    @staticmethod
    def _own_keys(lines: list[str], index: int, level: int) -> set[str]:
        """The keys the mapping holding line `index` sets itself, above and below it."""
        keys: set[str] = set()
        for step in (-1, 1):
            at = index + step
            while 0 <= at < len(lines):
                line = lines[at]
                if line.strip() and CiYaml.indent(line) < level:
                    break
                found = CiYaml.KEY.match(line) if CiYaml.indent(line) == level else None
                if found is not None:
                    keys.add(found.group("key").strip())
                at += step
        return keys

    @staticmethod
    def _children(block: list[str], skip: set[str]) -> list[str]:
        """The top-level entries of an anchor's block, without those keys the merging mapping sets."""
        out: list[str] = []
        keep = True
        for line in block:
            if not line.strip():
                continue
            if CiYaml.indent(line) == 0:
                found = CiYaml.KEY.match(line)
                keep = found is None or found.group("key").strip() not in skip
            if keep:
                out.append(line)
        return out

    @staticmethod
    def _rewrite(
        lines: list[str], blocks: dict[str, list[str]], scalars: dict[str, str], depth: int
    ) -> list[str]:
        out: list[str] = []
        for index, line in enumerate(lines):
            merge = CiYaml.MERGE.match(line)
            if merge is not None:
                level = len(merge.group("indent"))
                skip = CiYaml._own_keys(lines, index, level)
                for name in re.findall(r"\*([\w.-]+)", merge.group("names")):
                    block = blocks.get(name)
                    if block is not None and depth < MAX_DEPTH:
                        inner = CiYaml._rewrite(
                            CiYaml._children(block, skip), blocks, scalars, depth + 1
                        )
                        out.extend(" " * level + child for child in inner)
                continue
            plain = CiYaml._line(line, scalars)
            if plain is not None:
                out.append(plain)
        return out

    @staticmethod
    def _line(line: str, scalars: dict[str, str]) -> str | None:
        """One line made plain, or None when it cannot be (a tag the text does not resolve)."""
        scalar = CiYaml.SCALAR_ANCHOR.match(line)
        if scalar is not None:
            scalars[scalar.group("name")] = scalar.group("value")
            line = scalar.group("lead") + scalar.group("value")
        else:
            header = CiYaml.MAPPING_ANCHOR.match(line)
            if header is not None:
                line = header.group("lead").rstrip()
        alias = CiYaml.ALIAS.match(line)
        if alias is not None:
            value = scalars.get(alias.group("name"))
            if value is None:
                return None
            line = alias.group("lead") + value
        if line.lstrip().startswith(("- !reference", "!reference")) or re.search(
            r":\s+!reference\b", line
        ):
            return None
        return CiYaml.TAG.sub("", line)


__all__ = ["CiYaml"]
