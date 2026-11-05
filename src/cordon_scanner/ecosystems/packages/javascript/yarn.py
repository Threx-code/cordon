"""yarn.lock, classic and Berry: its blocks, the descriptors each resolves, and the graph between them."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.base import (
    LockEntry,
    LockGraph,
)

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class YarnLock:
    """Yarn's lockfile: Classic (v1, its own format) and Berry (2+, YAML).

    Both key an entry by the descriptors that resolved to it (`"lodash@^4.17.20, lodash@^4.17.21"`)
    and list each entry's dependencies as descriptors, so the edges are followed descriptor to
    entry -- which is also how an alias (`chalk-four@npm:chalk@4.1.2`) is seen to be `chalk`.

    Code that is not fetched carries no hash and is the project's own: Berry's `workspace:`,
    `link:`, `portal:`, `file:` and `exec:` protocols, a `linkType: soft`, and `patch:` (Yarn
    applying a built-in compatibility patch to a package that carries its own checksum one entry
    away). Every Berry lockfile also holds the root workspace itself (`app@workspace:.`); that is
    the project, not one of its dependencies, so it contributes the direct edges and no entry.
    """

    LOCAL_PROTOCOLS = ("workspace:", "link:", "portal:", "file:", "exec:", "patch:")
    LOCAL_VERSION = "0.0.0-use.local"

    @staticmethod
    def descriptor_name(descriptor: str) -> tuple[str, str]:
        """`(name, range)` of `name@range`, keeping a scope's leading `@`."""
        text = descriptor.strip().strip('"')
        at = text.find("@", 1 if text.startswith("@") else 0)
        if at <= 0:
            return text, ""
        return text[:at], text[at + 1 :]

    @staticmethod
    def alias_target(reference: str) -> str | None:
        """`npm:chalk@4.1.2` names `chalk`; `npm:^4.1.0` names nothing."""
        if not reference.startswith("npm:"):
            return None
        body = reference[4:]
        at = body.find("@", 1 if body.startswith("@") else 0)
        return body[:at] if at > 0 else None

    @classmethod
    def parse(cls, content: FileContent, ecosystem: str) -> LockGraph:
        text = content.text
        # Berry is YAML: `__metadata:` in a whole file, `version: 1.2.3` (with a colon) in any
        # entry. Classic writes `version "1.2.3"`.
        if "__metadata:" in text or re.search(r"(?m)^ {2}(?:version|resolution|checksum):\s", text):
            return cls._berry(content, ecosystem)
        return cls._classic(content, ecosystem)

    @classmethod
    def _graph(
        cls,
        content: FileContent,
        ecosystem: str,
        blocks: list[tuple[list[str], dict[str, Any]]],
        *,
        berry: bool,
    ) -> LockGraph:
        by_descriptor: dict[str, int] = {}
        for index, (descriptors, _) in enumerate(blocks):
            for descriptor in descriptors:
                by_descriptor[descriptor] = index
        names: list[str] = []
        root_indices: set[int] = set()
        members: list[str] = []
        for descriptors, meta in blocks:
            resolution = str(meta.get("resolution") or "")
            name = cls.descriptor_name(resolution)[0] if resolution else ""
            if not name:
                first, reference = cls.descriptor_name(descriptors[0])
                name = cls.alias_target(reference) or first
            names.append(name)
        edges = cls._edges(blocks, root_indices, members, berry, by_descriptor)
        direct = {t for r in root_indices for t in edges.get(r, ())}
        for index, (_, meta) in enumerate(blocks):
            resolution = str(meta.get("resolution") or "")
            if (
                cls.descriptor_name(resolution)[1].startswith("workspace:")
                and index not in root_indices
            ):
                direct |= edges.get(index, set())
        entries = cls._entries(blocks, root_indices, names, berry, edges, direct)
        # Berry records a workspace member twice when the root also names it by path
        # (`local-util@workspace:packages/util` and `local-util@file:packages/util`): one
        # package, kept once, with the version the member's own manifest gives it.
        kept: dict[str, LockEntry] = {}
        out: list[LockEntry] = []
        for entry in entries:
            if not entry.local:
                out.append(entry)
                continue
            previous = kept.get(entry.name)
            if previous is None or (not previous.version and entry.version):
                kept[entry.name] = entry
        out.extend(kept.values())
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(out),
            workspaces=tuple(sorted(members)),
        )

    @classmethod
    def _edges(
        cls,
        blocks: list[tuple[list[str], dict[str, Any]]],
        root_indices: set[int],
        members: list[str],
        berry: bool,
        by_descriptor: dict[str, int],
    ) -> dict[int, set[int]]:
        """Each block's edges to the blocks its dependencies resolve to."""
        edges: dict[int, set[int]] = {}
        for index, (_descriptors, meta) in enumerate(blocks):
            resolution = str(meta.get("resolution") or "")
            protocol = cls.descriptor_name(resolution)[1] if resolution else ""
            if protocol == "workspace:.":
                root_indices.add(index)
            elif protocol.startswith("workspace:"):
                members.append(protocol[len("workspace:") :])
            for field in ("dependencies", "optionalDependencies"):
                section = meta.get(field)
                if not isinstance(section, dict):
                    continue
                for dep, reference in section.items():
                    descriptor = f"{dep}@{reference}"
                    if berry and not str(reference).startswith(
                        tuple(
                            p
                            for p in (
                                "npm:",
                                "workspace:",
                                "patch:",
                                "link:",
                                "portal:",
                                "file:",
                                "exec:",
                                "git",
                                "http",
                                "github:",
                            )
                        )
                    ):
                        descriptor = f"{dep}@npm:{reference}"
                    target = by_descriptor.get(descriptor)
                    if target is None:
                        target = by_descriptor.get(f"{dep}@{reference}")
                    if target is not None:
                        edges.setdefault(index, set()).add(target)
        return edges

    @classmethod
    def _entries(
        cls,
        blocks: list[tuple[list[str], dict[str, Any]]],
        root_indices: set[int],
        names: list[str],
        berry: bool,
        edges: dict[int, set[int]],
        direct: set[int],
    ) -> list[LockEntry]:
        """One entry per block: its name, version, scope, whether it is direct, and its source."""
        entries: list[LockEntry] = []
        for index, (descriptors, meta) in enumerate(blocks):
            if index in root_indices:
                continue
            resolution = str(meta.get("resolution") or "")
            protocol = cls.descriptor_name(resolution)[1] if resolution else ""
            version = str(meta.get("version") or "")
            local = (
                any(protocol.startswith(p) for p in cls.LOCAL_PROTOCOLS)
                or any(
                    cls.descriptor_name(d)[1].startswith(cls.LOCAL_PROTOCOLS) for d in descriptors
                )
                or meta.get("linkType") == "soft"
                or version == cls.LOCAL_VERSION
            )
            declared_names = {cls.descriptor_name(d)[0] for d in descriptors}
            alias = next((n for n in sorted(declared_names) if n != names[index]), None)
            resolved = meta.get("resolved") if isinstance(meta.get("resolved"), str) else None
            if berry and protocol and not protocol.startswith("npm:") and not local:
                resolved = protocol
            integrity = meta.get("integrity") or meta.get("checksum")
            platform: list[str] = []
            conditions = meta.get("conditions")
            if isinstance(conditions, str):
                platform.extend(c.strip().replace("=", ": ", 1) for c in conditions.split("&"))
            entries.append(
                LockEntry(
                    name=names[index],
                    version="" if version == cls.LOCAL_VERSION else version,
                    integrity=str(integrity) if isinstance(integrity, str) else None,
                    resolved_from=resolved,
                    dependencies=tuple(sorted({names[t] for t in edges.get(index, ())})),
                    direct=index in direct,
                    local=local,
                    platform=tuple(platform),
                    alias=alias,
                )
            )
        return entries

    @classmethod
    def _berry(cls, content: FileContent, ecosystem: str) -> LockGraph:
        from cordon_scanner.foundation.formats.datayaml import DataYaml, DataYamlError

        try:
            data = DataYaml.load(content.text, source=content.path)
        except DataYamlError as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid YAML: {exc}"
            )
        if not isinstance(data, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="top level is not a mapping"
            )
        blocks = [
            ([d.strip() for d in str(key).split(",") if d.strip()], meta)
            for key, meta in data.items()
            if key != "__metadata" and isinstance(meta, dict)
        ]
        if not blocks and len(data) > 1:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no entry could be read"
            )
        return cls._graph(content, ecosystem, blocks, berry=True)

    _CLASSIC_FIELD = re.compile(r'^(\s+)("?[^"\s]+"?)\s+"?([^"]*)"?\s*$')

    @classmethod
    def _classic(cls, content: FileContent, ecosystem: str) -> LockGraph:
        blocks: list[tuple[list[str], dict[str, Any]]] = []
        current: dict[str, Any] | None = None
        section: dict[str, str] | None = None
        unreadable = 0
        for raw in content.text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if not raw[0].isspace():
                header = raw.strip().rstrip(":")
                descriptors = [d.strip().strip('"') for d in header.split(",") if d.strip()]
                if not raw.rstrip().endswith(":") or not descriptors:
                    unreadable += 1
                    current = None
                    continue
                current = {}
                section = None
                blocks.append((descriptors, current))
                continue
            if current is None:
                continue
            indent = len(raw) - len(raw.lstrip())
            stripped = raw.strip()
            if stripped.endswith(":") and " " not in stripped:
                section = {}
                current[stripped[:-1]] = section
                continue
            match = cls._CLASSIC_FIELD.match(raw)
            if not match:
                continue
            key, value = match.group(2).strip('"'), match.group(3)
            if indent > 2 and section is not None:
                section[key] = value
            else:
                section = None
                current[key] = value
        if unreadable and not blocks:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} entry header(s) could not be read",
            )
        return cls._graph(content, ecosystem, blocks, berry=False)


__all__ = ["YarnLock"]
