"""Editor extensions (VS Code Marketplace and Open VSX): the extensions a workspace asks for, as dependencies.

```
  .vscode/extensions.json          `recommendations`: extension ids a workspace asks its editor to install
  .devcontainer/devcontainer.json  `customizations.vscode.extensions` (and the older top-level `extensions`):
  .devcontainer.json               ids installed into the container, `publisher.name` or `publisher.name@version`
  extension.vsixmanifest           an extension's own manifest inside its .vsix: its identity (publisher, name,
                                   version) and the extensions it depends on or packs
```

An extension is `publisher.name`, compared case-insensitively as the editor does. Only a devcontainer entry
written `@version`, or an extension's own manifest, names a version: a recommendation is an id only, so it
carries no version, and nothing is guessed for it. An extension runs in the editor with the user's rights the
moment it is enabled: every one is a runtime dependency.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.archive_shapes import VsixArchive
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)
from cordon_scanner.foundation.models import Scope

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class ExtensionId:
    """`publisher.name`, the editor's own identifier, and the version a pin names."""

    #: The characters the Marketplace and Open VSX allow in a publisher and an extension name.
    CHARS: ClassVar[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
    MAX: ClassVar[int] = 256

    @classmethod
    def parse(cls, value: Any) -> tuple[str, str] | None:
        """`(publisher.name, version or "")` from `publisher.name` or `publisher.name@version`; None when the
        value is not an extension id."""
        if not isinstance(value, str) or not value or len(value) > cls.MAX:
            return None
        ident, _, version = value.strip().partition("@")
        publisher, dot, name = ident.lower().partition(".")
        if not dot or not publisher or not name or "." in name:
            return None
        if not set(publisher) <= cls.CHARS or not set(name) <= cls.CHARS:
            return None
        return f"{publisher}.{name}", version.strip()


class VsCodeEcosystem(BaseEcosystem):
    """Editor extensions, read from the files that name them."""

    id = "vscode"
    purl_type = "vscode-extension"
    published_archive = (VsixArchive(),)
    manifest_globs: tuple[str, ...] = (
        "**/.vscode/extensions.json",
        "**/.devcontainer/devcontainer.json",
        "**/.devcontainer.json",
        "**/extension.vsixmanifest",
    )
    lockfile_globs: tuple[str, ...] = ()
    #: Where extensions are published and served from.
    REGISTRY_HOSTS: ClassVar[frozenset[str]] = frozenset(
        {"open-vsx.org", "openvsx.eclipsecontent.org", "marketplace.visualstudio.com"}
    )
    #: The vsixmanifest properties that name other extensions, comma-separated.
    DEPENDENCY_PROPERTIES: ClassVar[tuple[str, ...]] = (
        "Microsoft.VisualStudio.Code.ExtensionDependencies",
        "Microsoft.VisualStudio.Code.ExtensionPack",
    )

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.split(".", 1)[0] if "." in name else None

    # -- the projects mcp writes for a package check (EcosystemProjects) ------------

    def pinned_project(self, pins: Sequence[tuple[str, str]]) -> dict[str, str] | None:
        """A dev container installing these extensions at these versions: `{path: content}`."""
        extensions = [f"{name}@{version}" for name, version in pins]
        body = {"customizations": {"vscode": {"extensions": extensions}}}
        return {".devcontainer/devcontainer.json": json.dumps(body)}

    def loose_project(self, names: Sequence[str]) -> dict[str, str] | None:
        """The extensions a workspace recommends, with no version: `{path: content}`."""
        return {".vscode/extensions.json": json.dumps({"recommendations": list(names)})}

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        from urllib.parse import urlsplit

        return bool(url) and (urlsplit(str(url)).hostname or "") in self.REGISTRY_HOSTS

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(
            path=content.path, ecosystem=self.id, parse_error="extensions have no lock file"
        )

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.path.rsplit("/", 1)[-1] == "extension.vsixmanifest":
            return self._vsix(content)
        from cordon_scanner.foundation.formats.jsonc import Jsonc

        data = Jsonc.loads(content.text)
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, self.id, "not a JSON object")
        if content.path.endswith("extensions.json"):
            entries, field = data.get("recommendations"), "recommendations"
        else:
            vscode = (
                (data.get("customizations") or {}).get("vscode")
                if isinstance(data.get("customizations"), dict)
                else None
            )
            entries = (
                vscode.get("extensions") if isinstance(vscode, dict) else data.get("extensions")
            )
            field = "customizations.vscode.extensions" if isinstance(vscode, dict) else "extensions"
        return Manifest(
            path=content.path, ecosystem=self.id, dependencies=self._declared(entries, field)
        )

    def _declared(self, entries: Any, field: str) -> tuple[DeclaredDependency, ...]:
        found: dict[str, DeclaredDependency] = {}
        for entry in entries if isinstance(entries, list) else ():
            parsed = ExtensionId.parse(entry)
            if parsed is None or parsed[0] in found:
                continue
            ident, version = parsed
            found[ident] = DeclaredDependency(
                name=ident,
                spec=version or "*",
                scope=Scope.RUNTIME,
                field_name=field,
                ecosystem=self.id,
            )
        return tuple(found.values())

    def _vsix(self, content: FileContent) -> Manifest:
        from cordon_scanner.foundation.formats.safexml import SafeXml

        try:
            root = SafeXml.parse(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, self.id, f"not a readable vsixmanifest: {exc}")
        identity = root.find("Metadata", "Identity")
        attributes = identity.attributes if identity is not None else {}
        publisher, name = attributes.get("Publisher", ""), attributes.get("Id", "")
        own = ExtensionId.parse(f"{publisher}.{name}@{attributes.get('Version', '')}")
        named: list[str] = []
        properties = root.find("Metadata", "Properties")
        for item in properties.children if properties is not None else ():
            if item.local == "Property" and item.attributes.get("Id") in self.DEPENDENCY_PROPERTIES:
                named.extend(v for v in item.attributes.get("Value", "").split(",") if v.strip())
        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=own[0] if own else None,
            version=(own[1] or None) if own else None,
            dependencies=self._declared(named, "ExtensionDependencies"),
        )


__all__ = ["ExtensionId", "VsCodeEcosystem"]
