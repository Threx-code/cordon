"""Editor extensions (VS Code Marketplace and Open VSX): the extensions a workspace asks for, as dependencies.

```
  .vscode/extensions.json              `recommendations`: extension ids a workspace asks its editor to install
                                       (`unwantedRecommendations` names ones it asks not to: never dependencies)
  <name>.code-workspace                `extensions.recommendations`, the same list for a multi-root workspace
  .devcontainer/devcontainer.json,     `customizations.vscode.extensions` (and the older top-level `extensions`):
  .devcontainer/<name>/devcontainer.json,  ids installed into the container, `publisher.name` or
  .devcontainer.json                   `publisher.name@version`; `-publisher.name` asks for one NOT to be installed
  .gitpod.yml                          `vscode.extensions`: Open VSX ids, `id@version`, or the URL of a .vsix
  extension.vsixmanifest               an extension's own manifest inside its .vsix: its identity (publisher,
                                       name, version) and the extensions it depends on or packs
```

An extension is `publisher.name`, compared case-insensitively as the editor does. Only an entry written
`@version`, or an extension's own manifest, names a version: a recommendation is an id only, so it carries no
version, and nothing is guessed for it. A .vsix named by URL is an archive source: its name is the file's, its
source the URL. An extension runs in the editor with the user's rights the moment it is enabled: every one is a
runtime dependency.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)
from cordon_scanner.ecosystems.own_names import OwnName
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


class VsixUrl:
    """A .vsix named by an https URL (a Gitpod entry): `(file name without .vsix, "")`, or None."""

    @staticmethod
    def parse(value: Any) -> tuple[str, str] | None:
        from urllib.parse import urlsplit

        if not isinstance(value, str) or len(value) > 2048 or "://" not in value:
            return None
        parts = urlsplit(value.strip())
        stem = parts.path.rsplit("/", 1)[-1]
        if parts.scheme != "https" or not parts.hostname or not stem.lower().endswith(".vsix"):
            return None
        name = stem[: -len(".vsix")].lower()
        return (name, "") if name and set(name) <= ExtensionId.CHARS | {"."} else None


class VsCodeEcosystem(BaseEcosystem):
    """Editor extensions, read from the files that name them."""

    id = "vscode"
    own_name = OwnName(
        ("extension/package.json",),
        readers=(("extension/package.json", "extension_manifest"),),
    )
    purl_type = "vscode-extension"
    manifest_globs: tuple[str, ...] = (
        "**/.vscode/extensions.json",
        "**/*.code-workspace",
        "**/.devcontainer/devcontainer.json",
        "**/.devcontainer/*/devcontainer.json",
        "**/.devcontainer.json",
        "**/.gitpod.yml",
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

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        from urllib.parse import urlsplit

        return bool(url) and (urlsplit(str(url)).hostname or "") in self.REGISTRY_HOSTS

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(
            path=content.path, ecosystem=self.id, parse_error="extensions have no lock file"
        )

    #: Each file kind by its name's ending, the reader that takes its document, and the field read.
    READERS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("extension.vsixmanifest", "_vsix", "ExtensionDependencies"),
        (".code-workspace", "_workspace", "extensions.recommendations"),
        ("extensions.json", "_recommendations", "recommendations"),
        (".gitpod.yml", "_gitpod", "vscode.extensions"),
        ("devcontainer.json", "_devcontainer", "customizations.vscode.extensions"),
    )

    def parse_manifest(self, content: FileContent) -> Manifest:
        reader = next(
            (r for r in self.READERS if content.path.rsplit("/", 1)[-1].endswith(r[0])), None
        )
        if reader is None:
            return BaseEcosystem._err(content, self.id, "not a file that names extensions")
        if reader[1] == "_vsix":
            return self._vsix(content)
        read = getattr(self, reader[1])
        try:
            data = self._yaml(content) if content.path.endswith(".yml") else self._jsonc(content)
        except ValueError as exc:
            return BaseEcosystem._err(content, self.id, str(exc))
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, self.id, "not a mapping")
        entries, field = read(data, reader[2])
        return Manifest(
            path=content.path, ecosystem=self.id, dependencies=self._declared(entries, field)
        )

    @staticmethod
    def _jsonc(content: FileContent) -> Any:
        from cordon_scanner.foundation.formats.jsonc import Jsonc

        data = Jsonc.loads(content.text)
        if data is None and content.text.strip():
            raise ValueError("not a JSON object")
        return data

    @staticmethod
    def _yaml(content: FileContent) -> Any:
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        return DataYaml.load(content.text, source=content.path)

    @staticmethod
    def _recommendations(data: dict[str, Any], field: str) -> tuple[Any, str]:
        return data.get("recommendations"), field

    @staticmethod
    def _workspace(data: dict[str, Any], field: str) -> tuple[Any, str]:
        extensions = data.get("extensions")
        return (extensions.get("recommendations") if isinstance(extensions, dict) else None), field

    @staticmethod
    def _gitpod(data: dict[str, Any], field: str) -> tuple[Any, str]:
        vscode = data.get("vscode")
        return (vscode.get("extensions") if isinstance(vscode, dict) else None), field

    @staticmethod
    def _devcontainer(data: dict[str, Any], field: str) -> tuple[Any, str]:
        customizations = data.get("customizations")
        vscode = customizations.get("vscode") if isinstance(customizations, dict) else None
        if isinstance(vscode, dict):
            return vscode.get("extensions"), field
        return data.get("extensions"), "extensions"

    def _declared(self, entries: Any, field: str) -> tuple[DeclaredDependency, ...]:
        found: dict[str, DeclaredDependency] = {}
        for entry in entries if isinstance(entries, list) else ():
            if isinstance(entry, str) and entry.strip().startswith("-"):
                continue  # `-publisher.name`: asks for the extension NOT to be installed
            archive = VsixUrl.parse(entry)
            parsed = archive or ExtensionId.parse(entry)
            if parsed is None or parsed[0] in found:
                continue
            ident, version = parsed
            found[ident] = DeclaredDependency(
                name=ident,
                spec=version or "*",
                scope=Scope.RUNTIME,
                field_name=field,
                ecosystem=self.id,
                source=entry.strip() if archive else None,
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


__all__ = ["ExtensionId", "VsCodeEcosystem", "VsixUrl"]
