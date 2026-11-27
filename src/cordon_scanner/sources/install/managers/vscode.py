"""Editor extensions (`code --install-extension`, and the editors built on it): every `.vsix` fetched from Open VSX
and checked before the editor installs it.

The editor would fetch from the Visual Studio Marketplace, whose terms allow only Microsoft's own products to use it;
Cordon never sends a request there. An extension is fetched from Open VSX instead, as the `.vsix` it signs: the file is held to
the SHA-256 Open VSX publishes beside it and its Ed25519 signature is verified against the key this package pins
(`intel/provenance/releases/openvsx_signature`). Only a verified package is scanned, and the editor is then run on those very
files (`--install-extension <file>.vsix`), never on a name. An extension Open VSX does not hold, or holds unsigned, is refused.

An extension names others it needs (`extensionDependencies`) or bundles (`extensionPack`), and the editor installs those on its
own from the Marketplace. They are resolved here the same way, depth first, and installed before the extension that needs them,
so the editor finds every one already installed. A `.vsix` the person names by path is scanned as it is (no registry signed
it), and what it needs is resolved the same way.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


@dataclass(frozen=True)
class VscodePlan:
    plan: InstallPlan
    #: The `.vsix` files to install, each after the ones it needs.
    packages: tuple[Path, ...]
    #: The command line without its `--install-extension` words.
    rest: tuple[str, ...]


class VscodePlanner:
    FLAG: ClassVar[str] = "--install-extension"
    MAX_EXTENSIONS: ClassVar[int] = 25
    MAX_DEPTH: ClassVar[int] = 6
    MAX_MANIFEST: ClassVar[int] = 4 << 20
    IDENTIFIER: ClassVar[re.Pattern[str]] = re.compile(
        r"[A-Za-z0-9][\w-]{0,100}\.[A-Za-z0-9][\w-]{0,100}"
    )
    VERSION: ClassVar[re.Pattern[str]] = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
    TERMS: ClassVar[str] = (
        "Cordon never requests the Visual Studio Marketplace: its terms allow only Microsoft's own "
        "products to use it. Install it from a .vsix you have checked: "
        "`--install-extension path/to/file.vsix` is scanned like any other"
    )

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        return any(a == cls.FLAG or a.startswith(cls.FLAG + "=") for a in args)

    @classmethod
    def split(cls, args: Sequence[str]) -> tuple[list[str], list[str]]:
        """`(the command line without its install words, the extensions asked for)`."""
        rest: list[str] = []
        wanted: list[str] = []
        at = 0
        while at < len(args):
            word = args[at]
            if word == cls.FLAG:
                if at + 1 >= len(args):
                    raise InstallRefused(f"{cls.FLAG} names no extension")
                wanted.append(args[at + 1])
                at += 2
                continue
            if word.startswith(cls.FLAG + "="):
                wanted.append(word.partition("=")[2])
            else:
                rest.append(word)
            at += 1
        return rest, wanted

    @classmethod
    def plan(
        cls,
        args: Sequence[str],
        directory: Path,
        signed: Callable[[str, str], Any] | None = None,
        latest: Callable[[str], str] | None = None,
    ) -> VscodePlan:
        rest, wanted = cls.split(args)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        run = _Run(directory, signed or cls.signed, latest or cls.latest)
        for spec in wanted:
            run.add(spec, depth=0)
        return VscodePlan(InstallPlan("vscode", local=[directory]), tuple(run.order), tuple(rest))

    @staticmethod
    def signed(name: str, version: str) -> Any:
        """The release's package once Open VSX's signature on it verifies, or the answer saying why not."""
        from cordon_scanner.intel.provenance.releases.openvsx_signature import OpenVsxSignature
        from cordon_scanner.intel.registries.openvsx import API, OpenVsx
        from cordon_scanner.intel.registries.registry_request import RegistryError

        namespace, extension = OpenVsx.split(name)
        try:
            document = OpenVsx._json(f"{API}/{namespace}/{extension}/{version}")
        except RegistryError as exc:
            raise InstallRefused(
                f"{name} {version} is not on Open VSX ({exc}). {VscodePlanner.TERMS}"
            ) from exc
        target = document.get("targetPlatform")
        if target != "universal":
            raise InstallRefused(
                f"{name} {version} is built per platform (Open VSX answered for {target}), and "
                "Cordon cannot yet pick the build your editor would take: install the right "
                "build from a .vsix you have downloaded, which is scanned like any other"
            )
        return OpenVsxSignature.signed_package(name, version)

    @staticmethod
    def latest(name: str) -> str:
        """The newest release Open VSX lists for `name`; `InstallRefused` when it lists none."""
        from cordon_scanner.intel.registries.openvsx import API, OpenVsx
        from cordon_scanner.intel.registries.registry_request import RegistryError

        namespace, extension = OpenVsx.split(name)
        try:
            document = OpenVsx._json(f"{API}/{namespace}/{extension}")
        except RegistryError as exc:
            raise InstallRefused(
                f"{name} is not on Open VSX ({exc}). {VscodePlanner.TERMS}"
            ) from exc
        version = document.get("version")
        if not isinstance(version, str) or not VscodePlanner.VERSION.fullmatch(version):
            raise InstallRefused(f"{name} is not on Open VSX. {VscodePlanner.TERMS}")
        return version

    @classmethod
    def needs(cls, package: bytes) -> list[str]:
        """The extensions a package names in its `extensionDependencies` and `extensionPack`."""
        try:
            with zipfile.ZipFile(io.BytesIO(package)) as archive:
                info = archive.getinfo("extension/package.json")
                if info.file_size > cls.MAX_MANIFEST:
                    raise InstallRefused("an extension manifest larger than any real one")
                manifest = json.loads(archive.read(info))
        except (zipfile.BadZipFile, KeyError, ValueError, OSError) as exc:
            raise InstallRefused(
                f"an extension package whose manifest cannot be read: {exc}"
            ) from exc
        found: list[str] = []
        for key in ("extensionDependencies", "extensionPack"):
            listed = manifest.get(key) if isinstance(manifest, dict) else None
            found += [e for e in listed if isinstance(e, str)] if isinstance(listed, list) else []
        return found


class _Run:
    """One resolution: the packages written so far, in install order."""

    def __init__(
        self, directory: Path, signed: Callable[[str, str], Any], latest: Callable[[str], str]
    ) -> None:
        self.directory = directory
        self.signed = signed
        self.latest = latest
        self.order: list[Path] = []
        self.seen: set[str] = set()

    def add(self, spec: str, depth: int) -> None:
        if depth > VscodePlanner.MAX_DEPTH:
            raise InstallRefused(
                f"{spec}: extensions needing extensions more than {VscodePlanner.MAX_DEPTH} deep"
            )
        if spec.lower().endswith(".vsix"):
            self.local(spec, depth)
            return
        name, _, version = spec.partition("@")
        if not VscodePlanner.IDENTIFIER.fullmatch(name):
            raise InstallRefused(f"{spec} is not a publisher.extension name or a .vsix file")
        key = name.lower()
        if key in self.seen:
            return
        if len(self.seen) >= VscodePlanner.MAX_EXTENSIONS:
            raise InstallRefused(
                f"more than {VscodePlanner.MAX_EXTENSIONS} extensions would be installed"
            )
        self.seen.add(key)
        version = version or self.latest(name)
        if not VscodePlanner.VERSION.fullmatch(version):
            raise InstallRefused(f"{spec}: {version!r} is not a version")
        answer = self.signed(name, version)
        if not isinstance(answer, tuple):
            raise InstallRefused(
                f"{name} {version} could not be verified against Open VSX: {answer.detail}. "
                "An extension is installed only from a package Open VSX signed"
            )
        package = answer[0]
        for needed in VscodePlanner.needs(package):
            self.add(needed, depth + 1)
        self.keep(f"{name}-{version}", package)

    def local(self, spec: str, depth: int) -> None:
        path = Path(spec).expanduser()
        if not path.is_file() or path.is_symlink():
            raise InstallRefused(f"{spec} is not a file Cordon can read")
        package = path.read_bytes()
        for needed in VscodePlanner.needs(package):
            self.add(needed, depth + 1)
        self.keep(f"local-{len(self.order)}-{path.name}", package)

    def keep(self, stem: str, package: bytes) -> None:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:120].removesuffix(".vsix")
        target = self.directory / f"{safe}.vsix"
        target.write_bytes(package)
        target.chmod(0o600)
        self.order.append(target)


__all__ = ["VscodePlan", "VscodePlanner"]
