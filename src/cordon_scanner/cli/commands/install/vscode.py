"""`code`, `codium`, `cursor` and the other editors with the VS Code command line: `--install-extension` installs only
packages Open VSX signed, scanned first, by file (never by name, which would send the editor to the Marketplace)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cordon_scanner.cli.commands.install.context import InstallContext


class VscodeTools:
    @staticmethod
    def installs(args: list[str]) -> bool:
        from cordon_scanner.sources.install.managers.vscode import VscodePlanner

        return VscodePlanner.installs(args)

    @staticmethod
    def code(editor: str, args: list[str], context: InstallContext) -> int:
        from cordon_scanner.sources.install.managers.vscode import VscodePlanner
        from cordon_scanner.sources.install.plan import PrivateDirectory

        with PrivateDirectory.made("cordon-vsix-") as scratch:
            result = VscodePlanner.plan(args, scratch / "extensions")
            files = scratch / "files"
            files.mkdir(mode=0o700)
            verdict = context.check(result.plan, files)
            if not verdict.ok:
                return context.blocked(verdict)
            installs = [
                word for path in result.packages for word in (VscodePlanner.FLAG, str(path))
            ]
            return context.run([editor, *result.rest, *installs])


__all__ = ["VscodeTools"]
