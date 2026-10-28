"""An install hook that runs an obfuscated in-tree file (review 98 P4-E, shape B).

A `postinstall: node <file>` whose target is JSFuck, or a line of kana / `_0x` identifiers, runs
code on every install that no content detector can read. The engine flags the target (the manifest
detector cannot read sibling bytes), and `manifest.py` blocks it as
`SUSPECT.INSTALL.OBFUSCATED_HOOK.001`. A hook that runs a readable file does not fire. Every fixture
here is inert text scanned in a tarball; none is run.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner

RULE = "SUSPECT.INSTALL.OBFUSCATED_HOOK.001"
#: JSFuck-dense: over 2,000 characters, every one of them in `[]()!+`.
JSFUCK = "[]()!+" * 400 + "\n"
#: A line over 2,000 characters that is almost all kana identifiers.
KANA = "const " + "ソゾギダぢヾ" * 400 + " = 1;\n"
#: A line over 2,000 characters renamed into `_0x` hex identifiers -- the hex-name packer.
HEX_PACKER = "var x=[" + ",".join(f"_0x{i:04x}" for i in range(300)) + "];\n"
#: A README carried as one long `long_description` string literal: over 2,000 characters of
#: natural-language prose with accents (about 9% non-ASCII) and no `_0x` names. This is the census
#: D false block -- a one-in-fifty off-ASCII bar read it as packed; it is readable (7 benign PyPI
#: setup.py lines: businessowner-retriever, declatravaux, viburnum, nonebot-plugin-hammer, ...).
README_PROSE = (
    'const long_description = "'
    + "a readable sentence with a few accents café déjà naïve résumé here. " * 35
    + '";\n'
)
READABLE = (
    'const fs = require("fs");\nconsole.log("building");\nfs.writeFileSync("out.txt", "ok");\n'
)


class Kit:
    @staticmethod
    def scan(tmp_path: Path, target_content: str, main: str = "index.js") -> list[tuple[str, str]]:
        manifest = {"name": "x", "version": "1.0.0", "scripts": {"postinstall": f"node {main}"}}
        members = {
            "package/package.json": json.dumps(manifest).encode(),
            f"package/{main}": target_content.encode(),
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, data in members.items():
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "x-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return [(f.rule_id, str(f.severity)) for f in Scanner().scan(target).findings]


class TestObfuscatedHook:
    def test_a_jsfuck_install_target_blocks(self, tmp_path: Path) -> None:
        found = Kit.scan(tmp_path, JSFUCK)
        assert any(r == RULE and s == "high" for r, s in found), found

    def test_a_kana_dense_install_target_blocks(self, tmp_path: Path) -> None:
        found = Kit.scan(tmp_path, KANA)
        assert any(r == RULE and s == "high" for r, s in found), found

    def test_a_hex_name_packer_install_target_blocks(self, tmp_path: Path) -> None:
        found = Kit.scan(tmp_path, HEX_PACKER)
        assert any(r == RULE and s == "high" for r, s in found), found

    def test_a_readable_install_target_does_not_fire(self, tmp_path: Path) -> None:
        found = Kit.scan(tmp_path, READABLE)
        assert not [r for r, _ in found if r == RULE], found

    def test_a_readme_prose_long_description_does_not_fire(self, tmp_path: Path) -> None:
        # census D: a README carried as one long string literal is natural-language prose, not a
        # packed hook. Off-ASCII accents at a fifth of the line or less, and no `_0x` names.
        found = Kit.scan(tmp_path, README_PROSE)
        assert not [r for r, _ in found if r == RULE], found

    def test_an_editor_extension_entry_is_not_an_install_hook(self) -> None:
        # A .vsix activation entry is in install_hook_paths too, but the editor starts it, not npm,
        # and it ships minified -- a dense bundle that is not a packed install hook (review 98: 5
        # benign Open VSX extensions blocked here).
        from cordon_scanner.detect.base import FileUnit, ScanContext
        from cordon_scanner.detect.supply.obfuscated_hook import ObfuscatedHookDetector
        from cordon_scanner.foundation.config.settings import Config
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        path = "ext-1.0.0.vsix!extension/dist/extension.js"
        unit = FileUnit(content=FileContent.from_bytes(path, KANA.encode()))
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            install_hook_paths=frozenset({path}),
        )
        assert list(ObfuscatedHookDetector().inspect(unit, ctx)) == []
