"""A published gem, crate or Go module zip names its own release (`Engine._archive_release_identity`).

What is tested is where each format keeps its manifest inside its archive; nothing is fetched.
"""

from __future__ import annotations

import gzip

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.engine.engine import Engine
from cordon_scanner.foundation.content import FileContent


class Units:
    @staticmethod
    def at(path: str, raw: bytes) -> FileUnit:
        return FileUnit(content=FileContent.from_bytes(path, raw), language=None)


class TestIdentity:
    def test_a_gem_by_its_metadata(self):
        meta = b"name: demo\nversion: !ruby/object:Gem::Version\n  version: 1.2.3\n"
        unit = Units.at("x/demo-1.2.3.gem!metadata.gz", gzip.compress(meta))
        assert Engine._archive_release_identity(unit) == ("rubygems", "demo", "1.2.3")

    def test_a_crate_by_its_manifest_directory(self):
        unit = Units.at("x/demo-0.3.10.crate!demo-0.3.10/Cargo.toml", b"[package]\n")
        assert Engine._archive_release_identity(unit) == ("cargo", "demo", "0.3.10")

    def test_a_go_module_zip_by_its_go_mod(self):
        unit = Units.at(
            "x/m.zip!example.invalid/mod@v1.0.0/go.mod", b"module example.invalid/mod\n"
        )
        assert Engine._archive_release_identity(unit) == ("gomod", "example.invalid/mod", "v1.0.0")

    def test_a_repositorys_own_manifest_is_not_a_release(self):
        assert Engine._archive_release_identity(Units.at("demo-0.3.10/Cargo.toml", b"")) is None


class TestBrowserSecrets:
    @staticmethod
    def rules(text: str) -> set[str]:
        from cordon_scanner.detect.base import ScanContext
        from cordon_scanner.detect.code.capability.detector import CapabilityDetector
        from cordon_scanner.foundation.config import Config
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        unit = FileUnit(content=FileContent.from_bytes("lib/x.rb", text.encode()), language="ruby")
        ctx = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))
        return {f.rule_id for f in CapabilityDetector().inspect(unit, ctx)}

    STORE = (
        "db = SQLite3::Database.new(ENV['HOME'] + '\\\\AppData\\\\Local\\\\Google\\\\Chrome"
        "\\\\User Data\\\\Default\\\\Login Data')\n"
        "rows = db.execute('SELECT origin_url, password_value FROM logins')\n"
        "plain = Win32::Crypt32.CryptUnprotectData(rows[0][1])\n"
    )

    def test_reading_the_store_alone_is_a_cookie_importer(self):
        assert "SUSPECT.EXFIL.BROWSER_SECRETS.001" not in self.rules(self.STORE)

    def test_killing_the_browser_first_is_a_stealer(self):
        found = self.rules('system("TASKKILL /IM chrome.exe /F")\n' + self.STORE)
        assert "SUSPECT.EXFIL.BROWSER_SECRETS.001" in found
