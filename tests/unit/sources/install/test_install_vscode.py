"""Editor extensions through Cordon (`sources/install/managers/vscode.py`, `cli/commands/install/vscode.py`).

The packages, signature and release documents are real Open VSX files (`vscode_captures/CAPTURES.md`). The signature check is the
product's own `OpenVsxSignature` with its pinned key.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.install.vscode import VscodeTools
from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
from cordon_scanner.intel.provenance.releases.openvsx_signature import OpenVsxSignature
from cordon_scanner.intel.registries.openvsx import OpenVsx
from cordon_scanner.intel.registries.registry_request import RegistryError
from cordon_scanner.sources.install.managers.vscode import VscodePlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "vscode_captures"
THEME = "Catppuccin.catppuccin-vsc-3.19.0"
PACK = "VMware.vscode-boot-dev-pack-0.2.2"


class Files:
    theme = (CAPTURES / f"{THEME}.vsix").read_bytes()
    sigzip = (CAPTURES / f"{THEME}.sigzip").read_bytes()
    pack = (CAPTURES / f"{PACK}.vsix").read_bytes()

    @staticmethod
    def document(stem: str) -> dict[str, Any]:
        return json.loads((CAPTURES / f"{stem}.json").read_text(encoding="utf-8"))

    @staticmethod
    def extension(needs: list[str] | None = None, pack: list[str] | None = None) -> bytes:
        """A minimal package: only its manifest, which is all the planner reads."""
        manifest = {"name": "x", "extensionDependencies": needs or [], "extensionPack": pack or []}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("extension/package.json", json.dumps(manifest))
        return buffer.getvalue()


class Registry:
    """The signed packages Open VSX would answer with, by extension name (lower case)."""

    def __init__(self, packages: dict[str, bytes], latest: str = "1.0.0") -> None:
        self.packages = packages
        self.latest_version = latest
        self.asked: list[str] = []

    def signed(self, name: str, version: str) -> Any:
        self.asked.append(name)
        package = self.packages.get(name.lower())
        if package is None:
            return ModuleCheck("absent", f"Open VSX publishes no signature for {name} {version}")
        return package, {}

    def latest(self, name: str) -> str:
        return self.latest_version


class Plans:
    @staticmethod
    def make(args: list[str], registry: Registry, into: Path) -> Any:
        return VscodePlanner.plan(args, into / "extensions", registry.signed, registry.latest)


class TestTheCommandLine:
    def test_the_install_words_are_taken_out_in_either_spelling(self) -> None:
        args = [
            "--user-data-dir",
            "/x",
            "--install-extension",
            "a.b",
            "--install-extension=c.d",
            "--force",
        ]
        assert VscodePlanner.installs(args)
        assert VscodePlanner.split(args) == (["--user-data-dir", "/x", "--force"], ["a.b", "c.d"])

    def test_other_editor_commands_are_not_installs(self) -> None:
        assert not VscodePlanner.installs(["--list-extensions"])
        assert not VscodePlanner.installs(["."])
        assert not VscodePlanner.installs(["--uninstall-extension", "a.b"])

    def test_an_install_word_with_no_extension_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="names no extension"):
            VscodePlanner.split(["--install-extension"])


class TestThePlan:
    def test_a_signed_package_is_written_for_the_scan_and_named_for_the_install(
        self, tmp_path: Path
    ) -> None:
        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme}, latest="3.19.0")
        result = Plans.make(
            ["--install-extension", "Catppuccin.catppuccin-vsc"], registry, tmp_path
        )
        (path,) = result.packages
        assert path.name == f"{THEME}.vsix"
        assert path.read_bytes() == Files.theme
        assert result.plan.ecosystem == "vscode" and result.plan.local == [tmp_path / "extensions"]
        assert result.rest == ()

    def test_a_version_asked_for_is_the_version_fetched(self, tmp_path: Path) -> None:
        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme})
        result = Plans.make(
            ["--install-extension", "Catppuccin.catppuccin-vsc@3.19.0"], registry, tmp_path
        )
        assert result.packages[0].name == f"{THEME}.vsix"

    def test_the_other_options_are_kept(self, tmp_path: Path) -> None:
        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme})
        result = Plans.make(
            ["--force", "--install-extension", "Catppuccin.catppuccin-vsc", "--profile", "work"],
            registry,
            tmp_path,
        )
        assert result.rest == ("--force", "--profile", "work")

    def test_a_package_open_vsx_did_not_sign_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="could not be verified against Open VSX"):
            Plans.make(["--install-extension", "acme.unsigned"], Registry({}), tmp_path)

    def test_a_pack_installs_what_it_names_before_itself(self, tmp_path: Path) -> None:
        members = {
            "vmware.vscode-spring-boot": Files.extension(),
            "vscjava.vscode-spring-initializr": Files.extension(),
            "vscjava.vscode-spring-boot-dashboard": Files.extension(),
            "vmware.vscode-boot-dev-pack": Files.pack,
        }
        result = Plans.make(
            ["--install-extension", "VMware.vscode-boot-dev-pack@0.2.2"],
            Registry(members),
            tmp_path,
        )
        names = [p.name for p in result.packages]
        assert names == [
            "vmware.vscode-spring-boot-1.0.0.vsix",
            "vscjava.vscode-spring-initializr-1.0.0.vsix",
            "vscjava.vscode-spring-boot-dashboard-1.0.0.vsix",
            f"{PACK}.vsix",
        ]

    def test_an_extension_needed_twice_is_fetched_once(self, tmp_path: Path) -> None:
        registry = Registry(
            {
                "a.one": Files.extension(needs=["c.shared"]),
                "b.two": Files.extension(needs=["c.shared"]),
                "c.shared": Files.extension(),
            }
        )
        result = Plans.make(
            ["--install-extension", "a.one", "--install-extension", "b.two"], registry, tmp_path
        )
        assert registry.asked.count("c.shared") == 1
        assert len(result.packages) == 3

    def test_a_chain_of_needs_that_never_ends_is_refused(self, tmp_path: Path) -> None:
        chain = {f"a.n{i}": Files.extension(needs=[f"a.n{i + 1}"]) for i in range(40)}
        with pytest.raises(InstallRefused, match=r"more than 25 extensions|deep"):
            Plans.make(["--install-extension", "a.n0"], Registry(chain), tmp_path)

    def test_a_cycle_ends(self, tmp_path: Path) -> None:
        registry = Registry(
            {"a.one": Files.extension(needs=["a.two"]), "a.two": Files.extension(needs=["a.one"])}
        )
        result = Plans.make(["--install-extension", "a.one"], registry, tmp_path)
        assert len(result.packages) == 2

    @pytest.mark.parametrize("spec", ["nonsense", "../etc.passwd", "a.b/../c", "a b.c"])
    def test_a_name_that_is_not_an_extension_is_refused(self, spec: str, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"not a publisher\.extension name"):
            Plans.make(["--install-extension", spec], Registry({}), tmp_path)

    def test_a_package_whose_manifest_cannot_be_read_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="manifest cannot be read"):
            Plans.make(["--install-extension", "a.b"], Registry({"a.b": b"not a zip"}), tmp_path)

    def test_the_packages_are_private(self, tmp_path: Path) -> None:
        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme})
        result = Plans.make(
            ["--install-extension", "Catppuccin.catppuccin-vsc"], registry, tmp_path
        )
        assert result.packages[0].stat().st_mode & 0o077 == 0


class TestAVsixByPath:
    def test_a_file_is_copied_for_the_scan_and_installed_from_the_copy(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "mine.vsix"
        source.write_bytes(Files.theme)
        result = Plans.make(["--install-extension", str(source)], Registry({}), tmp_path)
        (copy,) = result.packages
        assert copy != source and copy.read_bytes() == Files.theme

    def test_what_it_needs_is_resolved_from_open_vsx(self, tmp_path: Path) -> None:
        source = tmp_path / "mine.vsix"
        source.write_bytes(Files.extension(needs=["c.shared"]))
        registry = Registry({"c.shared": Files.extension()})
        result = Plans.make(["--install-extension", str(source)], registry, tmp_path)
        assert next(p.name for p in result.packages).startswith("c.shared")
        assert len(result.packages) == 2

    def test_a_missing_file_and_a_link_are_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="not a file"):
            Plans.make(["--install-extension", str(tmp_path / "none.vsix")], Registry({}), tmp_path)
        real = tmp_path / "real.vsix"
        real.write_bytes(Files.theme)
        link = tmp_path / "link.vsix"
        link.symlink_to(real)
        with pytest.raises(InstallRefused, match="not a file"):
            Plans.make(["--install-extension", str(link)], Registry({}), tmp_path)


class TestOpenVsx:
    def test_an_extension_open_vsx_does_not_hold_is_refused_with_the_terms_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing(url: str) -> Any:
            raise RegistryError("HTTP 404")

        monkeypatch.setattr(OpenVsx, "_json", staticmethod(missing))
        with pytest.raises(InstallRefused, match=r"Visual Studio Marketplace.*only Microsoft"):
            VscodePlanner.latest("acme.tool")

    def test_a_build_per_platform_is_refused_not_guessed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        document = {**Files.document(THEME), "targetPlatform": "alpine-arm64"}
        monkeypatch.setattr(OpenVsx, "_json", staticmethod(lambda url: document))
        with pytest.raises(InstallRefused, match="built per platform"):
            VscodePlanner.signed("Catppuccin.catppuccin-vsc", "3.19.0")

    def test_the_marketplace_is_never_named_as_a_host(self) -> None:
        text = (
            ROOT / "src" / "cordon_scanner" / "sources" / "install" / "managers" / "vscode.py"
        ).read_text(encoding="utf-8")
        assert "marketplace.visualstudio.com" not in text and "gallery.vsassets" not in text


class TestTheSignature:
    """The check `signed_package` makes, on the real files: the pinned key verifies a real package."""

    key = OpenVsxSignature.key_id(Files.document(THEME)["files"]["publicKey"])

    def test_the_real_package_verifies_against_the_pinned_key(self) -> None:
        assert OpenVsxSignature.verify(Files.theme, Files.sigzip, self.key).outcome == "verified"

    def test_a_changed_package_does_not(self) -> None:
        tampered = Files.theme[:-1] + bytes([Files.theme[-1] ^ 1])
        assert OpenVsxSignature.verify(tampered, Files.sigzip, self.key).outcome == "invalid"

    def test_a_key_that_is_not_pinned_is_not_trusted(self) -> None:
        other = "00000000-0000-0000-0000-000000000000"
        assert OpenVsxSignature.verify(Files.theme, Files.sigzip, other).outcome == "unverifiable"


class FakeContext:
    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.ran: list[list[str]] = []
        self.checked: list[list[str]] = []

    def check(self, plan: Any, scratch: Path) -> Any:
        self.checked.append(sorted(p.name for p in plan.local[0].iterdir()))
        return SimpleNamespace(ok=self.ok)

    def blocked(self, verdict: object) -> int:
        return 2

    def run(
        self, argv: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
    ) -> int:
        self.ran.append(list(argv))
        return 0


class TestTheCommand:
    @pytest.fixture(autouse=True)
    def _registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme}, latest="3.19.0")
        monkeypatch.setattr(VscodePlanner, "signed", staticmethod(registry.signed))
        monkeypatch.setattr(VscodePlanner, "latest", staticmethod(registry.latest))

    def test_the_editor_installs_the_scanned_file_not_the_name(self) -> None:
        context = FakeContext()
        args = ["--install-extension", "Catppuccin.catppuccin-vsc", "--force"]
        assert VscodeTools.code("/usr/local/bin/code", args, context) == 0  # type: ignore[arg-type]
        assert context.checked == [[f"{THEME}.vsix"]]
        ((argv),) = context.ran
        assert argv[:2] == ["/usr/local/bin/code", "--force"]
        assert argv[2] == "--install-extension" and argv[3].endswith(f"{THEME}.vsix")
        assert "Catppuccin.catppuccin-vsc" not in argv

    def test_a_block_runs_nothing(self) -> None:
        context = FakeContext(ok=False)
        args = ["--install-extension", "Catppuccin.catppuccin-vsc"]
        assert VscodeTools.code("/usr/local/bin/code", args, context) == 2  # type: ignore[arg-type]
        assert context.ran == []

    def test_a_refusal_runs_nothing(self) -> None:
        context = FakeContext()
        with pytest.raises(InstallRefused):
            VscodeTools.code(
                "/usr/local/bin/code", ["--install-extension", "acme.unknown"], context
            )  # type: ignore[arg-type]
        assert context.ran == []


class TestTheScan:
    def test_the_scanner_reads_a_real_extension_and_it_passes(self, tmp_path: Path) -> None:
        from cordon_scanner.cli.commands.install.context import InstallContext
        from cordon_scanner.foundation.config.settings import Config

        registry = Registry({"catppuccin.catppuccin-vsc": Files.theme})
        result = Plans.make(
            ["--install-extension", "Catppuccin.catppuccin-vsc"], registry, tmp_path
        )
        assert InstallContext.scanner(Config.default())(result.plan.local[0]) == ()
