"""cargo, go, RubyGems and Bundler through Cordon, and the shell shims (`sources/install/cargo.py`,
`gomod.py`, `hashes.py`, `gem.py`, `shims.py`)."""

from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.sources.install.cargo import CargoPlanner, CrateArchive
from cordon_scanner.sources.install.gem import GemPlanner, GemSpec
from cordon_scanner.sources.install.gomod import GoPlanner
from cordon_scanner.sources.install.hashes import GoModuleHash
from cordon_scanner.sources.install.plan import (
    SHIM_MARKER,
    InstallRefused,
    PackageFile,
    Subprocesses,
)
from cordon_scanner.sources.install.registries import InstallRegistries
from cordon_scanner.sources.install.shims import Shims

PUBLIC = InstallRegistries()
CHECKSUM = "ab" * 32


class NativeKit:
    @staticmethod
    def done(code: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, stdout, stderr)

    CARGO_LOCK = f"""version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["itoa"]

[[package]]
name = "itoa"
version = "1.0.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{CHECKSUM}"
"""


class TestCargo:
    def test_registry_crates_with_their_checksum_and_members_left_local(self) -> None:
        files = CargoPlanner.files(NativeKit.CARGO_LOCK)
        assert [(f.name, f.version) for f in files] == [("itoa", "1.0.11")]
        assert files[0].url == "https://static.crates.io/crates/itoa/itoa-1.0.11.crate"
        assert files[0].digest == bytes.fromhex(CHECKSUM)

    def test_a_git_crate_is_refused(self) -> None:
        text = '[[package]]\nname = "x"\nversion = "1.0.0"\nsource = "git+https://x/r#abc"\n'
        with pytest.raises(InstallRefused, match=r"crates\.io only"):
            CargoPlanner.files(text)

    def test_a_blocked_or_failed_resolve_puts_the_manifests_back(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").write_text("[package]\nname='app'\n", encoding="utf-8")

        def cargo(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            (cwd / "Cargo.toml").write_text("changed by cargo add\n", encoding="utf-8")
            (cwd / "Cargo.lock").write_text("broken = [\n", encoding="utf-8")
            return NativeKit.done()

        with pytest.raises(InstallRefused, match="could not be read"):
            CargoPlanner.project("add", ["itoa"], cargo, "cargo", tmp_path)
        assert (tmp_path / "Cargo.toml").read_text(encoding="utf-8") == "[package]\nname='app'\n"
        assert not (tmp_path / "Cargo.lock").exists()

    def test_the_build_runs_locked_before_any_program_arguments(self) -> None:
        assert CargoPlanner.locked("run", ["--release", "--", "--port", "1"]) == [
            "run", "--release", "--locked", "--", "--port", "1",
        ]  # fmt: skip
        assert CargoPlanner.locked("build", ["--frozen"]) == ["build", "--frozen"]

    def test_a_crate_unpacks_only_regular_files_inside_it(self, tmp_path: Path) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, data in (
                ("itoa-1.0.11/Cargo.toml", b"[package]\n"),
                ("itoa-1.0.11/src/lib.rs", b""),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("itoa-1.0.11/escape")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(link)
        crate = tmp_path / "itoa.crate"
        crate.write_bytes(buffer.getvalue())
        (tmp_path / "out").mkdir()
        root = CrateArchive.extract(crate, tmp_path / "out")
        assert (root / "src" / "lib.rs").is_file() and not (root / "escape").exists()


class TestGo:
    @staticmethod
    def module_zip(body: str = "package m\n") -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("example.com/m@v1.0.0/go.mod", "module example.com/m\n")
            zf.writestr("example.com/m@v1.0.0/m.go", body)
        return buffer.getvalue()

    def test_h1_is_the_dirhash_of_the_zip_contents(self) -> None:
        data = self.module_zip()
        lines = "".join(
            f"{hashlib.sha256(body).hexdigest()}  {name}\n"
            for name, body in sorted(
                [
                    ("example.com/m@v1.0.0/go.mod", b"module example.com/m\n"),
                    ("example.com/m@v1.0.0/m.go", b"package m\n"),
                ]
            )
        )
        assert GoModuleHash.of_zip(data) == hashlib.sha256(lines.encode()).digest()

    def test_go_sum_zip_lines_become_files_and_a_zip_is_verified(self) -> None:
        data = self.module_zip()
        h1 = "h1:" + base64.b64encode(GoModuleHash.of_zip(data)).decode()
        go_sum = (
            f"example.com/m v1.0.0 {h1}\n"
            "example.com/m v1.0.0/go.mod h1:" + base64.b64encode(b"\0" * 32).decode() + "\n"
            f"github.com/BurntSushi/toml v1.4.0 {h1}\n"
        )
        files = GoPlanner.files(go_sum)
        assert [f.name for f in files] == ["example.com/m", "github.com/BurntSushi/toml"]
        assert files[1].url == "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.zip"
        files[0].verify(data)
        with pytest.raises(InstallRefused, match="does not match"):
            files[0].verify(self.module_zip("package m // changed\n"))

    def test_only_the_build_list_is_fetched_and_a_failure_restores_go_mod(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "go.mod").write_text("module app\n", encoding="utf-8")
        h1 = "h1:" + base64.b64encode(b"\1" * 32).decode()

        def go(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            assert env["GOTOOLCHAIN"] == "local", "no toolchain is fetched and run"
            argv = list(argv)
            if argv[1] == "get":
                (cwd / "go.mod").write_text("module app\nrequire x v1\n", encoding="utf-8")
                (cwd / "go.sum").write_text(f"x v1 {h1}\nstale v0 {h1}\n", encoding="utf-8")
            if argv[1] == "list":
                return NativeKit.done(stdout="app \nx v1\n")
            return NativeKit.done()

        plan = GoPlanner.module("get", ["x@v1"], go, "go", tmp_path)
        assert [f.name for f in plan.files] == ["x"], "a stale go.sum line is not fetched"
        GoPlanner.restore(
            tmp_path, {k.removeprefix("saved:"): v for k, v in plan.manifests.items()}
        )
        assert (tmp_path / "go.mod").read_text(encoding="utf-8") == "module app\n"
        assert not (tmp_path / "go.sum").exists()


class TestRubyGems:
    LOCK = f"""GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0-arm64-darwin)
      racc (~> 1.4)
    racc (1.8.1)

PLATFORMS
  arm64-darwin

CHECKSUMS
  nokogiri (1.16.0-arm64-darwin) sha256={CHECKSUM}
  racc (1.8.1) sha256={"cd" * 32}

BUNDLED WITH
   2.5.0
"""

    def test_a_lockfile_with_checksums_needs_no_registry_lookup(self) -> None:
        files = GemPlanner.locked(self.LOCK, PUBLIC)
        assert [(f.name, f.version) for f in files] == [
            ("nokogiri", "1.16.0-arm64-darwin"),
            ("racc", "1.8.1"),
        ]
        assert files[0].url == "https://rubygems.org/gems/nokogiri-1.16.0-arm64-darwin.gem"
        assert files[1].digest == bytes.fromhex("cd" * 32)

    def test_without_checksums_the_registry_record_gives_the_sha256(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []

        def fetch(self: InstallRegistries, url: str, ecosystem: str) -> bytes:
            asked.append(url)
            return b'{"sha": "' + CHECKSUM.encode() + b'"}'

        monkeypatch.setattr(InstallRegistries, "fetch", fetch)
        text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    racc (1.8.1)\n"
        assert GemPlanner.locked(text, PUBLIC)[0].digest == bytes.fromhex(CHECKSUM)
        assert asked == [
            "https://rubygems.org/api/v2/rubygems/racc/versions/1.8.1.json?platform=ruby"
        ]

    def test_another_source_or_a_git_gem_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match=r"not rubygems\.org"):
            GemPlanner.locked(
                "GEM\n  remote: https://gems.evil.example/\n  specs:\n    x (1.0)\n", PUBLIC
            )
        with pytest.raises(InstallRefused, match="git gem"):
            GemPlanner.locked("GIT\n  remote: https://github.com/x/y.git\n", PUBLIC)

    def test_gem_full_names_split_into_name_version_platform(self) -> None:
        assert GemSpec.split("net-http-0.4.1") == ("net-http", "0.4.1", "")
        assert GemSpec.split("nokogiri-1.13.10-arm64-darwin") == (
            "nokogiri",
            "1.13.10",
            "arm64-darwin",
        )

    def test_gem_install_plans_what_explain_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            GemPlanner, "_published", classmethod(lambda cls, n, v, p, r: bytes.fromhex(CHECKSUM))
        )
        explain = "Gems to install:\n  racc-1.8.1\n  nokogiri-1.13.10-arm64-darwin\n"
        seen: list[list[str]] = []

        def gem(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            seen.append(list(argv))
            return NativeKit.done(stdout=explain)

        plan = GemPlanner.gem_install(["nokogiri"], gem, "gem", PUBLIC, Path.cwd())
        assert "--explain" in seen[0]
        assert [f.label for f in plan.files] == ["racc 1.8.1", "nokogiri 1.13.10-arm64-darwin"]


class TestShims:
    def test_shims_call_cordon_and_are_skipped_when_finding_the_real_tool(
        self, tmp_path: Path
    ) -> None:
        report = Shims.install(tmp_path / "shims", ("/opt/cordon-scanner",))
        assert set(report.written) == set(Shims.TOOLS)
        npm = (tmp_path / "shims" / "npm").read_text(encoding="utf-8")
        assert SHIM_MARKER in npm and 'exec /opt/cordon-scanner npm "$@"' in npm
        bundle = (tmp_path / "shims" / "bundle").read_text(encoding="utf-8")
        assert "cordon-scanner bundler" in bundle, "`bundle` is Cordon's own command"
        assert Subprocesses.is_shim(tmp_path / "shims" / "npm")

    def test_a_file_that_is_not_a_shim_is_never_overwritten_or_removed(
        self, tmp_path: Path
    ) -> None:
        directory = tmp_path / "shims"
        directory.mkdir()
        (directory / "go").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        report = Shims.install(directory, ("cordon-scanner",))
        assert report.kept == ("go",)
        removed = Shims.remove(directory)
        assert "go" not in removed.removed and (directory / "go").read_text(
            encoding="utf-8"
        ).endswith("mine\n")
        assert not (directory / "npm").exists()


class TestTheVerifiedFile:
    def test_a_sha256_file_verifies_against_its_published_hash(self) -> None:
        data = b"gem bytes"
        file = PackageFile(
            "rubygems",
            "x",
            "1",
            "https://rubygems.org/gems/x-1.gem",
            "sha256",
            hashlib.sha256(data).digest(),
        )
        file.verify(data)
        with pytest.raises(InstallRefused):
            file.verify(data + b"!")
