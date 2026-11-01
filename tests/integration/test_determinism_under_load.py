"""The same input scanned repeatedly while the machine is busy gives the same answer: the same
findings, the same complete flag, the same exit code under --fail-on-incomplete, and the same
verdict. A per-file cut on the wall clock once made a 1 MB main.tf come out with and without its
OPERATIONAL.FILE.TIMEOUT note from run to run (2026-10-31); every detector now runs on every file,
so nothing in a scan's answer may depend on how loaded the machine is."""

from __future__ import annotations

import json
import multiprocessing
import time
from pathlib import Path

from cordon_scanner import Config, Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.policy import Policy


class Load:
    """Processes that keep the CPU busy while a scan runs, so a clock-bound step would show."""

    @staticmethod
    def spin(until: float) -> None:
        x = 0
        while time.monotonic() < until:
            x = (x * 31 + 7) % 1_000_003

    @staticmethod
    def start(seconds: float, count: int = 2) -> list[multiprocessing.Process]:
        until = time.monotonic() + seconds
        procs = [multiprocessing.Process(target=Load.spin, args=(until,)) for _ in range(count)]
        for p in procs:
            p.start()
        return procs


class Answer:
    @staticmethod
    def of(root: Path) -> tuple[list[str], bool, int, object]:
        cfg = Config.default().with_overrides(use_cache=False)
        result = Scanner(cfg).scan(root)
        rows = []
        for f in result.findings:
            d = f.to_dict()
            evidence = d.get("evidence")
            if isinstance(evidence, dict):
                evidence.pop("match_hash", None)  # an HMAC under a key drawn per run
            if d.get("rule_id") == "OPERATIONAL.INTEL.STALE":
                d.pop("message", None)  # names the intel's age in hours, which the clock moves
            rows.append(json.dumps(d, sort_keys=True))
        gate = PolicyGate.evaluate(result, Policy(fail_on_incomplete=True))
        verdict = result.verdict or {}
        return sorted(rows), result.complete, int(gate.exit_code), verdict.get("score")


class TestTheSameAnswerUnderLoad:
    @staticmethod
    def tree(root: Path) -> Path:
        blocks = [
            'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'
        ]
        for i in range(1500):  # about 300 KB: big enough to take seconds, as the 1 MB one did
            blocks.append(
                f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "example-{i}"\n}}\n'
                f'module "m{i}" {{\n  source  = "terraform-aws-modules/vpc/aws"\n'
                f'  version = "5.{i % 10}.0"\n}}\n'
            )
        (root / "main.tf").write_text("".join(blocks), encoding="utf-8")
        (root / "install.js").write_text(
            "const p = atob(process.argv[2]);\neval(p);\n", encoding="utf-8"
        )
        return root

    def test_three_scans_under_load_agree_on_everything(self, tmp_path: Path) -> None:
        root = self.tree(tmp_path)
        quiet = Answer.of(root)
        loaded = []
        for _ in range(2):
            procs = Load.start(seconds=60)
            try:
                loaded.append(Answer.of(root))
            finally:
                for p in procs:
                    p.terminate()
                    p.join()
        # nothing cut a file (completeness itself can also hang on the advisory feed, which an
        # offline run cannot refresh: the same every run, so it is compared, not required)
        assert "OPERATIONAL.FILE.TIMEOUT" not in "".join(quiet[0])
        assert "SUSPECT.DECODE_EXEC.001" in "".join(quiet[0])  # the scan found what it should
        for answer in loaded:
            assert answer == quiet
