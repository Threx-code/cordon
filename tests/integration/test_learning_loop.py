"""The learning loop end to end on the scanner's own code paths (learning loop LL-57): packages are scanned to facts
(`--format facts`), the distiller learns a rule from the facts of several families, the rule ships as an ordinary
pack, and a scanner that loads the pack catches a package of a family it never learned from while passing
legitimate packages. Nothing here is a sample: every package is built in a temporary folder from ordinary code (a
helper that runs `git status` and checks a status page), and the only difference between the "families" is that
their helper ships where nothing the package runs reaches it.

The thresholds are loosened (a few dozen packages cannot carry the 0.5% bound): this proves the mechanism, not a
detection rate."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from dataclasses import replace
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.facts import ScanFacts
from support import ROOT

sys.path.insert(0, str(ROOT))

from bench.cdi.distill import Distiller, PackRenderer, Unit

HELPER = """const { spawn } = require('child_process');
const https = require('https');

function refresh() {
  const child = spawn('git', ['status']);
  https.get('https://example.com/status', () => {});
  return child;
}

module.exports = { refresh };
"""
ALONE = "module.exports = (a, b) => a + b;\n"
LOADS = "const helper = require('./lib/helper');\nmodule.exports = helper;\n"


class LoopKit:
    @staticmethod
    def tarball(folder: Path, name: str, index: str) -> Path:
        files = {
            "package/package.json": json.dumps(
                {"name": name, "version": "1.0.0", "main": "index.js"}
            ),
            "package/index.js": index,
            "package/lib/helper.js": HELPER,
        }
        path = folder / f"{name}-1.0.0.tgz"
        with tarfile.open(path, "w:gz") as tar:
            for member, text in files.items():
                data = text.encode("utf-8")
                info = tarfile.TarInfo(member)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    @staticmethod
    def facts(scanner: Scanner, path: Path) -> dict:
        return ScanFacts.of(scanner.scan(path))


class TestTheLoopLearnsShipsAndCatches:
    def test_a_rule_learned_from_three_families_catches_a_fourth_and_spares_legitimate_packages(
        self, tmp_path
    ) -> None:
        scanner = Scanner(Config.default())
        units = []
        for family in range(4):
            for j in range(2):
                path = LoopKit.tarball(tmp_path, f"fam{family}-tool-{j}", ALONE)
                split = "train" if family < 3 else "confirm"
                units.append(
                    Unit(
                        f"m{family}{j}",
                        "mal",
                        f"f{family}",
                        "npm",
                        "s0",
                        split,
                        LoopKit.facts(scanner, path),
                    )
                )
        for j in range(16):
            path = LoopKit.tarball(tmp_path, f"ordinary-{j}", LOADS)
            split = "train" if j < 10 else "confirm"
            units.append(
                Unit(f"l{j}", "legit", "", "npm", "s0", split, LoopKit.facts(scanner, path))
            )

        run = Distiller(min_families=3, budget=0.5, alpha=0.5).distill(units)
        assert run.candidate is not None, run.refused
        # The same fact two ways: in no place set, or (facts v2) reached by nothing at all.
        assert any(
            t[0] == "file"
            and t[1] in ("unreached", "reach:unreached")
            and t[2:] == ["egress", "spawn"]
            for t in run.candidate["predicate"]
        )

        pack = tmp_path / "learned.yaml"
        pack.write_text(PackRenderer.render(run.candidate, "LEARNED.NPM.001"), encoding="utf-8")
        learned = Scanner(replace(Config.default(), extra_rule_paths=(str(pack),)))

        unseen = learned.scan(LoopKit.tarball(tmp_path, "never-seen-family", ALONE))
        assert [f.rule_id for f in unseen.findings if f.rule_id.startswith("LEARNED.")] == [
            "LEARNED.NPM.001"
        ]
        ordinary = learned.scan(LoopKit.tarball(tmp_path, "another-ordinary", LOADS))
        assert not [f for f in ordinary.findings if f.rule_id.startswith("LEARNED.")]
