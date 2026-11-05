"""Item 68's secret-blocking policy. Every secret rule says what it is for (its class, required), and
the drop points the package graders exempt are exactly the exfiltration-channel class. An exfiltration
channel's credential keeps its grade wherever it sits in code, a minified `dist/` bundle included,
because malware ships one there to send stolen data out; documentation still lowers it. A leaked
credential in a package is the publisher's to rotate and is reported below the gate
(`Publisher.publisher_secrets`, unchanged); in a repository it keeps its grade. Fabricated values are
joined at runtime (`Support.assemble`)."""

from __future__ import annotations

import dataclasses
import io
import json
import re
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.secrets.detector import SecretDetector
from cordon_scanner.detect.secrets.patterns import PROVIDER_PATTERNS, SecretClass, SecretPattern
from cordon_scanner.engine.pipeline.constants import DROP_POINT_SECRETS
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from support import Support

TOKEN = Support.assemble("ghp", "_", "Rk7Lw2Qz9TbXn4Vp1HcJ8sMfY3dGu6EaWo5N")
TELEGRAM = Support.assemble("7351942068", ":AA", "Hx3kQ9vLmT2pRw7ZsN4bYc8dFj6GuE1aKo")
EXFILTRATION = DROP_POINT_SECRETS


class PolicyKit:
    @staticmethod
    def package(tmp_path: Path, files: dict[str, str]) -> Path:
        manifest = {"name": "keys-lib", "version": "1.0.0", "main": "index.js"}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in {"package/package.json": json.dumps(manifest), **files}.items():
                data = text.encode()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "keys-lib-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def grades(target: Path, rule: str) -> list[tuple[Severity, str]]:
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return [(f.severity, f.message) for f in found if f.rule_id == rule]


class TestEveryRuleSaysWhatItIsFor:
    def test_the_class_is_required(self) -> None:
        spec = PROVIDER_PATTERNS[0]
        fields = {
            f.name: getattr(spec, f.name)
            for f in dataclasses.fields(spec)
            if f.name != "secret_class"
        }
        with pytest.raises(TypeError):
            SecretPattern(**fields)  # type: ignore[call-arg]

    def test_the_exfiltration_channels_are_exactly_the_drop_points(self) -> None:
        classes = {p.rule_id: p.secret_class for p in PROVIDER_PATTERNS}
        assert {
            r for r, c in classes.items() if c is SecretClass.EXFILTRATION_CHANNEL
        } == EXFILTRATION
        assert all(c is SecretClass.LEAK for r, c in classes.items() if r not in EXFILTRATION)

    def test_every_secret_rule_the_detector_names_has_a_pattern_class(self) -> None:
        source = Path(SecretDetector.__module__.replace(".", "/") + ".py")
        named = set(
            re.findall(
                r'"(SECRET\.[A-Z_.]+\.\d{3})"', (Path("src") / source).read_text(encoding="utf-8")
            )
        )
        assert named <= {p.rule_id for p in PROVIDER_PATTERNS} | {
            "SECRET.GENERIC.ASSIGNMENT.001",
            "SECRET.URL.CREDENTIAL.001",
        }


class TestInAPackage:
    def test_a_leaked_key_is_the_publishers_and_below_the_gate(self, tmp_path: Path) -> None:
        target = PolicyKit.package(
            tmp_path, {"package/index.js": f'const k = "{TOKEN}";\nmodule.exports = k;\n'}
        )
        grades = PolicyKit.grades(target, "SECRET.GITHUB.TOKEN.001")
        assert grades and all(severity <= Severity.MEDIUM for severity, _ in grades)

    def test_an_exfiltration_token_in_a_minified_bundle_keeps_its_grade(
        self, tmp_path: Path
    ) -> None:
        bundle = "var a=1;" * 2000 + f'var t="{TELEGRAM}";' + "var b=2;" * 2000 + "\n"
        target = PolicyKit.package(
            tmp_path,
            {"package/index.js": "module.exports = 1;\n", "package/dist/app.min.js": bundle},
        )
        grades = PolicyKit.grades(target, "SECRET.TELEGRAM.BOT_TOKEN.001")
        assert grades and all(severity >= Severity.HIGH for severity, _ in grades)

    def test_an_exfiltration_token_in_documentation_is_still_lowered(self, tmp_path: Path) -> None:
        target = PolicyKit.package(
            tmp_path,
            {
                "package/index.js": "module.exports = 1;\n",
                "package/README.md": f"Set the bot token `{TELEGRAM}`.\n",
            },
        )
        grades = PolicyKit.grades(target, "SECRET.TELEGRAM.BOT_TOKEN.001")
        assert all(severity <= Severity.MEDIUM for severity, _ in grades)


class TestInARepository:
    def test_a_leaked_key_keeps_its_grade(self, tmp_path: Path) -> None:
        root = tmp_path / "repo"
        (root / "tools").mkdir(parents=True)
        (root / "tools" / "notes.js").write_text(f'const k = "{TOKEN}";\n', encoding="utf-8")
        grades = PolicyKit.grades(root, "SECRET.GITHUB.TOKEN.001")
        assert grades and all(severity >= Severity.HIGH for severity, _ in grades)
