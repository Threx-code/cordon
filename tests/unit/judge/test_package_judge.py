"""The package judge (reviews/big-picture/15): a release read into one bounded bundle, triaged, and confirmed
only when triage flags it; a reply that does not parse is an error, never a verdict. The providers here are
scripted: nothing is dialled."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner.detect.agents.language_model.review import JudgeError
from cordon_scanner.judge.package_judge import (
    PackageJudge,
    PackagePrompts,
    ReleaseBundle,
    ScanHint,
)
from cordon_scanner.judge.providers import BaseProvider


class Scripted(BaseProvider):
    NAME = "scripted"

    def __init__(self, *replies: str) -> None:
        super().__init__("m", "http://127.0.0.1:1", environ={})
        self.replies = list(replies)
        self.seen: list[tuple[str, str]] = []

    def _exchange(self, system: str, user: str) -> str:
        self.seen.append((system, user))
        return self.replies.pop(0)


class JudgeKit:
    @staticmethod
    def sdist(tmp_path: Path, files: dict[str, str]) -> Path:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"demo-1.0/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        path = tmp_path / "demo-1.0.tar.gz"
        path.write_bytes(buf.getvalue())
        return path

    FILES: ClassVar[dict[str, str]] = {
        "PKG-INFO": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\nSummary: a demo\n\nLong text.\n",
        "demo/util.py": "def helper():\n    return 1\n",
        "demo/__init__.py": "from .util import helper\n",
        "setup.py": "from setuptools import setup\nsetup(name='demo')\n",
        "demo/blob.py": "DATA = '" + "A" * 400 + "'\n",
    }


class TestTheBundle:
    def test_setup_first_then_package_roots(self, tmp_path) -> None:
        text = ReleaseBundle.build(JudgeKit.sdist(tmp_path, JudgeKit.FILES))
        assert (
            text.index("## FILE setup.py")
            < text.index("## FILE demo/__init__.py")
            < text.index("## FILE demo/util.py")
        )

    def test_long_literals_are_shown_by_length(self, tmp_path) -> None:
        text = ReleaseBundle.build(JudgeKit.sdist(tmp_path, JudgeKit.FILES))
        assert "<BLOB len=400>" in text
        assert "A" * 200 not in text

    def test_metadata_and_scan_hints_are_shown(self, tmp_path) -> None:
        hints = [ScanHint("MALWARE.EXFIL.001", "demo-1.0.tar.gz!demo-1.0/demo/util.py", 2)]
        text = ReleaseBundle.build(JudgeKit.sdist(tmp_path, JudgeKit.FILES), hints)
        assert "Summary: a demo" in text
        assert "Static scan findings here: MALWARE.EXFIL.001 line 2" in text
        assert text.index("## FILE demo/util.py") < text.index("## FILE demo/blob.py")

    def test_the_budget_bounds_the_bundle(self, tmp_path) -> None:
        files = {**JudgeKit.FILES, **{f"demo/m{i}.py": "x = 1\n" * 2000 for i in range(20)}}
        assert len(ReleaseBundle.build(JudgeKit.sdist(tmp_path, files), budget=10_000)) <= 16_000


class TestTheCascade:
    MAL = '{"verdict": "malicious", "confidence": 95, "evidence": "sends the environment out"}'
    BEN = '{"verdict": "benign", "confidence": 90, "evidence": "an API client"}'

    def test_triage_clears_without_asking_the_confirmer(self) -> None:
        triage, confirm = Scripted(self.BEN), Scripted()
        verdict = PackageJudge(triage, confirm).judge("bundle")
        assert (verdict.verdict, verdict.stage, confirm.seen) == ("benign", 1, [])

    def test_malicious_needs_the_confirmer_to_agree(self) -> None:
        verdict = PackageJudge(Scripted(self.MAL), Scripted(self.BEN)).judge("bundle")
        assert (verdict.verdict, verdict.stage) == ("benign", 2)
        verdict = PackageJudge(Scripted(self.MAL), Scripted(self.MAL)).judge("bundle")
        assert (verdict.malicious, verdict.confidence, verdict.stage) == (True, 95, 2)

    def test_each_stage_has_its_prompt_reasoning_and_budget(self) -> None:
        triage, confirm = Scripted(self.MAL), Scripted(self.MAL)
        PackageJudge(triage, confirm).judge("bundle", similar="MALWARE: sends env")
        assert triage.seen[0][0] == PackagePrompts.TRIAGE and triage.think is False
        assert confirm.seen[0][0] == PackagePrompts.CONFIRM and confirm.think is True
        assert confirm.max_tokens > triage.max_tokens
        assert "<similar>" in confirm.seen[0][1] and "<similar>" not in triage.seen[0][1]

    def test_both_prompts_treat_the_release_as_untrusted(self) -> None:
        assert (
            "UNTRUSTED DATA" in PackagePrompts.TRIAGE and "UNTRUSTED DATA" in PackagePrompts.CONFIRM
        )


class TestAgentExtensions:
    def test_an_agent_judge_also_reads_instructions_aimed_at_the_agent(self) -> None:
        triage, confirm = Scripted(TestTheCascade.MAL), Scripted(TestTheCascade.MAL)
        PackageJudge(triage, confirm, kind="agent").judge("bundle")
        assert "tool poisoning" in triage.seen[0][0] and "tool poisoning" in confirm.seen[0][0]
        assert triage.seen[0][0].endswith(PackagePrompts.ANSWER)

    def test_a_package_judge_does_not(self) -> None:
        assert "tool poisoning" not in PackagePrompts.triage("package")

    def test_an_unknown_kind_is_refused(self) -> None:
        with pytest.raises(ValueError):
            PackageJudge(Scripted(), kind="other")


class TestTheReply:
    def test_reasoning_before_the_answer_is_ignored(self) -> None:
        verdict = PackageJudge.parse(
            '<think>hmm</think>{"verdict": "benign", "confidence": 70, "evidence": "x"}',
            stage=1,
            model="m",
        )
        assert (verdict.verdict, verdict.confidence) == ("benign", 70)

    @pytest.mark.parametrize("text", ["", "no json here", '{"verdict": "maybe"}', "{broken"])
    def test_an_unreadable_reply_is_an_error(self, text) -> None:
        with pytest.raises(JudgeError):
            PackageJudge.parse(text, stage=1, model="m")
