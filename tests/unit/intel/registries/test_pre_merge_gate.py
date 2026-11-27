"""The pre-merge gate (`review --base REF --format github`): on a pull request, the lockfiles, the workflow actions and
the container images are diffed against the base; each change that blocks is an `::error` annotation titled with its
reason code, and the check fails. A repinned action or image is a change. A 200-change pull request is reviewed well
inside a minute."""

from __future__ import annotations

import argparse
import json
import subprocess
import time

import pytest

from cordon_scanner.cli.commands.review import (
    ChangeReview,
    GithubAnnotations,
    GraphDiff,
    PackageChange,
    ReviewCommand,
)
from support import ROOT
from unit.intel.registries.test_dependency_review import ReviewHelpers


class Gate:
    @staticmethod
    def git(root, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    @staticmethod
    def workflow(ref: str) -> str:
        return f"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{ref}\n"

    @classmethod
    def repository(
        cls,
        root,
        before: dict[str, str],
        after: dict[str, str],
        *,
        refs=("v3", "v3"),
        images=("3.11", "3.11"),
    ):
        root.mkdir()
        cls.git(root, "init", "-q")
        cls.git(root, "config", "user.email", "gate@example.test")
        cls.git(root, "config", "user.name", "gate")
        (root / ".github/workflows").mkdir(parents=True)
        for packages, ref, image, commit in (
            (before, refs[0], images[0], True),
            (after, refs[1], images[1], False),
        ):
            (root / "package-lock.json").write_text(ReviewHelpers.lock(packages), encoding="utf-8")
            (root / ".github/workflows/ci.yml").write_text(cls.workflow(ref), encoding="utf-8")
            (root / "Dockerfile").write_text(f"FROM python:{image}-slim\n", encoding="utf-8")
            if commit:
                cls.git(root, "add", "-A")
                cls.git(root, "commit", "-qm", "base")
        return root

    @staticmethod
    def run(root, capsys, form: str = "github") -> tuple[int, str]:
        args = argparse.Namespace(
            target=str(root),
            base="HEAD",
            format=form,
            online=False,
            quiet=True,
            annotations=None,
        )
        code = ReviewCommand.run(args)
        return code, capsys.readouterr().out


class TestTheReasonCodes:
    def test_each_blocking_kind_has_the_code_decide_gives(self) -> None:
        change = PackageChange("added", "npm", "evil", None, "1.0.0")
        change.malicious = ["MAL-2025-1"]
        change.vulnerable = [("GHSA-aaaa", "critical"), ("GHSA-bbbb", "low")]
        change.release = [
            ("SUSPECT.A.001", "critical", "downloads and runs"),
            ("SUSPECT.X.001", "high", "odd"),
        ]
        change.categories = {"SUSPECT.A.001": "malicious"}
        assert [code for code, _ in change.reasons()] == ["R100", "R404", "R400", "R401"], (
            "by category, not name"
        )
        assert PackageChange("added", "npm", "fine", None, "1.0.0").reasons() == []

    def test_each_reason_is_an_error_annotation_titled_with_its_code(self) -> None:
        change = PackageChange("upgraded", "npm", "evil", "1.0.0", "1.0.1")
        change.malicious = ["MAL-2025-1"]
        out = GithubAnnotations.render([change], "origin/main")
        assert (
            out
            == "::error title=R100 Known malware::upgraded npm:evil 1.0.0 -> 1.0.1: known malware MAL-2025-1"
        )

    def test_a_message_cannot_start_a_new_workflow_command(self) -> None:
        change = PackageChange("added", "npm", "evil", None, "1.0.0")
        change.release = [("SUSPECT.X.001", "high", "line one\n::warning::forged")]
        out = GithubAnnotations.render([change], "main")
        assert out.count("\n") == 0 and "%0A::warning" in out

    def test_nothing_blocking_is_one_notice(self) -> None:
        out = GithubAnnotations.render(
            [PackageChange("added", "npm", "fine", None, "1.0.0")], "main"
        )
        assert out.startswith("::notice ") and "nothing blocks" in out


class TestThePullRequest:
    def test_a_repinned_action_and_a_new_image_tag_are_changes(self, tmp_path) -> None:
        root = Gate.repository(
            tmp_path / "repo",
            {"ms": "2.1.3"},
            {"ms": "2.1.3"},
            refs=("v3", "v4"),
            images=("3.11", "3.12"),
        )
        base = tmp_path / "base"
        base.mkdir()
        GraphDiff.at_revision(root, "HEAD", base)
        changes = GraphDiff.diff(GraphDiff.graph(base), GraphDiff.graph(root))
        kinds = {(c.ecosystem, c.old, c.new) for c in changes}
        assert ("actions", "ref:v3", "ref:v4") in kinds
        assert any(c.ecosystem == "image" and c.old and c.new for c in changes)

    def test_a_pull_request_adding_known_malware_fails_with_r100(self, tmp_path, capsys) -> None:
        probe = PackageChange("added", "npm", "flatmap-stream", None, "0.1.1")
        ChangeReview.advisories([probe])
        if not probe.malicious:
            pytest.skip("the bundled intel no longer lists flatmap-stream 0.1.1")
        root = Gate.repository(
            tmp_path / "repo", {"ms": "2.1.3"}, {"ms": "2.1.3", "flatmap-stream": "0.1.1"}
        )
        code, out = Gate.run(root, capsys)
        assert code == 1
        assert "::error title=R100 Known malware::added npm:flatmap-stream 0.1.1" in out

    def test_a_clean_pull_request_passes(self, tmp_path, capsys) -> None:
        root = Gate.repository(tmp_path / "repo", {"ms": "2.0.0"}, {"ms": "2.1.3"})
        code, out = Gate.run(root, capsys)
        assert code == 0 and out.startswith("::notice ")

    def test_two_hundred_changes_are_reviewed_inside_a_minute(self, tmp_path, capsys) -> None:
        before = {f"pkg-{i:03d}": "1.0.0" for i in range(200)}
        after = {f"pkg-{i:03d}": "1.0.1" for i in range(200)}
        root = Gate.repository(tmp_path / "repo", before, after)
        started = time.monotonic()
        Gate.run(root, capsys)
        took = time.monotonic() - started
        assert took < 60, f"a 200-change review took {took:.1f} s"

    def test_the_markdown_pass_also_writes_the_annotations_and_the_action_prints_them(
        self, tmp_path, capsys
    ) -> None:

        root = Gate.repository(tmp_path / "repo", {"ms": "2.0.0"}, {"ms": "2.1.3"})
        written = tmp_path / "out.annotations"
        args = argparse.Namespace(
            target=str(root),
            base="HEAD",
            format="markdown",
            online=False,
            quiet=True,
            annotations=str(written),
        )
        assert ReviewCommand.run(args) == 0
        assert written.read_text(encoding="utf-8").startswith("::notice ")
        action = (ROOT / "action" / "action.yml").read_text(encoding="utf-8")
        assert 'rm -f "$notes"' in action and '--annotations "$notes"' in action, "removed first"
        assert '2> "$RUNNER_TEMP/cordon-review.err"' in action, "stderr never reaches the runner"
        assert 'if [ "$code" -le 1 ]' in action, "only a finished review is printed"
        assert "sed 's/^[[:space:]]*::/: :/'" in action, (
            "a failed run's messages are shown, never as commands"
        )


class TestTheCodesAndVersionsDecideReads:
    def test_a_rule_with_its_own_code_keeps_it(self) -> None:
        from cordon_scanner.decide.decision.reason_map import ReasonMap

        rule = next(iter(ReasonMap.TABLE))
        change = PackageChange("added", "npm", "x", None, "1.0.0")
        change.release = [(rule, "high", "m")]
        assert change.reasons()[0][0] == ReasonMap.TABLE[rule]

    def test_an_unlocked_range_is_not_a_pinned_version(self) -> None:
        from cordon_scanner.foundation.results import Dependency

        ranged = Dependency(purl="pkg:npm/ms", ecosystem="npm", name="ms", declared_spec="^2.0.0")
        action = Dependency(
            purl="pkg:github/actions/checkout@v4",
            ecosystem="actions",
            name="actions/checkout",
            declared_spec="ref:v4",
        )
        assert GraphDiff.pinned_at(ranged) is None and GraphDiff.pinned_at(action) == "ref:v4"

    def test_every_code_is_the_one_decide_gives_the_same_finding(self) -> None:
        from cordon_scanner.decide.decision.evidence import FindingFact
        from cordon_scanner.decide.decision.pipeline import RuleStage
        from cordon_scanner.detect.supply import release_diff

        def decide_gives(rule: str, category: str) -> str:
            fact = FindingFact(rule_id=rule, severity="high", confidence="high", category=category)
            from cordon_scanner.decide.decision.reason_map import ReasonMap

            return ReasonMap.of(rule) or RuleStage._code_of((fact,))

        for category in ("malicious", "suspicious"):
            change = PackageChange("added", "npm", "x", None, "1.0.0")
            change.categories = {"SUSPECT.UNMAPPED.001": category}
            assert change.code_of("SUSPECT.UNMAPPED.001") == decide_gives(
                "SUSPECT.UNMAPPED.001", category
            )
        # A changed release's findings carry no category: every rule the comparison can raise is a SUSPECT rule.
        for rule in (
            release_diff.RELEASE_NEW_HOOK,
            release_diff.RELEASE_NEW_CAPABILITY,
            release_diff.RELEASE_NEW_OBFUSCATION,
            release_diff.RELEASE_NEW_BINARY,
            release_diff.RELEASE_NEW_PUBLISHER,
        ):
            assert rule.startswith("SUSPECT.")
            assert PackageChange("upgraded", "npm", "x", "1", "2").code_of(rule) == decide_gives(
                rule, "suspicious"
            )


class TestGitLabAndBitbucket:
    """The same gate on a GitLab merge request and a Bitbucket pull request: GitLab's Code Quality report and a
    Bitbucket Code Insights report carry one entry per blocking reason, titled with its reason code and placed at
    the lockfile that declares the package."""

    @staticmethod
    def flagged(tmp_path):
        probe = PackageChange("added", "npm", "flatmap-stream", None, "0.1.1")
        ChangeReview.advisories([probe])
        if not probe.malicious:
            pytest.skip("the bundled intel no longer lists flatmap-stream 0.1.1")
        return Gate.repository(
            tmp_path / "repo", {"ms": "2.1.3"}, {"ms": "2.1.3", "flatmap-stream": "0.1.1"}
        )

    def test_gitlab_code_quality_names_the_reason_at_the_lockfile(self, tmp_path, capsys) -> None:
        code, out = Gate.run(self.flagged(tmp_path), capsys, "codeclimate")
        entries = [e for e in json.loads(out) if e["check_name"] == "R100"]
        assert entries, "no R100 entry"
        entry = entries[0]
        assert code == 1
        assert entry["description"].startswith("R100 Known malware: added npm:flatmap-stream 0.1.1")
        assert entry["severity"] == "blocker" and entry["categories"] == ["Security"]
        assert entry["location"]["path"] == "package-lock.json"
        assert entry["location"]["lines"]["begin"] >= 1 and len(entry["fingerprint"]) == 64

    def test_bitbucket_code_insights_fail_with_the_reason(self, tmp_path, capsys) -> None:
        code, out = Gate.run(self.flagged(tmp_path), capsys, "bitbucket")
        document = json.loads(out)
        assert code == 1 and document["report"]["result"] == "FAILED"
        assert document["report"]["report_type"] == "SECURITY"
        found = [a for a in document["annotations"] if a["summary"].startswith("R100 ")]
        assert found, "no R100 annotation"
        annotation = found[0]
        assert (
            annotation["severity"] == "CRITICAL"
            and annotation["annotation_type"] == "VULNERABILITY"
        )
        assert annotation["path"] == "package-lock.json" and len(annotation["summary"]) <= 450

    @pytest.mark.parametrize(("form", "empty"), [("codeclimate", []), ("bitbucket", "PASSED")])
    def test_a_clean_change_passes_on_both(self, tmp_path, capsys, form: str, empty) -> None:
        root = Gate.repository(tmp_path / "repo", {"ms": "2.0.0"}, {"ms": "2.1.3"})
        code, out = Gate.run(root, capsys, form)
        document = json.loads(out)
        assert code == 0
        assert (document if form == "codeclimate" else document["report"]["result"]) == empty

    def test_every_format_the_command_offers_renders(self) -> None:
        change = PackageChange("added", "npm", "x", None, "1.0.0", path="package-lock.json")
        for render in ReviewCommand.FORMATS.values():
            assert isinstance(render([change], "main"), str)
