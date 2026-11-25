"""An air-gapped install lists its learned detectors from the installed bundle alone, with the network blocked."""

from __future__ import annotations

import argparse
import socket
from datetime import date
from typing import Any

import pytest

from cordon_scanner.cli.commands.rules import RulesCommand
from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.learned_view import LearnedView
from kits.delivered_sets import Isolated, Sets

LEARNED_PACK = """
pack:
  id: edge.learned
  version: 1.0.0
  license: Apache-2.0
  expires: 2099-12-31

rules:
  - id: LEARNED.EDGE.001
    category: suspicious
    severity: high
    confidence: medium
    title: A learned detector
    message: Something happened.
    remediation: Fix it.
    learned:
      families: 4
      legit_rate: 0.0012
      interval: [0.0, 0.0041]
      batch: 2026-11-10-a
      n: 5200
    match:
      kind: regex
      pattern: 'dangerous_call'
    tests:
      positive:
        - "dangerous_call(x)"
      negative:
        - "safe_call(x)"
"""


class Kit:
    @staticmethod
    def install(**index: Any) -> None:
        entry = Sets.entry("rulepack-edge.yaml", "shadow", promoted="2026-11-10")
        FeedRules.install(Sets.rules([entry], {"rulepack-edge.yaml": LEARNED_PACK}, **index))

    @staticmethod
    def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("the network was used")

        monkeypatch.setattr(socket, "socket", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)


class TestTheLearnedViewIsReadFromTheBundle(Isolated):
    def test_each_detector_shows_the_bundles_date_its_age_and_its_basis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Kit.install(issued="2026-11-20")
        Kit.block_network(monkeypatch)
        lines = LearnedView.lines(date(2026, 11, 24))
        assert "issued 2026-11-20" in lines[0]
        detector = next(line for line in lines if "LEARNED.EDGE.001" in line)
        assert "shadow" in detector and "14 days" in detector
        for part in (
            "families=4",
            "legit_rate=0.0012",
            "interval=0.0000-0.0041",
            "batch=2026-11-10-a",
            "n=5200",
        ):
            assert part in detector

    def test_it_says_that_reports_leave_as_a_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        Kit.install(issued="2026-11-20")
        Kit.block_network(monkeypatch)
        assert "exported as a file" in LearnedView.lines(date(2026, 11, 24))[-1]

    def test_a_bundle_without_dates_says_so_and_does_not_guess(self) -> None:
        entry = Sets.entry("rulepack-edge.yaml")
        FeedRules.install(Sets.rules([entry], {"rulepack-edge.yaml": LEARNED_PACK}))
        lines = LearnedView.lines(date(2026, 11, 24))
        detector = next(line for line in lines if "LEARNED" in line)
        assert "date unknown" in lines[0] and "age unknown" in detector

    def test_a_machine_with_no_bundle_lists_nothing(self) -> None:
        lines = LearnedView.lines(date(2026, 11, 24))
        assert any("none" in line for line in lines)

    def test_the_command_prints_the_same_with_the_network_blocked(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        Kit.install(issued="2026-11-20")
        Kit.block_network(monkeypatch)
        code = RulesCommand.run(argparse.Namespace(rules_command="learned"))
        assert code == 0 and "LEARNED.EDGE.001" in capsys.readouterr().out
