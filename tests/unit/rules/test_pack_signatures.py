"""A delivered rule pack is taken only when the gate and the pack signer both signed it, and every clause holds.

The vectors are the rule lane's live archive (invented fixtures: a pack the scanner's emitter wrote, promoted at a fixed time with
test keys). The tests pin the test keys, re-pack the archive with one thing changed, and read what the scan would load.
"""

from __future__ import annotations

import copy
import io
import json
import tarfile
from typing import Any

import pytest

from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.feed_floor import FeedFloor
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader
from cordon_scanner.rules.pack_signatures import PackSignatures
from kits.delivered_sets import Isolated
from support import ROOT

LANE = ROOT / "tests" / "unit" / "intel" / "malware" / "rule_lane"
LAB = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
SIGNER = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
YAML = "rulepack-learned-npm-7.yaml"


class Lane:
    @staticmethod
    def parts() -> tuple[dict[str, Any], bytes]:
        with tarfile.open(LANE / "rules-live.tar.gz", mode="r:gz") as archive:
            index = json.loads(archive.extractfile("rulepacks.json").read())  # type: ignore[union-attr]
            pack = archive.extractfile(YAML).read()  # type: ignore[union-attr]
        return index, pack

    @staticmethod
    def archive(index: dict[str, Any], pack: bytes) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in (("rulepacks.json", json.dumps(index).encode()), (YAML, pack)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def loaded(index: dict[str, Any], pack: bytes) -> list[str]:
        FeedRules.install(Lane.archive(index, pack))
        return [
            c.rule.id for p in FeedPacks.packs(RuleLoader(), set(), shadow=True) for c in p.rules
        ]


class TestTwoSignaturesAreRequired(Isolated):
    @pytest.fixture(autouse=True)
    def pinned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        monkeypatch.setattr(PackSignatures, "LAB_KEYS", (LAB,))
        monkeypatch.setattr(PackSignatures, "PACK_KEYS", (SIGNER,))

    def entry(self, index: dict[str, Any]) -> dict[str, Any]:
        return index["packs"][0]

    def test_the_live_vector_signed_twice_loads(self) -> None:
        index, pack = Lane.parts()
        assert Lane.loaded(index, pack) == ["LEARNED.NPM.7"]

    @pytest.mark.parametrize("missing", ["signatures", "statement", "decision"])
    def test_a_pack_with_a_signing_part_missing_is_refused(self, missing: str) -> None:
        index, pack = Lane.parts()
        del self.entry(index)[missing]
        assert Lane.loaded(index, pack) == []

    @pytest.mark.parametrize("which", ["gate", "pack"])
    def test_a_pack_with_one_of_the_two_signatures_is_refused(self, which: str) -> None:
        index, pack = Lane.parts()
        del self.entry(index)["signatures"][which]
        assert Lane.loaded(index, pack) == []

    def test_a_pack_whose_text_was_changed_is_refused(self) -> None:
        index, pack = Lane.parts()
        assert Lane.loaded(index, pack + b"\n# changed\n") == []

    def test_a_decision_changed_after_it_was_signed_is_refused(self) -> None:
        index, pack = Lane.parts()
        self.entry(index)["decision"]["outcome"] = "block"
        assert Lane.loaded(index, pack) == []

    def test_a_statement_changed_after_it_was_signed_is_refused(self) -> None:
        index, pack = Lane.parts()
        self.entry(index)["statement"]["version"] = "9.9.9"
        assert Lane.loaded(index, pack) == []

    def test_an_enforcement_the_statement_does_not_name_is_refused(self) -> None:
        index, pack = Lane.parts()
        self.entry(index)["enforcement"] = "block"
        assert Lane.loaded(index, pack) == []

    def test_a_signature_by_a_key_that_is_not_pinned_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        index, pack = Lane.parts()
        monkeypatch.setattr(PackSignatures, "LAB_KEYS", ("00" * 32,))
        assert Lane.loaded(index, pack) == []

    def test_one_key_cannot_stand_for_both_signers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        index, pack = Lane.parts()
        monkeypatch.setattr(PackSignatures, "PACK_KEYS", (LAB,))
        assert Lane.loaded(index, pack) == []

    def test_a_signature_with_a_bad_hex_value_is_refused_not_raised(self) -> None:
        index, pack = Lane.parts()
        self.entry(index)["signatures"]["pack"]["sig"] = "not hex"
        assert Lane.loaded(index, pack) == []

    def test_the_reason_is_named(self) -> None:
        index, pack = Lane.parts()
        entry = copy.deepcopy(self.entry(index))
        del entry["signatures"]["pack"]
        assert "both" in (PackSignatures.problem(entry, pack) or "")

    def test_a_release_that_does_not_require_them_reads_the_pack_unsigned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        index, pack = Lane.parts()
        for field in ("signatures", "statement", "decision"):
            del self.entry(index)[field]
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", False)
        assert Lane.loaded(index, pack) == ["LEARNED.NPM.7"]


class TestTheReleaseDefault:
    def test_the_release_requires_both_signatures_and_pins_no_test_key(self) -> None:
        import importlib

        floor = importlib.import_module("cordon_scanner.rules.feed_floor")
        assert "REQUIRE_PACK_SIGNATURES: ClassVar[bool] = True" in (
            ROOT / "src/cordon_scanner/rules/feed_floor.py"
        ).read_text(encoding="utf-8")
        assert floor.FeedFloor is FeedFloor
        assert LAB not in PackSignatures.LAB_KEYS and SIGNER not in PackSignatures.PACK_KEYS


class TestTheScanSaysDeliveredPacksAreOff:
    """With two signatures required and no key pinned, no delivered pack loads, and the scan's intel status says why."""

    def test_a_release_with_no_pinned_key_says_off_and_names_the_missing_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        status = PackSignatures.delivered_status()
        assert (
            status.startswith("off: no lab or pack-signer key is pinned")
            and "bundled rules run alone" in status
        )

    def test_with_both_keys_pinned_it_says_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        monkeypatch.setattr(PackSignatures, "LAB_KEYS", (LAB,))
        monkeypatch.setattr(PackSignatures, "PACK_KEYS", (SIGNER,))
        assert PackSignatures.delivered_status() == "on"

    def test_with_only_the_pack_key_missing_it_names_that_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        monkeypatch.setattr(PackSignatures, "LAB_KEYS", (LAB,))
        assert "no pack-signer key" in PackSignatures.delivered_status()

    def test_a_scan_result_carries_it_in_its_intel_status(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        (tmp_path / "package.json").write_text('{"name":"p","version":"1.0.0"}', encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            tmp_path
        )
        assert str(result.to_dict()["intel"]["delivered_packs"]).startswith("off:")
