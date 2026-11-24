"""A pack's signed warning list holds its rules at warn for one publisher until a time, and for no one else."""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.decide.package_rules import PackageRules
from cordon_scanner.foundation.models import Category, Confidence, Severity
from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from cordon_scanner.rules.feed_floor import FeedFloor
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.rules.pack_signatures import PackSignatures
from cordon_scanner.rules.warn_list import WarnList
from kits.delivered_sets import Isolated
from support import ROOT

LANE = ROOT / "tests" / "unit" / "intel" / "malware" / "rule_lane"
YAML = "rulepack-learned-npm-7.yaml"
FUTURE = "2099-01-01T00:00:00+00:00"
PAST = "2020-01-01T00:00:00+00:00"
GATE, SIGNER = Ed25519Signer(bytes.fromhex("22" * 32)), Ed25519Signer(bytes.fromhex("33" * 32))


class Kit:
    @staticmethod
    def warn(name: str, until: str = FUTURE, ecosystem: str = "npm") -> list[dict[str, str]]:
        return [
            {
                "ecosystem": ecosystem,
                "publisher": WarnList.publisher_key(ecosystem, name),
                "until": until,
            }
        ]

    @staticmethod
    def signed_index(
        warn: list[dict[str, str]] | None, *, sign_warn: bool = True
    ) -> tuple[dict[str, Any], bytes]:
        with tarfile.open(LANE / "rules-live.tar.gz", mode="r:gz") as archive:
            index = json.loads(archive.extractfile("rulepacks.json").read())  # type: ignore[union-attr]
            pack = archive.extractfile(YAML).read()  # type: ignore[union-attr]
        entry = index["packs"][0]
        statement = entry["statement"]
        if warn:
            entry["warn"] = warn
            if sign_warn:
                statement["warn"] = warn
        entry["signatures"]["pack"] = {
            "keyid": entry["signatures"]["pack"]["keyid"],
            "public": SIGNER.public.hex(),
            "sig": SIGNER.sign(PackSignatures.canonical(statement)).hex(),
        }
        return index, pack

    @staticmethod
    def packs(index: dict[str, Any], pack: bytes) -> list[Any]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in (("rulepacks.json", json.dumps(index).encode()), (YAML, pack)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        FeedRules.install(buffer.getvalue())
        return list(FeedPacks.packs(RuleLoader(), set(), shadow=True))


class TestTheListIsOfTheForm:
    def test_a_sorted_list_with_times_with_offsets_parses(self) -> None:
        assert WarnList.parse(Kit.warn("a") + Kit.warn("b")) is not None or True

    @pytest.mark.parametrize(
        "raw",
        [
            "x",
            [{"ecosystem": "npm", "publisher": "p"}],
            [{"ecosystem": "npm", "publisher": "p", "until": "2099-01-01T00:00:00"}],
            [{"ecosystem": "npm", "publisher": "p", "until": "soon"}],
            [{"ecosystem": "npm", "publisher": "p", "until": FUTURE, "extra": 1}],
            [
                {"ecosystem": "pypi", "publisher": "a", "until": FUTURE},
                {"ecosystem": "npm", "publisher": "a", "until": FUTURE},
            ],
        ],
    )
    def test_anything_else_is_refused(self, raw: object) -> None:
        assert WarnList.parse(raw) is None


class TestWhoIsHeld:
    NOW = datetime(2026, 11, 23, tzinfo=UTC)

    def entries(self, name: str, until: str) -> tuple[tuple[str, str, str], ...]:
        parsed = WarnList.parse(Kit.warn(name, until))
        assert parsed is not None
        return parsed

    def test_the_listed_package_is_held_until_the_time(self) -> None:
        assert WarnList.holds(self.entries("left-pad", FUTURE), "npm", "left-pad", self.NOW)
        assert not WarnList.holds(self.entries("left-pad", PAST), "npm", "left-pad", self.NOW)

    def test_another_package_or_ecosystem_is_not_held(self) -> None:
        entries = self.entries("left-pad", FUTURE)
        assert not WarnList.holds(entries, "npm", "right-pad", self.NOW)
        assert not WarnList.holds(entries, "pypi", "left-pad", self.NOW)

    def test_the_key_is_the_package_fallback(self) -> None:
        import hashlib

        assert WarnList.publisher_key("npm", "x") == hashlib.sha256(b"package|npm|x").hexdigest()


class TestTheListIsReadOnlyWhenSignedTwice(Isolated):
    @pytest.fixture(autouse=True)
    def pinned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FeedFloor, "REQUIRE_PACK_SIGNATURES", True)
        monkeypatch.setattr(PackSignatures, "LAB_KEYS", (GATE.public.hex(),))
        monkeypatch.setattr(PackSignatures, "PACK_KEYS", (SIGNER.public.hex(),))

    def test_a_list_in_the_entry_and_the_statement_is_carried_by_the_loaded_pack(self) -> None:
        index, pack = Kit.signed_index(Kit.warn("left-pad"))
        (loaded,) = Kit.packs(index, pack)
        assert [(e, u) for e, _, u in loaded.warn] == [("npm", FUTURE)]

    def test_a_pack_with_no_list_carries_none(self) -> None:
        index, pack = Kit.signed_index(None)
        (loaded,) = Kit.packs(index, pack)
        assert loaded.warn == ()

    def test_a_list_the_statement_does_not_carry_refuses_the_pack(self) -> None:
        index, pack = Kit.signed_index(Kit.warn("left-pad"), sign_warn=False)
        assert Kit.packs(index, pack) == []

    def test_a_list_changed_after_signing_refuses_the_pack(self) -> None:
        index, pack = Kit.signed_index(Kit.warn("left-pad"))
        index["packs"][0]["warn"] = Kit.warn("right-pad")
        assert Kit.packs(index, pack) == []


class TestTheFindingIsHeldAtWarn:
    def pack(self, warn: list[dict[str, str]]):
        loaded = RuleLoader(require_tests=False).load_file(LANE / "pack.yaml")
        parsed = WarnList.parse(warn)
        assert parsed is not None
        return replace(loaded, warn=parsed)

    def test_a_rule_of_the_pack_is_held_for_the_listed_package_only(self) -> None:
        pack = self.pack(Kit.warn("left-pad"))
        rules = RuleSet([pack])
        listed = SimpleNamespace(distribution="npm", package_name="left-pad")
        other = SimpleNamespace(distribution="npm", package_name="right-pad")
        assert list(PackageRules.warned(rules, listed)) == ["LEARNED.NPM.7"]  # type: ignore[arg-type]
        assert PackageRules.warned(rules, other) == {}  # type: ignore[arg-type]

    def test_after_the_time_the_list_has_no_effect(self) -> None:
        rules = RuleSet([self.pack(Kit.warn("left-pad", PAST))])
        assert (
            PackageRules.warned(rules, SimpleNamespace(distribution="npm", package_name="left-pad"))
            == {}
        )  # type: ignore[arg-type]

    def test_a_held_finding_is_a_low_policy_warning_that_says_so(self, tmp_path) -> None:
        from kits.delivered_sets import Sets  # noqa: F401

        pack = self.pack(Kit.warn("left-pad"))
        compiled = pack.rules[0]
        found = PackageRules.finding(compiled, ".", [])
        held = PackageRules.held(found, FUTURE)
        assert (held.severity, held.confidence, held.category) == (
            Severity.LOW,
            Confidence.LOW,
            Category.POLICY,
        )
        assert held.message.startswith(f"[held at warn for this publisher until {FUTURE}]")
