"""The refresh from OSV of advisories changed since the database was built, against a fake OSV."""

from __future__ import annotations

import json

import pytest

from cordon_scanner.intel import advisories, osv_delta
from cordon_scanner.intel.osv_delta import OsvDelta, OsvDeltaError

NOW = 1_800_000_000.0
BUILT = NOW - 30 * 3600


class FakeOsv:
    """OSV's bucket: a change list per ecosystem and one record per id."""

    def __init__(self) -> None:
        self.lists: dict[str, list[tuple[float, str]]] = {}
        self.records: dict[str, dict] = {}
        self.requests: list[str] = []
        self.down: set[str] = set()

    @staticmethod
    def _stamp(when: float) -> str:
        from datetime import UTC, datetime

        return datetime.fromtimestamp(when, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def get(self, path: str, *, byte_range=None, limit: int) -> bytes:
        self.requests.append(path)
        ecosystem, _, name = path.partition("/")
        if ecosystem in self.down:
            raise OsvDeltaError("OSV could not be reached (URLError)")
        if name == "modified_id.csv":
            rows = sorted(self.lists.get(ecosystem, []), reverse=True)
            body = "".join(f"{self._stamp(t)},{i}\n" for t, i in rows).encode()
            start, end = byte_range
            return body[start : end + 1]
        return json.dumps(self.records[name.removesuffix(".json")]).encode()

    @staticmethod
    def record(identifier: str, name: str, fixed: str, *, withdrawn: bool = False) -> dict:
        value = {
            "id": identifier,
            "summary": f"{name} is vulnerable",
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": name},
                    "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                    ],
                }
            ],
        }
        if withdrawn:
            value["withdrawn"] = "2026-10-08T00:00:00Z"
        return value


class TestRefresh:
    @pytest.fixture
    def osv(self, monkeypatch, tmp_path) -> FakeOsv:
        fake = FakeOsv()
        monkeypatch.setattr(osv_delta, "ENABLED", True)
        monkeypatch.setattr(OsvDelta, "_get", staticmethod(fake.get))
        monkeypatch.setattr(OsvDelta, "state_dir", staticmethod(lambda: tmp_path / "delta"))
        advisories.ShippedAdvisories.reset_caches()
        yield fake
        advisories.ShippedAdvisories.reset_caches()

    def test_an_advisory_published_after_the_build_is_matched(self, osv: FakeOsv) -> None:
        osv.lists["npm"] = [
            (NOW - 3600, "GHSA-new1-0000-0001"),
            (BUILT - 60, "GHSA-old0-0000-0001"),
        ]
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0"
        )
        result = OsvDelta.refresh(since=BUILT, now=NOW)
        assert result.error == ""
        assert result.records == 1
        assert result.through == NOW
        advisories.ShippedAdvisories.reset_caches()
        found = advisories.ShippedAdvisories._shipped_raw("npm")["made-up-pkg"]
        assert [r["id"] for r in found] == ["GHSA-new1-0000-0001"]

    def test_only_changes_after_the_build_are_fetched(self, osv: FakeOsv) -> None:
        osv.lists["npm"] = [(BUILT - 60, "GHSA-old0-0000-0001")]
        OsvDelta.refresh(since=BUILT, now=NOW)
        assert not [r for r in osv.requests if not r.endswith("modified_id.csv")]

    def test_the_next_refresh_starts_where_the_last_ended(self, osv: FakeOsv) -> None:
        OsvDelta.refresh(since=BUILT, now=NOW)
        osv.lists["npm"] = [(NOW - 60, "GHSA-new1-0000-0001")]
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0"
        )
        assert OsvDelta.refresh(since=BUILT, now=NOW + 600).records == 0

    def test_a_withdrawn_record_removes_the_advisory(self, osv: FakeOsv) -> None:
        osv.lists["npm"] = [(NOW - 3600, "GHSA-new1-0000-0001")]
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0"
        )
        OsvDelta.refresh(since=BUILT, now=NOW)
        osv.lists["npm"].append((NOW + 60, "GHSA-new1-0000-0001"))
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0", withdrawn=True
        )
        OsvDelta.refresh(since=BUILT, now=NOW + 120)
        upserts, withdrawn = OsvDelta.read_overlay("npm")
        assert upserts == []
        assert "GHSA-new1-0000-0001" in withdrawn

    def test_git_churn_other_than_malicious_repositories_is_skipped(self, osv: FakeOsv) -> None:
        osv.lists["GIT"] = [(NOW - i, f"CVE-2026-{i:05d}") for i in range(1, 5000)]
        result = OsvDelta.refresh(since=BUILT, now=NOW)
        assert result.error == ""
        assert not [r for r in osv.requests if r.startswith("GIT/CVE")]

    def test_an_unreachable_ecosystem_is_named_and_the_others_apply(self, osv: FakeOsv) -> None:
        osv.down.add("PyPI")
        osv.lists["npm"] = [(NOW - 3600, "GHSA-new1-0000-0001")]
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0"
        )
        result = OsvDelta.refresh(since=BUILT, now=NOW)
        assert "pypi" in result.error
        assert result.through == 0.0
        assert OsvDelta.read_overlay("npm")[0]

    def test_a_tampered_overlay_is_ignored(self, osv: FakeOsv) -> None:
        osv.lists["npm"] = [(NOW - 3600, "GHSA-new1-0000-0001")]
        osv.records["GHSA-new1-0000-0001"] = FakeOsv.record(
            "GHSA-new1-0000-0001", "made-up-pkg", "2.0.0"
        )
        OsvDelta.refresh(since=BUILT, now=NOW)
        path = OsvDelta.overlay_path("npm")
        document = json.loads(path.read_text(encoding="utf-8"))
        document["withdraw"] = ["GHSA-anything"]
        path.write_text(json.dumps(document), encoding="utf-8")
        assert OsvDelta.read_overlay("npm") == ([], frozenset())

    def test_disabled_makes_no_request(self, osv: FakeOsv, monkeypatch) -> None:
        monkeypatch.setattr(osv_delta, "ENABLED", False)
        OsvDelta.refresh(since=BUILT, now=NOW)
        assert osv.requests == []
