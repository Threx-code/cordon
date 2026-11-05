"""A malicious-package record matches what it names, as it names it.

```
  record ── case-sensitive registry? ── exact spelling only      (`Orchestrator` != `orchestrator`)
         ── lists exact versions?    ── those versions only      (`roboter` 2.0.2, not 12.7.0)
         ── reviewed as not malware? ── dropped; its vulnerability record still reports
```
"""

from __future__ import annotations

from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase


class Records:
    @staticmethod
    def malicious(name: str, identifier: str, **kwargs: object) -> Advisory:
        return Advisory(
            ecosystem="npm", name=name, malicious=True, summary="s", identifier=identifier, **kwargs
        )  # type: ignore[arg-type]


class TestAdvisoryNaming:
    def test_an_npm_name_matches_only_its_own_case(self) -> None:
        database = AdvisoryDatabase((Records.malicious("Orchestrator", "MAL-X", introduced="0"),))
        assert database.matching("npm", "orchestrator", "0.3.8") == ()
        assert len(database.matching("npm", "Orchestrator", "0.3.8")) == 1

    def test_a_record_listing_its_versions_claims_only_those(self) -> None:
        database = AdvisoryDatabase(
            (
                Records.malicious("roboter", "MAL-Y", versions=("2.0.2",)),
                Records.malicious("roboter", "MAL-Y", introduced="0"),
            )
        )
        assert database.matching("npm", "roboter", "12.7.0") == ()
        assert len(database.matching("npm", "roboter", "2.0.2")) >= 1

    def test_an_open_range_with_no_list_still_covers_every_version(self) -> None:
        database = AdvisoryDatabase((Records.malicious("evil-squat", "MAL-Z", introduced="0"),))
        assert len(database.matching("npm", "evil-squat", "9.9.9")) == 1

    def test_a_reviewed_record_is_not_malware_but_its_vulnerability_stays(self) -> None:
        database = AdvisoryDatabase(
            (
                Records.malicious("fsevents", "MAL-2023-462", introduced="1.0.0", fixed="1.2.11"),
                Advisory(
                    ecosystem="npm",
                    name="fsevents",
                    summary="Code injection in fsevents",
                    identifier="GHSA-8r6j-v8pm-fqw3",
                    introduced="0",
                    fixed="1.2.11",
                ),
            )
        )
        found = database.matching("npm", "fsevents", "1.1.3")
        assert [a.identifier for a in found] == ["GHSA-8r6j-v8pm-fqw3"]
        assert not any(a.malicious for a in found)
