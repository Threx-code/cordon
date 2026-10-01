"""The rubysec reader: its YAML shape, RubyGems requirements, and the ranges they leave affected."""

from __future__ import annotations

import io
import tarfile

import pytest

from cordon_scanner.intel import rubysec

CRASS = """---
gem: crass
ghsa: 6jxj-px6v-747w
url: https://github.com/advisories/GHSA-6jxj-px6v-747w
title: Crass has a denial of service
date: 2026-05-01
description: |
  A crafted stylesheet makes the tokenizer loop.
  patched_versions:
    - ">= 0"
cvss_v3: 7.5
patched_versions:
  - ">= 1.0.7"
"""

CARRIERWAVE = """---
gem: carrierwave
cve: 2023-49090
ghsa: vfmv-jfc5-pjjw
title: Content-Type allowlist bypass
patched_versions:
  - "~> 2.2.5"
  - ">= 3.0.5"
unaffected_versions:
  - "< 0.5.0"
"""


def _affected(record_text: str, version: str) -> bool:
    return any(a.affects(version) for a in rubysec.advisories_from(rubysec.parse(record_text)))


class TestTheFileShape:
    def test_scalars_and_lists(self) -> None:
        record = rubysec.parse(CRASS)
        assert record["gem"] == "crass"
        assert record["patched_versions"] == [">= 1.0.7"]
        assert record["cvss_v3"] == "7.5"

    def test_a_block_scalar_is_not_read_as_keys(self) -> None:
        # The description above contains an indented `patched_versions:` of its own.
        assert rubysec.parse(CRASS)["patched_versions"] == [">= 1.0.7"]


class TestAffectedRanges:
    @pytest.mark.parametrize(
        ("version", "expected"), [("1.0.6", True), ("1.0.7", False), ("2.0.0", False)]
    )
    def test_a_single_patched_floor(self, version: str, expected: bool) -> None:
        assert _affected(CRASS, version) is expected

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            ("0.4.9", False),  # unaffected
            ("1.3.4", True),
            ("2.2.4", True),
            ("2.2.5", False),  # ~> 2.2.5
            ("2.2.9", False),
            ("2.3.0", True),  # above the pessimistic range, below 3.0.5
            ("3.0.4", True),
            ("3.0.5", False),
        ],
    )
    def test_pessimistic_and_floor_together(self, version: str, expected: bool) -> None:
        assert _affected(CARRIERWAVE, version) is expected

    def test_identity_severity_and_aliases(self) -> None:
        advisory = rubysec.advisories_from(rubysec.parse(CARRIERWAVE))[0]
        assert advisory.identifier == "GHSA-vfmv-jfc5-pjjw"
        assert advisory.aliases == ("CVE-2023-49090",)
        assert rubysec.advisories_from(rubysec.parse(CRASS))[0].severity == "high"

    def test_an_unreadable_requirement_yields_nothing(self) -> None:
        text = "---\ngem: x\ncve: 2020-1\npatched_versions:\n  - 'whatever'\n"
        assert rubysec.advisories_from(rubysec.parse(text)) == ()


class TestTheArchive:
    def _tarball(self, files: dict[str, str]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def test_only_gem_advisories_are_read(self) -> None:
        data = self._tarball(
            {
                "ruby-advisory-db-master/gems/crass/GHSA-6jxj-px6v-747w.yml": CRASS,
                "ruby-advisory-db-master/rubies/ruby/CVE-2020-1.yml": CRASS,
                "ruby-advisory-db-master/README.md": "not yaml",
            }
        )
        assert {a.name for a in rubysec.records_from_archive(data)} == {"crass"}

    def test_what_osv_already_has_is_dropped(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import Advisory

        data = self._tarball(
            {
                "db/gems/crass/a.yml": CRASS,
                "db/gems/carrierwave/b.yml": CARRIERWAVE,
            }
        )
        monkeypatch.setattr(rubysec, "_download", lambda: data)
        osv = (
            Advisory(
                ecosystem="rubygems",
                name="carrierwave",
                identifier="GHSA-other",
                aliases=("CVE-2023-49090",),
            ),
        )
        assert {a.name for a in rubysec.new_records(osv)} == {"crass"}

    def test_the_host_is_fixed(self) -> None:
        assert rubysec.ARCHIVE_URL.startswith(f"https://{rubysec.HOST}/rubysec/")
