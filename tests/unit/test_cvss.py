"""CVSS v3.x base scores against published NVD values."""

from __future__ import annotations

import pytest

from cordon_scanner.intel import cvss


class TestCvss:
    """The tests of test_cvss.py that stood alone."""

    @pytest.mark.parametrize(
        ("vector", "score"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_published_scores(self, vector: str, score: float) -> None:
        assert cvss.Cvss.base_score(vector) == score

    def test_not_a_v3_vector(self) -> None:
        assert (
            cvss.Cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
            is None
        )
        assert cvss.Cvss.base_score("CVSS:3.1/AV:X") is None

    @pytest.mark.parametrize(
        ("score", "rated"), [(9.8, "critical"), (7.0, "high"), (6.1, "medium"), (3.1, "low")]
    )
    def test_ratings(self, score: float, rated: str) -> None:
        assert cvss.Cvss.rating(score) == rated

    def test_an_osv_record_without_a_written_rating_is_rated_from_its_vector(self) -> None:
        from cordon_scanner.intel import osv_import

        record = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        assert osv_import.OsvImport._severity_of(record) == "critical"
