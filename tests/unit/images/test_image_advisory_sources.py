"""Where an image's operating-system advisories come from: Amazon's updateinfo and OSV's API.

The network is replaced by canned responses; what matters is what is refused, what is said when a
source cannot be reached, and which version compares as newer.
"""

from __future__ import annotations

import gzip
import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from cordon_scanner.images import alas, osv
from cordon_scanner.images.alas import AlasError, AmazonLinuxAdvisories
from cordon_scanner.images.osv import OsvClient, OsvError, Query
from cordon_scanner.images.packages import OsPackage


class Response(io.BytesIO):
    """What `urlopen` returns: a body that can be read in pieces and used as a context manager."""

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)


class _Kit_serve:
    @staticmethod
    def serve(monkeypatch: pytest.MonkeyPatch, answers: dict[str, bytes | Exception]) -> list[str]:
        asked: list[str] = []

        def urlopen(request: Any, timeout: float = 0) -> Response:
            url = request.full_url
            asked.append(url)
            answer = answers[url]
            if isinstance(answer, Exception):
                raise answer
            return Response(answer)

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        return asked


serve = _Kit_serve.serve


class TestRpmVersionsTheOtherWay:
    """The same vectors as the conformance table, with the sides swapped."""

    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("1.0", "1.0~rc1", 1),
            ("1.0~rc2", "1.0~rc1", 1),
            ("1.0~rc1", "1.0~rc1~git123", 1),
            ("1.0", "1.0^", -1),
            ("1.0", "1.0^git1", -1),
            ("1.01", "1.0^git1", 1),
            ("1.0.1", "1.0^git1", 1),
            ("1.0^git2", "1.0^git1", 1),
            ("1.0^git1", "1.0^git1~pre", 1),
            ("1.0~rc1", "1.0~rc1^git1", -1),
            ("1.0^", "1.0^git1", -1),
            ("1.0^git1", "1.0^", 1),
        ],
    )
    def test_vercmp(self, a: str, b: str, expected: int) -> None:
        assert AmazonLinuxAdvisories.vercmp(a, b) == expected
        assert AmazonLinuxAdvisories.vercmp(b, a) == -expected


UPDATEINFO = b"""<updates>
 <update type="security"><id>ALAS-1</id><title>openssl</title><severity>critical</severity>
  <pkglist><collection>
   <package name="openssl" epoch="1" version="3.0.8" release="2.amzn2023" arch="x86_64"/>
   <package name="openssl" epoch="1" version="3.0.8" release="2.amzn2023" arch="aarch64"/>
  </collection></pkglist></update>
 <update type="security"><id>ALAS-2</id><title>openssl again</title><severity>moderate</severity>
  <pkglist><collection>
   <package name="openssl" epoch="1" version="3.0.9" release="1.amzn2023" arch="noarch"/>
  </collection></pkglist></update>
</updates>"""


class TestAffected:
    def test_one_match_per_advisory_and_only_for_the_packages_architecture(self) -> None:
        advisories = AmazonLinuxAdvisories.parse(UPDATEINFO)
        installed = [OsPackage("rpm", "openssl", "3.0.1-1.amzn2023", "x86_64", epoch="1")]
        found = AmazonLinuxAdvisories.affected(installed, advisories)
        assert [(m.advisory.id, m.fixed) for m in found] == [
            ("ALAS-1", "1:3.0.8-2.amzn2023"),
            ("ALAS-2", "1:3.0.9-1.amzn2023"),
        ]
        assert [a.severity for a in advisories] == ["critical", "medium"]

    def test_an_advisory_for_another_architecture_does_not_match(self) -> None:
        advisories = AmazonLinuxAdvisories.parse(UPDATEINFO)
        installed = [OsPackage("rpm", "openssl", "3.0.1-1.amzn2023", "s390x", epoch="1")]
        # ALAS-1 lists x86_64 and aarch64 only; ALAS-2's package is noarch, which fits any machine.
        assert [m.advisory.id for m in AmazonLinuxAdvisories.affected(installed, advisories)] == [
            "ALAS-2"
        ]

    def test_packages_of_other_managers_are_not_compared(self) -> None:
        advisories = AmazonLinuxAdvisories.parse(UPDATEINFO)
        installed = [OsPackage("dpkg", "openssl", "1", "x86_64")]
        assert AmazonLinuxAdvisories.affected(installed, advisories) == []

    def test_a_version_with_no_release_is_compared_as_it_is(self) -> None:
        advisories = AmazonLinuxAdvisories.parse(UPDATEINFO)
        installed = [OsPackage("rpm", "openssl", "3.0.1", "", epoch="1")]
        assert {m.advisory.id for m in AmazonLinuxAdvisories.affected(installed, advisories)} == {
            "ALAS-1",
            "ALAS-2",
        }

    def test_an_advisory_listing_a_package_twice_matches_once(self) -> None:
        twice = b"""<updates><update type="security"><id>X</id><pkglist><collection>
          <package name="a" version="2" release="1" arch="x86_64"/>
          <package name="a" version="3" release="1" arch="noarch"/>
          </collection></pkglist></update></updates>"""
        found = AmazonLinuxAdvisories.affected(
            [OsPackage("rpm", "a", "1-1", "x86_64")], AmazonLinuxAdvisories.parse(twice)
        )
        assert len(found) == 1

    def test_bad_xml_is_an_error_naming_the_file(self) -> None:
        with pytest.raises(AlasError, match=r"updateinfo\.xml did not parse"):
            AmazonLinuxAdvisories.parse(b"<updates")


MIRROR = "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"
BASE = "https://cdn.amazonlinux.com/al2023/mirror"
REPOMD = f"{BASE}/repodata/repomd.xml"
REPOMD_BODY = (
    b'<repomd><data type="updateinfo"><location href="repodata/u.xml.gz"/></data></repomd>'
)


class TestFetch:
    def test_updateinfo_is_followed_from_the_mirror_list_and_unzipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = serve(
            monkeypatch,
            {
                MIRROR: f"{BASE}/\nhttps://elsewhere.test/\n".encode(),
                REPOMD: REPOMD_BODY,
                f"{BASE}/repodata/u.xml.gz": gzip.compress(UPDATEINFO),
            },
        )
        advisories = AmazonLinuxAdvisories.fetch("2023")
        assert [a.id for a in advisories] == ["ALAS-1", "ALAS-2"]
        assert asked == [MIRROR, REPOMD, f"{BASE}/repodata/u.xml.gz"]

    def test_an_uncompressed_updateinfo_is_read_as_it_is(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        serve(
            monkeypatch,
            {
                MIRROR: BASE.encode(),
                REPOMD: REPOMD_BODY.replace(b"u.xml.gz", b"u.xml"),
                f"{BASE}/repodata/u.xml": UPDATEINFO,
            },
        )
        assert len(AmazonLinuxAdvisories.fetch("2023")) == 2

    def test_a_release_without_a_source_is_refused_before_any_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = serve(monkeypatch, {})
        with pytest.raises(AlasError, match="no advisory source is known for Amazon Linux 1"):
            AmazonLinuxAdvisories.fetch("1")
        assert asked == []

    def test_an_empty_mirror_list_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        serve(monkeypatch, {MIRROR: b"\n"})
        with pytest.raises(AlasError, match="mirror list was empty"):
            AmazonLinuxAdvisories.fetch("2023")

    def test_a_repository_without_updateinfo_is_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        serve(monkeypatch, {MIRROR: BASE.encode(), REPOMD: b"<repomd/>"})
        with pytest.raises(AlasError, match="lists no updateinfo"):
            AmazonLinuxAdvisories.fetch("2023")

    def test_a_damaged_gzip_is_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        serve(
            monkeypatch,
            {MIRROR: BASE.encode(), REPOMD: REPOMD_BODY, f"{BASE}/repodata/u.xml.gz": b"not gzip"},
        )
        with pytest.raises(AlasError, match="did not decompress"):
            AmazonLinuxAdvisories.fetch("2023")

    def test_an_unreachable_host_is_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        serve(monkeypatch, {MIRROR: urllib.error.URLError("down")})
        with pytest.raises(AlasError, match=r"cdn\.amazonlinux\.com could not be reached"):
            AmazonLinuxAdvisories.fetch("2023")

    def test_a_body_past_the_cap_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(alas, "MAX_BYTES", 8)
        serve(monkeypatch, {MIRROR: b"x" * 100})
        with pytest.raises(AlasError, match="larger than the reader accepts"):
            AmazonLinuxAdvisories.fetch("2023")

    def test_a_plain_http_address_is_refused(self) -> None:
        with pytest.raises(AlasError, match="refusing an Amazon Linux URL"):
            AmazonLinuxAdvisories._get("http://cdn.amazonlinux.com/x")


class TestOsvTransport:
    def test_post_sends_the_body_as_json_and_reads_the_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[Any] = []

        def urlopen(request: Any, timeout: float = 0) -> Response:
            seen.append(request)
            return Response(b'{"results": []}')

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        assert OsvClient._post(f"{osv.API}/querybatch", {"queries": [1]}) == {"results": []}
        assert seen[0].get_method() == "POST"
        assert json.loads(seen[0].data) == {"queries": [1]}
        assert seen[0].get_header("Content-type") == "application/json"

    def test_get_reads_one_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        serve(monkeypatch, {f"{osv.API}/vulns/X": b'{"id": "X"}'})
        assert OsvClient._get(f"{osv.API}/vulns/X") == {"id": "X"}


class _Kit_query:
    @staticmethod
    def query(name: str = "openssl") -> Query:
        return Query("Debian:12", name, "3.0.1")


query = _Kit_query.query


class TestOsvMatch:
    def test_a_failed_batch_names_why(self) -> None:
        def post(url: str, body: dict[str, Any]) -> Any:
            raise urllib.error.URLError("no route")

        with pytest.raises(OsvError, match="OSV could not be asked"):
            OsvClient.match([query()], post=post, get=lambda url: {})

    def test_an_answer_that_is_not_json_is_the_same_error(self) -> None:
        def post(url: str, body: dict[str, Any]) -> Any:
            raise ValueError("bad json")

        with pytest.raises(OsvError, match="OSV could not be asked"):
            OsvClient.match([query()], post=post)

    def test_a_paged_answer_and_a_missing_record_are_reported(self) -> None:
        def post(url: str, body: dict[str, Any]) -> Any:
            return {
                "results": [{"vulns": [{"id": "DSA-1"}, {"id": "DSA-2"}], "next_page_token": "t"}]
            }

        def get(url: str) -> Any:
            if url.endswith("DSA-2"):
                raise urllib.error.URLError("gone")
            return {"id": "DSA-1", "summary": "s"}

        found = OsvClient.match([query()], post=post, get=get)
        assert [v.id for v in found.by_query[query()]] == ["DSA-1"]
        assert any("only the first page was read" in p for p in found.problems)
        assert "1 advisory record(s) could not be fetched from OSV" in found.problems

    def test_details_are_fetched_for_a_bounded_number_of_advisories(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(osv, "MAX_DETAILS", 2)
        fetched: list[str] = []

        def post(url: str, body: dict[str, Any]) -> Any:
            return {"results": [{"vulns": [{"id": f"V-{i}"} for i in range(5)]}]}

        def get(url: str) -> Any:
            fetched.append(url)
            return {"id": url.rsplit("/", 1)[-1]}

        found = OsvClient.match([query()], post=post, get=get)
        assert sorted(fetched) == [f"{osv.API}/vulns/V-0", f"{osv.API}/vulns/V-1"]
        assert any("details were fetched for the first 2" in p for p in found.problems)
        assert [v.id for v in found.by_query[query()]] == ["V-0", "V-1"]

    def test_queries_go_in_batches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(osv, "BATCH", 2)
        sizes: list[int] = []

        def post(url: str, body: dict[str, Any]) -> Any:
            sizes.append(len(body["queries"]))
            return {"results": [{} for _ in body["queries"]]}

        OsvClient.match([query(f"p{i}") for i in range(5)], post=post, get=lambda u: {})
        assert sizes == [2, 2, 1]


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestCvss:
    @pytest.mark.parametrize(
        ("vector", "score"),
        [
            (VECTOR, 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:2.0/AV:N", None),
            ("CVSS:3.1/AV:N/AC:L", None),
            ("", None),
        ],
    )
    def test_base_scores(self, vector: str, score: float | None) -> None:
        assert OsvClient.cvss3_base(vector) == score


class TestOsvRecords:
    def test_a_record_is_read_for_the_package_asked_about(self) -> None:
        record = {
            "id": "DSA-1",
            "summary": "s",
            "aliases": ["CVE-2026-0001"],
            "upstream": ["CVE-2026-0002"],
            "severity": [{"type": "CVSS_V3", "score": VECTOR}, "junk", {"score": "CVSS:2.0/x"}],
            "affected": [
                {
                    "package": {"name": "other", "ecosystem": "Debian:12"},
                    "ranges": [{"events": [{"fixed": "9"}]}],
                },
                {
                    "package": {"name": "openssl", "ecosystem": "Debian:11"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.2"}]}],
                },
            ],
            "references": [{"url": "https://a.test"}, {"nourl": 1}, "x", {"url": "https://b.test"}],
        }
        got = OsvClient._vulnerability(record, query())
        assert got.id == "DSA-1" and got.score == 9.8
        assert got.cves == {"CVE-2026-0001", "CVE-2026-0002"}
        assert got.fixed == "3.0.2"
        assert got.references == (
            "https://a.test",
        )  # only the first three references are looked at

    def test_a_record_with_no_vector_has_no_score(self) -> None:
        got = OsvClient._vulnerability({"id": "CVE-2026-9999", "details": "d"}, query())
        assert got.score is None and got.summary == "d" and got.cves == {"CVE-2026-9999"}
