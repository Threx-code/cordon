"""Building the NVD files from NVD's feeds: every feed is checked against its published digest before a byte
of it is used, a cut-short transfer is fetched again, and the CPE dictionary becomes a name -> product index."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.intel.advisories import nvd_import
from cordon_scanner.intel.advisories.nvd import CPE_NAME, CVES_NAME
from cordon_scanner.intel.advisories.nvd_import import NvdBuild, NvdImport, NvdImportError


class Feeds:
    """NVD's feed host, answering from a dict of URL -> bytes, and counting the requests it gets."""

    def __init__(self, pages: dict[str, bytes | Exception]) -> None:
        self.pages = pages
        self.asked: list[str] = []

    def urlopen(self, request: Any, timeout: float) -> io.BytesIO:
        url = request.full_url
        self.asked.append(url)
        page = self.pages[url]
        if isinstance(page, Exception):
            raise page
        return io.BytesIO(page)


class FeedHelpers:
    CVE: ClassVar[str] = nvd_import.CVE_FEED.format(year=2024)

    @staticmethod
    def meta(data: bytes) -> bytes:
        return (
            b"lastModifiedDate:2024\r\nsha256:" + hashlib.sha256(data).hexdigest().upper().encode()
        )

    @staticmethod
    def cve_feed(*cves: dict[str, Any]) -> tuple[bytes, bytes]:
        """The `.json.gz` body and its `.meta`, whose digest is over the uncompressed JSON."""
        raw = json.dumps({"vulnerabilities": [{"cve": c} for c in cves]}).encode()
        return gzip.compress(raw), FeedHelpers.meta(raw)

    @staticmethod
    def cpe_archive(*chunks: list[dict[str, Any]]) -> tuple[bytes, bytes]:
        """The CPE dictionary's `.tar.gz` and its `.meta`, whose digest is over the chunks' JSON in name order."""
        buffer = io.BytesIO()
        joined = b""
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            folder = tarfile.TarInfo("nvdcpe-2.0-chunks")
            folder.type = tarfile.DIRTYPE  # a directory entry is skipped
            tar.addfile(folder)
            for number, products in enumerate(chunks):
                data = json.dumps({"products": products}).encode()
                joined += data
                info = tarfile.TarInfo(f"nvdcpe-2.0-chunks/nvdcpe-2.0-{number:03}.json")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buffer.getvalue(), FeedHelpers.meta(joined)

    @staticmethod
    def product(cpe: str, refs: list[dict[str, str]], **extra: Any) -> dict[str, Any]:
        return {"cpe": {"cpeName": cpe, "refs": refs, **extra}}


@pytest.fixture
def feeds(monkeypatch: pytest.MonkeyPatch):
    def install(pages: dict[str, bytes | Exception]) -> Feeds:
        host = Feeds(pages)
        monkeypatch.setattr(nvd_import.urllib.request, "urlopen", host.urlopen)
        return host

    return install


class TestAFeedIsCheckedBeforeItIsUsed:
    def test_a_cve_feed_matching_its_digest_is_read(self, feeds) -> None:
        body, meta = FeedHelpers.cve_feed({"id": "CVE-2024-1", "vulnStatus": "Analyzed"})
        feeds({f"{FeedHelpers.CVE}.meta": meta, f"{FeedHelpers.CVE}.json.gz": body})
        assert [c["id"] for c in NvdImport.cves(2024)] == ["CVE-2024-1"]

    def test_a_rejected_or_unnamed_record_is_left_out(self, feeds) -> None:
        body, meta = FeedHelpers.cve_feed(
            {"id": "CVE-2024-1", "vulnStatus": "Rejected"}, {"vulnStatus": "Analyzed"}
        )
        feeds({f"{FeedHelpers.CVE}.meta": meta, f"{FeedHelpers.CVE}.json.gz": body})
        assert list(NvdImport.cves(2024)) == []

    def test_a_feed_that_does_not_match_fails_after_three_tries(self, feeds) -> None:
        body, _ = FeedHelpers.cve_feed({"id": "CVE-2024-1"})
        _, other = FeedHelpers.cve_feed({"id": "CVE-2024-2"})
        host = feeds({f"{FeedHelpers.CVE}.meta": other, f"{FeedHelpers.CVE}.json.gz": body})
        with pytest.raises(NvdImportError, match="does not match its published SHA-256"):
            NvdImport.verified(FeedHelpers.CVE, ".json.gz")
        assert len(host.asked) == 6  # meta and body, three times

    def test_a_transfer_cut_short_is_fetched_again(self, feeds, monkeypatch) -> None:
        body, meta = FeedHelpers.cve_feed({"id": "CVE-2024-1"})
        answers = iter([body[: len(body) // 2], body])
        host = feeds({f"{FeedHelpers.CVE}.meta": meta})
        real = host.urlopen

        def urlopen(request, timeout):
            if request.full_url.endswith(".json.gz"):
                host.asked.append(request.full_url)
                return io.BytesIO(next(answers))
            return real(request, timeout)

        monkeypatch.setattr(nvd_import.urllib.request, "urlopen", urlopen)
        assert json.loads(NvdImport.verified(FeedHelpers.CVE, ".json.gz"))["vulnerabilities"]

    def test_a_meta_file_that_gives_no_digest_fails(self, feeds) -> None:
        body, _ = FeedHelpers.cve_feed({"id": "CVE-2024-1"})
        feeds({f"{FeedHelpers.CVE}.meta": b"size:10", f"{FeedHelpers.CVE}.json.gz": body})
        with pytest.raises(NvdImportError, match="gives no SHA-256"):
            NvdImport.verified(FeedHelpers.CVE, ".json.gz")

    def test_a_feed_that_cannot_be_downloaded_fails(self, feeds) -> None:
        feeds({f"{FeedHelpers.CVE}.meta": OSError("connection reset")})
        with pytest.raises(NvdImportError, match="connection reset"):
            NvdImport.verified(FeedHelpers.CVE, ".json.gz")

    def test_only_https_is_fetched(self) -> None:
        with pytest.raises(NvdImportError, match="non-HTTPS"):
            NvdImport._fetch("http://nvd.nist.gov/feed")

    def test_a_feed_past_the_size_limit_fails(self, feeds, monkeypatch) -> None:
        monkeypatch.setattr(nvd_import, "MAX_FEED_BYTES", 8)
        feeds({"https://nvd.example/feed": b"x" * 20})
        with pytest.raises(NvdImportError, match="larger than 8 bytes"):
            NvdImport._fetch("https://nvd.example/feed")

    def test_a_cpe_archive_is_checked_over_its_chunks_in_name_order(self, feeds) -> None:
        archive, meta = FeedHelpers.cpe_archive([], [])
        base = nvd_import.CPE_FEED
        feeds({f"{base}.meta": meta, f"{base}.tar.gz": archive})
        assert NvdImport.verified(base, ".tar.gz") == archive

    def test_a_cpe_archive_that_does_not_match_fails(self, feeds) -> None:
        archive, _ = FeedHelpers.cpe_archive([])
        base = nvd_import.CPE_FEED
        feeds({f"{base}.meta": FeedHelpers.meta(b"other"), f"{base}.tar.gz": archive})
        with pytest.raises(NvdImportError, match="does not match"):
            NvdImport.verified(base, ".tar.gz")

    def test_a_cpe_archive_that_is_not_one_fails(self, feeds) -> None:
        base = nvd_import.CPE_FEED
        feeds({f"{base}.meta": FeedHelpers.meta(b""), f"{base}.tar.gz": b"not a tar"})
        with pytest.raises(NvdImportError):
            NvdImport.verified(base, ".tar.gz")


class TestTheProductIndex:
    @pytest.fixture
    def dictionary(self, feeds):
        def install(*products: dict[str, Any]) -> None:
            archive, meta = FeedHelpers.cpe_archive(list(products))
            base = nvd_import.CPE_FEED
            feeds({f"{base}.meta": meta, f"{base}.tar.gz": archive})

        return install

    def test_a_product_is_named_with_its_own_sites_and_not_advisories(self, dictionary) -> None:
        dictionary(
            FeedHelpers.product(
                "cpe:2.3:a:curl:libcurl:*",
                [
                    {"ref": "https://curl.se/libcurl/", "type": "Product"},
                    {"ref": "https://access.redhat.com/errata/1", "type": "Advisory"},
                ],
            ),
            FeedHelpers.product("cpe:2.3:a:curl:curl:*", [{"ref": "https://curl.se/"}]),
        )
        index = NvdImport.index()
        assert index["libcurl"] == [["curl:libcurl", ["curl.se"]]]
        assert all("redhat" not in str(entry) for entry in index.values())

    def test_a_deprecated_or_non_application_entry_is_left_out(self, dictionary) -> None:
        dictionary(
            FeedHelpers.product(
                "cpe:2.3:a:old:thing:*", [{"ref": "https://old.example/"}], deprecated=True
            ),
            FeedHelpers.product("cpe:2.3:o:linux:kernel:*", [{"ref": "https://kernel.org/"}]),
            FeedHelpers.product("cpe:2.3", [{"ref": "https://short.example/"}]),
        )
        assert NvdImport.index() == {}

    def test_an_acronym_in_the_title_names_the_product(self, dictionary) -> None:
        dictionary(
            FeedHelpers.product(
                "cpe:2.3:a:nasm:netwide_assembler:*",
                [{"ref": "https://www.nasm.us/", "type": "Vendor"}],
                titles=[{"title": "Netwide Assembler (NASM)"}],
            )
        )
        index = NvdImport.index()
        assert index["nasm"][0][0] == "nasm:netwide_assembler"

    def test_a_named_product_the_dictionary_lacks_takes_its_vendors_sites(self, dictionary) -> None:
        dictionary(
            FeedHelpers.product(
                "cpe:2.3:a:gnu:bash:*", [{"ref": "https://www.gnu.org/", "type": "Vendor"}]
            ),
            FeedHelpers.product("cpe:2.3:a:gnu:make:*", [{"ref": "https://www.gnu.org/"}]),
        )
        index = NvdImport.index(named={"gnu:m4"})
        assert ["gnu:m4", ["gnu.org"]] in index["m4"]

    def test_a_repository_from_a_cves_references_is_a_site(self, dictionary) -> None:
        dictionary()
        index = NvdImport.index(
            named={"open-mpi:hwloc"}, repositories={"open-mpi:hwloc": {"github.com/open-mpi/hwloc"}}
        )
        assert index["hwloc"] == [["open-mpi:hwloc", ["github.com/open-mpi/hwloc"]]]

    def test_a_product_with_no_site_anywhere_is_left_out(self, dictionary) -> None:
        dictionary(FeedHelpers.product("cpe:2.3:a:lone:tool:*", [{"ref": "not a url"}]))
        assert NvdImport.index(named={"nowhere:else"}) == {}


class TestBuildingFromTheFeeds:
    def test_a_build_reads_every_year_and_the_dictionary(self, feeds) -> None:
        cve = {
            "id": "CVE-2024-1",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "A flaw in tool.\nMore."}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.0",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        body, meta = FeedHelpers.cve_feed(cve)
        archive, cpe_meta = FeedHelpers.cpe_archive(
            [FeedHelpers.product("cpe:2.3:a:acme:tool:*", [{"ref": "https://acme.example/"}])]
        )
        feeds(
            {
                f"{FeedHelpers.CVE}.meta": meta,
                f"{FeedHelpers.CVE}.json.gz": body,
                f"{nvd_import.CPE_FEED}.meta": cpe_meta,
                f"{nvd_import.CPE_FEED}.tar.gz": archive,
            }
        )
        logged: list[str] = []
        built = NvdImport.build(range(2024, 2025), lambda i, r: True, log=logged.append)
        assert built.cves == 1
        assert built.products == {"acme:tool": [["CVE-2024-1", "", {"versionEndExcluding": "2.0"}]]}
        assert built.text == {"CVE-2024-1": "A flaw in tool."}
        assert built.index["tool"] == [["acme:tool", ["acme.example"]]]
        assert any("2024: 1" in line for line in logged)

    def test_a_cve_list_that_fails_to_download_fails_the_import(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import cve_list

        def fail(scratch: Path) -> Path:
            raise cve_list.CveListError("baseline unavailable")

        monkeypatch.setattr(cve_list.CveList, "fetch", staticmethod(fail))
        with pytest.raises(NvdImportError, match="the CVE List: baseline unavailable"):
            list(NvdImport.cve_list_records())

    def test_the_cve_list_baseline_is_read_from_a_scratch_folder(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import cve_list

        seen: list[Path] = []

        def fetch(scratch: Path) -> Path:
            seen.append(scratch)
            return scratch / "baseline.zip"

        monkeypatch.setattr(cve_list.CveList, "fetch", staticmethod(fetch))
        monkeypatch.setattr(
            cve_list.CveList, "records", staticmethod(lambda path: iter([{"cveMetadata": {}}]))
        )
        assert list(NvdImport.cve_list_records()) == [{"cveMetadata": {}}]
        assert seen and not seen[0].exists()


class TestWritingTheFiles:
    def test_both_files_are_written_and_their_digests_recorded(self, tmp_path) -> None:
        built = NvdBuild(products={"a:b": []}, index={"b": []})
        (tmp_path / nvd_import.DIGESTS_NAME).write_text(
            json.dumps({"other.json.gz": "abc", "bad": 3}), encoding="utf-8"
        )
        NvdImport.write(tmp_path, built, filtered=True, seal=False)
        manifest = json.loads((tmp_path / nvd_import.DIGESTS_NAME).read_text(encoding="utf-8"))
        assert set(manifest) == {"other.json.gz", CVES_NAME, CPE_NAME}
        cves = json.loads(gzip.decompress((tmp_path / CVES_NAME).read_bytes()))
        assert cves["filtered"] is True and cves["products"] == {"a:b": []}

    def test_the_same_input_writes_the_same_bytes(self, tmp_path) -> None:
        NvdImport._write(tmp_path / "a.json.gz", {"k": 1})
        NvdImport._write(tmp_path / "b.json.gz", {"k": 1})
        assert (tmp_path / "a.json.gz").read_bytes() == (tmp_path / "b.json.gz").read_bytes()

    def test_a_manifest_that_is_not_json_is_started_again(self, tmp_path) -> None:
        (tmp_path / nvd_import.DIGESTS_NAME).write_text("{not json", encoding="utf-8")
        NvdImport.write(tmp_path, NvdBuild(), filtered=False, seal=False)
        manifest = json.loads((tmp_path / nvd_import.DIGESTS_NAME).read_text(encoding="utf-8"))
        assert set(manifest) == {CVES_NAME, CPE_NAME}

    def test_the_years_run_from_the_first_feed(self) -> None:
        assert NvdImport.years(2004) == range(2002, 2005)
        assert NvdImport.years().start == 2002


class TestTheCveListFillsWhatNvdLeavesUnranged:
    @staticmethod
    def record(identifier: str, cpe: str, *, references=(), rating="HIGH") -> dict[str, Any]:
        return {
            "cveMetadata": {"cveId": identifier},
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "cpes": [cpe],
                            "versions": [{"status": "affected", "version": "0", "lessThan": "3.1"}],
                        }
                    ],
                    "metrics": [{"cvssV3_1": {"baseSeverity": rating}}],
                    "descriptions": [{"lang": "en", "value": "Overflow in widget."}],
                    "references": list(references),
                }
            },
        }

    def test_a_cve_nvd_gave_no_range_takes_its_records_range(self, feeds) -> None:
        cves = [
            # NVD's own analysis: one ranged CVE, one with nothing NVD ranges, one not an application.
            {
                "id": "CVE-2024-1",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:acme:tool:1.0:*"},
                                    {"vulnerable": True, "criteria": "cpe:2.3:o:acme:os:1:*:*"},
                                    {"vulnerable": False, "criteria": "cpe:2.3:a:acme:x:1:*:*"},
                                ]
                            }
                        ]
                    }
                ],
            },
            {"id": "CVE-2024-2"},
        ]
        body, meta = FeedHelpers.cve_feed(*cves)
        archive, cpe_meta = FeedHelpers.cpe_archive([])
        feeds(
            {
                f"{FeedHelpers.CVE}.meta": meta,
                f"{FeedHelpers.CVE}.json.gz": body,
                f"{nvd_import.CPE_FEED}.meta": cpe_meta,
                f"{nvd_import.CPE_FEED}.tar.gz": archive,
            }
        )
        records = [
            # NVD ranged it: NVD's analysis stands.
            self.record("CVE-2024-1", "cpe:2.3:a:acme:tool:*"),
            # NVD gave none: the record's range is used, its forge reference becomes a site.
            self.record(
                "CVE-2024-2",
                "cpe:2.3:a:widgets:widget:*",
                references=[
                    {"url": "https://github.com/widgets/widget/pull/1", "tags": ["patch"]},
                    {"url": "not a url", "tags": ["patch"]},
                ],
            ),
            # Kept out by the filter.
            self.record("CVE-2024-3", "cpe:2.3:a:low:lib:*", rating="LOW"),
            # Nothing to range, and a record with no id.
            {"cveMetadata": {"cveId": "CVE-2024-4"}, "containers": {"cna": {}}},
            {"cveMetadata": {}},
        ]
        logged: list[str] = []
        built = NvdImport.build(
            range(2024, 2025),
            lambda identifier, rating: rating != "low",
            log=logged.append,
            cve_list=records,
        )
        assert built.products["acme:tool"] == [["CVE-2024-1", "", {"v": "1.0"}]]
        assert built.products["widgets:widget"] == [
            ["CVE-2024-2", "high", {"versionEndExcluding": "3.1"}]
        ]
        assert "low:lib" not in built.products
        assert built.text["CVE-2024-2"] == "Overflow in widget."
        assert any("CVE List: 1" in line for line in logged)

    def test_a_reference_with_no_site_names_none(self) -> None:
        assert NvdImport.project_sites({"references": [{"url": "", "tags": ["Patch"]}]}) == set()

    def test_written_files_are_sealed_by_default(self, tmp_path, monkeypatch) -> None:
        sealed: list[Path] = []
        monkeypatch.setattr(nvd_import.AdvisoryFiles, "seal_manifest", staticmethod(sealed.append))
        NvdImport.write(tmp_path, NvdBuild(), filtered=False)
        assert sealed == [tmp_path]
