"""The functions an advisory's prose names, read for every ecosystem (`AdvisoryTextSymbols.RULES`).

The prose is real: public advisory records saved verbatim (`upstream/advisory_prose.json`, from api.osv.dev, fetched
2026-11-27: GHSA records are CC-BY-4.0, EEF and OSEC records their publishers'). They are the records of the ecosystems in
which OSV had one whose text names a function. For the ecosystems where none of the 40 packages looked at had one (pub, hackage,
julia, cran, swift, cocoapods, opam's own libraries, ansible, conan, vcpkg, homebrew, nix, bazel) the prose below is written
in each ecosystem's documented spelling of a qualified name; it says so."""

from __future__ import annotations

import json

import pytest

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories.advisory_text import (
    AdvisoryTextSymbols,
    NoSymbols,
    Qualified,
)
from support import ROOT

PROSE = ROOT / "tests" / "unit" / "intel" / "advisories" / "upstream" / "advisory_prose.json"
REAL = {r["id"]: r for r in json.loads(PROSE.read_text(encoding="utf-8"))}


class Prose:
    @staticmethod
    def symbols(record_id: str) -> tuple[str, ...]:
        record = REAL[record_id]
        return AdvisoryTextSymbols.extract(
            record["ecosystem"], record["package"], f"{record['summary']}\n{record['details']}"
        )


class TestEveryEcosystemHasARule:
    def test_the_table_holds_exactly_the_registered_ecosystems(self) -> None:
        assert set(AdvisoryTextSymbols.RULES) == set(EcosystemRegistry.BY_ID)

    def test_an_ecosystem_with_no_symbols_says_why(self) -> None:
        for ecosystem, rule in AdvisoryTextSymbols.RULES.items():
            if isinstance(rule, NoSymbols):
                assert len(rule.reason.split()) >= 10, ecosystem
                assert (
                    AdvisoryTextSymbols.extract(
                        ecosystem, "anything", "`anything.call()` is unsafe."
                    )
                    == ()
                )

    def test_the_two_ecosystems_it_was_built_for_read_as_before(self) -> None:
        assert AdvisoryTextSymbols.RULES["npm"] == Qualified("published")
        assert AdvisoryTextSymbols.RULES["pypi"] == Qualified("python")


class TestRealProse:
    @pytest.mark.parametrize(
        ("record", "expected"),
        [
            ("GHSA-4q83-7cq4-p6wg", ("text:tokio.io.ReadHalf.unsplit",)),
            ("GHSA-6g7w-8wpp-frhj", ("text:rustls.ConnectionCommon.complete_io",)),
            ("GHSA-wcg3-cvx6-7396", ("text:time.UtcOffset.local_offset_at",)),
            ("GHSA-2j8w-xcrc-x985", ("text:Rack.Request.host_with_port",)),
            ("GHSA-vmwr-mc7x-5vc3", ("text:Rexml.Document.new",)),
            ("GHSA-3w22-6jfg-527w", ("text:Nokogiri.XML.Node.lang",)),
            ("EEF-CVE-2026-105963", ("text:Plug.Crypto.verify", "text:Plug.Crypto.decrypt")),
            ("EEF-CVE-2026-128361", ("text:Phoenix.Presence.group", "text:Phoenix.Presence.list")),
            ("GHSA-6r3c-xf4w-jxjm", ("text:org.springframework.http.ContentDisposition",)),
            ("GHSA-5crp-9r3c-p9vr", ("text:Newtonsoft.Json.JsonReaderException",)),
        ],
    )
    def test_the_function_the_prose_names_is_read(
        self, record: str, expected: tuple[str, ...]
    ) -> None:
        assert set(expected) <= set(Prose.symbols(record))

    @pytest.mark.parametrize(
        "record",
        [
            "GHSA-2r5h-6r7v-5m7c",  # symfony: `Yaml::parse`, a class of another package's namespace
            "GHSA-4r78-hx75-jjj2",  # x/net: `html.Parse`, a subpackage the module's name does not give
            "OSEC-2026-01",  # ocaml: the standard library's `Marshal.from_channel`, not a package's module
        ],
    )
    def test_a_name_the_package_does_not_give_is_never_claimed(self, record: str) -> None:
        assert Prose.symbols(record) == ()

    def test_every_symbol_is_the_packages_own(self) -> None:
        for record in REAL.values():
            for symbol in Prose.symbols(record["id"]):
                assert symbol.startswith("text:"), record["id"]


class TestDocumentedSpelling:
    """Prose written in the ecosystem's own spelling of a qualified name (no real advisory names one: see the module doc)."""

    @pytest.mark.parametrize(
        ("ecosystem", "package", "text", "expected"),
        [
            ("pub", "http", "A crash in `http.get()` on a crafted redirect.", "text:http.get"),
            ("hackage", "aeson", "`Data.Aeson.decode` overflows the stack.", "text:Aeson.decode"),
            ("julia", "HTTP", "`HTTP.request` follows a crafted header.", "text:HTTP.request"),
            ("cran", "xml2", "`xml2::read_xml()` expands entities.", "text:xml2.read_xml"),
            ("swift", "swift-nio", "`SwiftNio.Channel.write` is unbounded.", "text:SwiftNio.Channel.write"),
            ("cocoapods", "AFNetworking", "`AFNetworking.manager` skips pinning.", "text:AFNetworking.manager"),
            ("ansible", "community.general", "`community.general.nmcli` runs input.", "text:community.general.nmcli"),
            ("conan", "zlib", "`inflate()` reads past the buffer.", "text:zlib.inflate"),
            ("vcpkg", "libpng", "`png_read_row()` overflows.", "text:libpng.png_read_row"),
            ("homebrew", "curl", "`curl_easy_perform()` follows a redirect to a file.", "text:curl.curl_easy_perform"),
            ("nix", "openssl", "`X509_verify_cert()` accepts a loop.", "text:openssl.X509_verify_cert"),
            ("bazel", "rules_go", "`go_repository()` runs a fetched script.", "text:rules_go.go_repository"),
            ("conda", "PyYAML", "Unsafe `yaml.load()` allows code execution.", "text:yaml.load"),
            ("gradle", "org.apache.logging.log4j:log4j-core", "`org.apache.logging.log4j.core.lookup.JndiLookup.lookup` resolves a URL.", "text:org.apache.logging.log4j.core.lookup.JndiLookup.lookup"),
            ("composer", "monolog/monolog", "`Monolog\\Handler.write` logs a secret.", "text:Monolog.Handler.write"),
            ("gomod", "github.com/gin-gonic/gin", "`gin.Context.Bind` reads unbounded.", "text:gin.Context.Bind"),
        ],
    )  # fmt: skip
    def test_a_name_in_the_ecosystems_own_spelling_is_read(
        self, ecosystem: str, package: str, text: str, expected: str
    ) -> None:
        assert expected in AdvisoryTextSymbols.extract(ecosystem, package, text)

    @pytest.mark.parametrize(
        ("ecosystem", "package"),
        [
            ("cargo", "serde"),
            ("hex", "plug"),
            ("rubygems", "rack"),
            ("pub", "http"),
            ("julia", "HTTP"),
        ],
    )
    def test_another_packages_function_is_not_claimed(self, ecosystem: str, package: str) -> None:
        text = "`os::system()` and `Kernel.exec` and `other.call()` run input."
        assert AdvisoryTextSymbols.extract(ecosystem, package, text) == ()
