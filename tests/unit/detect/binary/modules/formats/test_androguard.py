"""The `androguard` module (modules.formats.androguard on formats.apk and formats.axml): its values held
to Google's own reading of two signed packages (aapt2 dump badging and xmltree, apksigner verify
--print-certs, recorded in tests/unit/data/rule_reference/android), its functions' semantics as the
Koodous module defines them (strcasecmp for text, a regex match ending past the first byte), a Koodous
report given to the scan, and files that are not packages.

Named differences from aapt2, where the module follows androguard (the reader Koodous's reports come
from): aapt2 lists every launcher activity, a disabled one included, and the main activity here is the
first that is not disabled; aapt2 adds permissions it implies (a target SDK under 4), and the module
reads only those the manifest requests; apksigner prints a name most specific attribute first, and the
module in the certificate's own order, as androguard does."""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.formats.androguard import Androguard
from cordon_scanner.detect.binary.modules.formats.apk import Apk, ApkFacts
from cordon_scanner.detect.binary.rule_engine.lang import Rules
from kits.androidkit import AndroidKit
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "android"


class Reference:
    """What Google's tools recorded for one package."""

    @staticmethod
    def text(name: str) -> str:
        return (DIR / name).read_text(encoding="utf-8")

    @staticmethod
    def badging(name: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for line in Reference.text(f"{name}.badging.txt").splitlines():
            for key in ("package", "minSdkVersion", "maxSdkVersion", "targetSdkVersion", "uses-permission",
                        "application-label", "launchable-activity"):  # fmt: skip
                if line.startswith(key + ":"):
                    value = re.search(r"'([^']*)'", line)
                    out.setdefault(key, []).append(value.group(1) if value else "")
        return out

    @staticmethod
    def components(name: str) -> dict[str, list[str]]:
        """The xmltree's component names under `application`, by tag, as the manifest writes them."""
        out: dict[str, list[str]] = {}
        tag = None
        for line in Reference.text(f"{name}.xmltree.txt").splitlines():
            element = re.match(r"\s*E: (\S+)", line)
            if element:
                tag = element.group(1)
                continue
            attr = re.search(r'android:name\(0x01010003\)="([^"]*)"', line)
            if attr and tag in ("activity", "activity-alias", "service", "receiver"):
                out.setdefault(tag, []).append(attr.group(1))
        return out

    @staticmethod
    def signer(name: str) -> tuple[str, str]:
        text = Reference.text(f"{name}.certs.txt")
        dn = re.search(r"certificate DN: (.*)", text)
        sha1 = re.search(r"certificate SHA-1 digest: ([0-9a-f]+)", text)
        assert dn and sha1
        return dn.group(1), sha1.group(1)

    @staticmethod
    def facts(name: str) -> ApkFacts:
        found = Apk.facts((DIR / f"{name}.apk").read_bytes())
        assert found is not None
        return found


class TestAgainstGooglesTools:
    @pytest.mark.parametrize("name", ["full", "edge"])
    def test_the_manifest_values_are_aapt2s(self, name: str) -> None:
        f, b = Reference.facts(name), Reference.badging(name)
        assert f.package_name == b["package"][0].encode()
        for key, value in (
            ("minSdkVersion", f.min_sdk),
            ("maxSdkVersion", f.max_sdk),
            ("targetSdkVersion", f.target_sdk),
        ):
            assert value == int(b.get(key, ["0"])[0])
        assert f.app_name == b["application-label"][0].encode()
        implied = set(
            re.findall(
                r"uses-implied-permission: name='([^']*)'", Reference.text(f"{name}.badging.txt")
            )
        )
        assert [p.decode() for p in f.permissions] == [
            p for p in b["uses-permission"] if p not in implied
        ]
        assert f.main_activity is not None and f.main_activity.decode() in b["launchable-activity"]

    @pytest.mark.parametrize("name", ["full", "edge"])
    def test_the_components_are_the_xmltrees_in_full(self, name: str) -> None:
        f, tree = Reference.facts(name), Reference.components(name)
        package = Reference.badging(name)["package"][0]

        def full(n: str) -> bytes:
            return (
                package + n if n.startswith(".") else n if "." in n else f"{package}.{n}"
            ).encode()

        assert f.activities == [
            full(n) for n in tree.get("activity", []) + tree.get("activity-alias", [])
        ]
        assert f.services == [full(n) for n in tree.get("service", [])]
        assert f.receivers == [full(n) for n in tree.get("receiver", [])]

    @pytest.mark.parametrize("name", ["full", "edge"])  # full: v1 PKCS#7; edge: the v2 block only
    def test_the_signer_is_apksigners(self, name: str) -> None:
        f = Reference.facts(name)
        dn, sha1 = Reference.signer(name)
        assert f.sha1 == sha1.encode()
        assert f.subject is not None and f.subject.decode().split(", ") == list(
            reversed(dn.split(", "))
        )
        assert f.issuer == f.subject  # self-signed

    def test_the_named_differences(self) -> None:
        edge = Reference.badging("edge")
        assert edge["launchable-activity"] == ["org.cordon.edge.Off", "org.cordon.edge.On"]
        assert Reference.facts("edge").main_activity == b"org.cordon.edge.On"  # Off is disabled
        assert "android.permission.READ_PHONE_STATE" in edge["uses-permission"]
        assert Reference.facts("edge").permissions == [b"android.permission.CAMERA"]

    def test_the_urls_in_the_dex(self) -> None:
        assert Reference.facts("full").urls == [
            b"https://c2.example/p?q=1",
            b"ftp://files.example/x",
        ]


class TestTheFunctions:
    @staticmethod
    def holds(condition: str, data: bytes | None = None) -> bool:
        rules = Rules.compile('import "androguard" rule r { condition: ' + condition + " }")
        return bool(rules.match((DIR / "full.apk").read_bytes() if data is None else data))

    @pytest.mark.parametrize(
        "condition",
        [
            'androguard.package_name("COM.CORDON.SAMPLE")', "androguard.package_name(/sample$/)",
            'androguard.app_name("cordon sample")', "androguard.main_activity(/\\.Main$/)",
            'androguard.activity("com.cordon.sample.settings")', "androguard.activity(/Alias/)",
            'androguard.service("com.other.svc")', "androguard.service(/Svc/)",
            'androguard.receiver("com.cordon.sample.boot")', "androguard.receiver(/Boot/)",
            "androguard.permission(/SEND_SMS/)", "androguard.permission(/PRIVATE/)",
            "androguard.permissions_number == 2", "androguard.url(/c2\\.example/)",
            'androguard.url("FTP://files.example/x")',
            'androguard.certificate.sha1("1AFD8C4643CC206851604AFD15E763D6E013AC45")',
            "androguard.certificate.subject(/CN=Cordon Test/)", "androguard.certificate.issuer(/C=GB/)",
            "androguard.min_sdk == 21 and androguard.target_sdk == 34 and androguard.max_sdk == 35",
        ],
    )  # fmt: skip
    def test_each_holds_on_the_full_package(self, condition: str) -> None:
        assert self.holds(condition)

    @pytest.mark.parametrize(
        "condition",
        [
            'androguard.app_name("Cordon")', "androguard.permission(/^/)", 'androguard.url("https://c2.example")',
            "androguard.service(/^$/)", 'androguard.certificate.sha1("1afd")',
        ],
    )  # fmt: skip
    def test_whole_text_and_a_match_past_the_first_byte(self, condition: str) -> None:
        """Text is compared whole; an empty match at the start is no match (`yr_re_match > 0`)."""
        assert not self.holds(condition)

    def test_not_a_package(self) -> None:
        for data in (b"not an apk", AndroidKit.apk({"x.txt": b"x"}), b"PK\x03\x04" + b"\x00" * 64):
            assert Apk.facts(data) is None
            assert not self.holds(
                "androguard.permissions_number > 0 or androguard.package_name(/./)", data
            )
            assert self.holds("androguard.min_sdk == 0", data)

    def test_an_entry_marked_encrypted_is_read_as_android_reads_it(self) -> None:
        data = bytearray((DIR / "full.apk").read_bytes())
        at = data.find(b"PK\x01\x02")
        while at >= 0:  # set the encryption bit in every central and local header
            data[at + 8] |= 1
            at = data.find(b"PK\x01\x02", at + 4)
        at = data.find(b"PK\x03\x04")
        while at >= 0:
            data[at + 6] |= 1
            at = data.find(b"PK\x03\x04", at + 4)
        f = Apk.facts(bytes(data))
        assert f is not None and f.package_name == b"com.cordon.sample"


class TestAReport:
    REPORT: ClassVar[dict[str, Any]] = {
        "package_name": "com.evil.app", "app_name": "Flash Player", "main_activity": "com.evil.app.Main",
        "activities": ["com.evil.app.Main"], "services": ["com.evil.app.Svc"], "receivers": ["com.evil.app.Boot"],
        "permissions": ["android.permission.SEND_SMS"], "new_permissions": ["com.evil.app.C2D"],
        "urls": ["http://c2.example/gate.php"], "min_sdk_version": " 9x", "target_sdk_version": "21",
        "certificate": {"sha1": "ABCD", "subjectDN": "CN=Evil", "IssuerDN": "CN=Evil CA"},
    }  # fmt: skip

    def test_a_report_answers_for_every_file(self) -> None:
        source = 'import "androguard" rule r { condition: androguard.package_name("com.evil.app") and androguard.url(/gate/) and androguard.min_sdk == 9 and androguard.target_sdk == 21 and androguard.max_sdk == 0 and androguard.certificate.issuer(/Evil CA/) and androguard.receiver("COM.EVIL.APP.BOOT") and androguard.permission(/C2D/) and androguard.permissions_number == 1 }'
        rules = Rules.compile(source)
        given = {"androguard": Androguard.module(json.dumps(self.REPORT).encode())}
        assert rules.match(b"any file at all", given=given)

    @pytest.mark.parametrize("raw", [b"[1, 2]", b"not json", b'"text"'])
    def test_a_report_that_is_not_an_object_is_refused(self, raw: bytes) -> None:
        with pytest.raises(ValueError, match="androguard report"):
            Androguard.report(raw)

    def test_text_is_read_to_its_first_nul_and_odd_items_are_skipped(self) -> None:
        f = Androguard.report(
            json.dumps({"package_name": "a.b\u0000c", "urls": ["http://x", 3, None]}).encode()
        )
        assert f.package_name == b"a.b" and f.urls == [b"http://x"] and f.min_sdk == 0
