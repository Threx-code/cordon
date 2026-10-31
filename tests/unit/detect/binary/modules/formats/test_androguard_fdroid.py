"""The androguard module's values on 20 real open-source APKs from F-Droid (GPL, Apache or MIT, each
checked against F-Droid's index sha256; PROVENANCE.tsv in tests/unit/data/rule_reference/android/fdroid),
held to aapt2 dump badging and xmltree and apksigner verify --print-certs, recorded there once. The APKs
themselves are not kept here: they are read from the directory CORDON_ANDROID_APKS names (the Docker
volume cordon-android-apks, read only); without it these tests are skipped, and say why.

Held per APK: the package, the three SDK levels (from uses-sdk; 0 where it gives none), the label, the
requested permissions (aapt2's implied ones left out), the main activity (one of aapt2's launchable
ones), the activities and aliases, services and receivers in full, and the signer's SHA-1 and name
attributes (apksigner prints them most specific first, the module in the certificate's order)."""

from __future__ import annotations

import csv
import hashlib
import os
import re
from pathlib import Path

import pytest

from cordon_scanner.detect.binary.modules.formats.apk import Apk, ApkFacts
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "android" / "fdroid"
ROWS = {
    r["file"]: r
    for r in csv.DictReader(
        (DIR / "PROVENANCE.tsv").read_text(encoding="utf-8").splitlines(), delimiter="\t"
    )
}


class Recorded:
    """One APK's recorded reference output, and the package read from the volume."""

    def __init__(self, name: str) -> None:
        root = os.environ.get("CORDON_ANDROID_APKS")
        if not root:
            pytest.skip("CORDON_ANDROID_APKS is not set: the F-Droid APKs live in a Docker volume")
        path = Path(root) / name
        if not path.is_file():
            pytest.skip(f"{name} is not in {root}")
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == ROWS[name]["sha256"]
        found = Apk.facts(data)
        assert found is not None
        self.facts: ApkFacts = found
        self.badging = (DIR / f"{name}.badging.txt").read_text(encoding="utf-8", errors="replace")
        self.xmltree = (DIR / f"{name}.xmltree.txt").read_text(encoding="utf-8", errors="replace")
        self.certs = (DIR / f"{name}.certs.txt").read_text(encoding="utf-8", errors="replace")
        package = re.search(r"package: name='([^']*)'", self.badging)
        assert package is not None
        self.package = package.group(1)

    def sdk(self, key: str) -> int:
        block = re.search(r"E: uses-sdk.*?(?=\n\s*E: |\Z)", self.xmltree, re.S)
        found = re.search(key + r"\(0x[0-9a-f]+\)=(\d+)", block.group(0)) if block else None
        return int(found.group(1)) if found else 0

    def components(self) -> dict[str, list[bytes]]:
        out: dict[str, list[bytes]] = {}
        tag = None
        for line in self.xmltree.splitlines():
            element = re.match(r"\s*E: (\S+)", line)
            if element:
                tag = element.group(1)
                continue
            attr = re.search(r'android:name\(0x01010003\)="([^"]*)"', line)
            if attr and tag in ("activity", "activity-alias", "service", "receiver"):
                n, p = attr.group(1), self.package
                n = p + n if n.startswith(".") else n if "." in n else f"{p}.{n}"
                out.setdefault("activity" if tag.startswith("activity") else tag, []).append(
                    n.encode()
                )
        return out


class TestTheFDroidPackages:
    @pytest.mark.parametrize("name", sorted(ROWS))
    def test_every_value_is_googles(self, name: str) -> None:
        r = Recorded(name)
        f = r.facts
        assert f.package_name == r.package.encode()
        assert (f.min_sdk, f.target_sdk, f.max_sdk) == tuple(
            r.sdk(k) for k in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion")
        )
        label = re.search(r"application-label:'([^']*)'", r.badging)
        assert (f.app_name or b"") == (label.group(1).encode() if label else b"")
        implied = set(re.findall(r"uses-implied-permission: name='([^']*)'", r.badging))
        requested = {
            p
            for p in re.findall(r"uses-permission(?:-sdk-23)?: name='([^']*)'", r.badging)
            if p not in implied
        }
        assert {p.decode() for p in f.permissions} == requested
        launchable = re.findall(r"launchable-activity: name='([^']*)'", r.badging)
        assert (f.main_activity.decode() if f.main_activity else None) in (launchable or [None])
        components = r.components()
        assert (f.activities, f.services, f.receivers) == (
            components.get("activity", []),
            components.get("service", []),
            components.get("receiver", []),
        )
        sha1 = re.search(r"Signer #1 certificate SHA-1 digest: ([0-9a-f]+)", r.certs)
        dn = re.search(r"Signer #1 certificate DN: (.*)", r.certs)
        assert (
            sha1 is not None and dn is not None and f.sha1 == sha1.group(1).encode() and f.subject
        )
        theirs = [s.strip() for s in re.split(r",(?=\s*[A-Za-z.0-9]+=)", dn.group(1))]
        assert sorted(f.subject.decode().split(", ")) == sorted(theirs)
