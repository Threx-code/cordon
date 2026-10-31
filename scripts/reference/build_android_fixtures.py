"""Build the unsigned APKs the androguard module's signed fixtures are made from (AndroidKit), into a
directory. A maintainer's tool, never part of Cordon; signing and the reference dumps are in the README
of tests/unit/data/rule_reference/android.

    PYTHONPATH=src:tests:tests/unit/detect/binary/modules/formats \\
        python scripts/reference/build_android_fixtures.py OUT_DIR
"""

from __future__ import annotations

import sys
from pathlib import Path

from test_dex import Build

from kits.androidkit import AndroidKit, Ref


class Fixtures:
    """The two packages: a full manifest (v1 and v2 signed later), and an edge-case one (v2 only)."""

    @staticmethod
    def launcher() -> list[tuple[str, dict[str, object], list[object]]]:
        return [("intent-filter", {}, [
            ("action", {"android:name": "android.intent.action.MAIN"}, []),
            ("category", {"android:name": "android.intent.category.LAUNCHER"}, []),
        ])]  # fmt: skip

    @staticmethod
    def full() -> bytes:
        manifest = ("manifest", {"package": "com.cordon.sample", "android:versionCode": 7, "android:versionName": "1.0"}, [
            ("uses-sdk", {"android:minSdkVersion": 21, "android:targetSdkVersion": 34, "android:maxSdkVersion": 35}, []),
            ("uses-permission", {"android:name": "android.permission.INTERNET"}, []),
            ("uses-permission", {"android:name": "android.permission.SEND_SMS"}, []),
            ("permission", {"android:name": "com.cordon.sample.PRIVATE"}, []),
            ("application", {"android:label": Ref(0x7F010000)}, [
                ("activity", {"android:name": ".Main"}, Fixtures.launcher()),
                ("activity", {"android:name": "Settings"}, []),
                ("activity-alias", {"android:name": "com.cordon.sample.Alias"}, []),
                ("service", {"android:name": "com.other.Svc"}, []),
                ("receiver", {"android:name": ".Boot"}, []),
            ]),
        ])  # fmt: skip
        dex = Build.dex(
            (b"Lcom/A;", b"run", b"V", b"get https://c2.example/p?q=1 then ftp://files.example/x")
        )
        return AndroidKit.apk({
            "AndroidManifest.xml": AndroidKit.manifest(manifest),
            "resources.arsc": AndroidKit.resources("com.cordon.sample", {"app_name": "Cordon Sample"}),
            "classes.dex": dex,
        })  # fmt: skip

    @staticmethod
    def edge() -> bytes:
        manifest = ("manifest", {"package": "org.cordon.edge", "android:versionCode": 1}, [
            ("uses-permission", {"android:name": "android.permission.CAMERA"}, []),
            ("application", {"android:label": "Edge App"}, [
                ("activity", {"android:name": "org.cordon.edge.Off", "android:enabled": False}, Fixtures.launcher()),
                ("activity", {"android:name": ".On"}, Fixtures.launcher()),
            ]),
        ])  # fmt: skip
        return AndroidKit.apk({
            "AndroidManifest.xml": AndroidKit.manifest(manifest),
            "resources.arsc": AndroidKit.resources("org.cordon.edge", {"unused": "x"}),
        })  # fmt: skip

    @staticmethod
    def main(out: Path) -> None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "full-unsigned.apk").write_bytes(Fixtures.full())
        (out / "edge-unsigned.apk").write_bytes(Fixtures.edge())
        print("built", sorted(p.name for p in out.iterdir()))


if __name__ == "__main__":
    Fixtures.main(Path(sys.argv[1]))
