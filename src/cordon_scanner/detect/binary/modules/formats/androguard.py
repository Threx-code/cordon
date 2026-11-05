"""cordon-rule's `androguard` module: an Android package's manifest, signer and URLs as a condition sees
them, with Koodous's names (the module the Koodous rule collections import).

Each function answers 1 or 0. A text argument is compared whole, ignoring ASCII case (`strcasecmp`); a
regular expression must match somewhere with the match ending past the text's first byte, as the
reference's `yr_re_match(...) > 0` reads (an empty match at the start does not count).

    package_name(s|r)  app_name(s|r)  main_activity(r)
    activity(s|r)  service(s|r)  receiver(s|r)   any of the manifest's components
    permission(r)          a requested permission, else a declared one
    permissions_number     how many permissions are requested
    url(s|r)               a URL the code's string tables name
    certificate.sha1(s)  certificate.subject(r)  certificate.issuer(r)
    min_sdk  max_sdk  target_sdk   0 where the manifest gives none

The values are read from the package itself (`formats.apk`): no report is needed. A Koodous report given
to the scan (`--rule-module-data androguard=report.json`) is read instead, as the reference reads one:
`package_name`, `app_name`, `main_activity`, `activities`, `services`, `receivers`, `permissions`,
`new_permissions`, `urls`, the `*_sdk_version` texts (C's atoi) and `certificate.{sha1,subjectDN,IssuerDN}`.
A report that is not a JSON object is refused. Text is read up to its first NUL, as C reads it.

Beyond the Koodous source this module was measured from (androguard.c, Apache-2.0): `activity(s)`,
`receiver(s|r)` and `permissions_number` are the later collections' surface, given the same semantics as
their siblings (`receivers` read like `services`; the count is the requested list's length).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.formats.apk import Apk, ApkFacts
from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Sig

INT = Scalar.INT


class Androguard:
    """The module: its declaration and its values for one package's facts."""

    @staticmethod
    def _fn(*kinds: str) -> Call:
        return Call(*(Sig((k,), INT) for k in kinds))

    SCHEMA: ClassVar[Record] = Record(
        {
            "package_name": _fn("text", "regex"),
            "app_name": _fn("text", "regex"),
            "main_activity": _fn("regex"),
            "activity": _fn("text", "regex"),
            "service": _fn("text", "regex"),
            "receiver": _fn("text", "regex"),
            "permission": _fn("regex"),
            "permissions_number": INT,
            "url": _fn("text", "regex"),
            "certificate": Record(
                {"sha1": _fn("text"), "subject": _fn("regex"), "issuer": _fn("regex")}
            ),
            "min_sdk": INT,
            "max_sdk": INT,
            "target_sdk": INT,
        }
    )

    @staticmethod
    def module(raw: bytes | None = None) -> Module:
        """The module; with a report `raw`, every file answers from it (read once, here)."""
        if raw is None:
            return Module(
                Androguard.SCHEMA, lambda file: Androguard.values(Apk.facts(file) or ApkFacts())
            )
        values = Androguard.values(Androguard.report(raw))
        return Module(Androguard.SCHEMA, lambda file: values)

    @staticmethod
    def report(raw: bytes) -> ApkFacts:
        """A Koodous report's facts; ValueError where it is not a JSON object."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"the androguard report is not JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("the androguard report is not a JSON object")

        def text(value: Any) -> bytes | None:
            return (
                value.encode("utf-8", "surrogatepass").split(b"\x00", 1)[0]
                if isinstance(value, str)
                else None
            )

        def texts(key: str) -> list[bytes]:
            items = data.get(key)
            return [t for t in map(text, items) if t is not None] if isinstance(items, list) else []

        def level(key: str) -> int:
            value = data.get(key)
            return Apk.atoi(value.encode()) if isinstance(value, str) else 0

        given = data.get("certificate")
        cert: dict[str, Any] = given if isinstance(given, dict) else {}
        return ApkFacts(
            package_name=text(data.get("package_name")), app_name=text(data.get("app_name")),
            main_activity=text(data.get("main_activity")), activities=texts("activities"),
            services=texts("services"), receivers=texts("receivers"), permissions=texts("permissions"),
            new_permissions=texts("new_permissions"), urls=texts("urls"),
            min_sdk=level("min_sdk_version"), max_sdk=level("max_sdk_version"),
            target_sdk=level("target_sdk_version"), sha1=text(cert.get("sha1")),
            subject=text(cert.get("subjectDN")), issuer=text(cert.get("IssuerDN")),
        )  # fmt: skip

    @staticmethod
    def same(wanted: bytes, value: bytes | None) -> bool:
        """`strcasecmp(wanted, value) == 0`: ASCII case folded, each up to its first NUL."""
        return value is not None and wanted.split(b"\x00", 1)[0].lower() == value.lower()

    @staticmethod
    def found(pattern: Any, value: bytes | None) -> bool:
        return value is not None and pattern.run(value) > 0

    @staticmethod
    def values(f: ApkFacts) -> dict[str, Any]:
        same, found = Androguard.same, Androguard.found

        def one(value: bytes | None) -> tuple[Callable[[Any], int], Callable[[Any], int]]:
            return (lambda s: int(same(s, value)), lambda r: int(found(r, value)))

        def many(values: Iterable[bytes]) -> tuple[Callable[[Any], int], Callable[[Any], int]]:
            items = list(values)
            return (
                lambda s: int(any(same(s, v) for v in items)),
                lambda r: int(any(found(r, v) for v in items)),
            )

        return {
            "package_name": one(f.package_name),
            "app_name": one(f.app_name),
            "main_activity": (one(f.main_activity)[1],),
            "activity": many(f.activities),
            "service": many(f.services),
            "receiver": many(f.receivers),
            "permission": (lambda r: int(any(found(r, v) for v in f.permissions) or any(found(r, v) for v in f.new_permissions)),),
            "permissions_number": len(f.permissions),
            "url": many(f.urls),
            "certificate": {
                "sha1": (one(f.sha1)[0],),
                "subject": (one(f.subject)[1],),
                "issuer": (one(f.issuer)[1],),
            },
            "min_sdk": f.min_sdk,
            "max_sdk": f.max_sdk,
            "target_sdk": f.target_sdk,
        }  # fmt: skip


__all__ = ["Androguard"]
