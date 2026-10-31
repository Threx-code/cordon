"""cordon-rule's `cuckoo` module: what a sandbox run did, read from the run's report given to the scan.

A Cuckoo report (the JSON the sandbox writes) is given once for a scan, as the reference takes it
(`yara -x cuckoo=report.json`); every file of the scan is matched against the same run. Each
function says whether some recorded item matches its regular expression (anywhere in the item,
an empty match included): 1 or 0. Without a report every function answers 0, as the reference's
do.

    network.dns_lookup(re)      a looked-up domain: `network.domains[].domain` (an entry with an
                                `ip`), or, in older reports with no `domains`, `network.dns[].hostname`
    network.http_get(re)        the URI of an HTTP request whose method is GET (any case)
    network.http_post(re)       ... POST
    network.http_request(re)    ... GET or POST
    network.http_user_agent(re) an HTTP request's `user-agent`
    network.host(re)            an entry of `network.hosts`
    network.tcp(re, port)       a `network.tcp[]` connection to `dst` matching, on `dport` == port
    network.udp(re, port)       ... `network.udp[]`
    registry.key_access(re)     an entry of `behavior.summary.keys`
    filesystem.file_access(re)  ... `behavior.summary.files`
    sync.mutex(re)              ... `behavior.summary.mutexes`

Matched as the reference reads a report: a text item is read up to its first NUL, a port must be a
JSON integer, and a report that is not a JSON object or array -- or holds an integer outside 64
bits, a constant like NaN, or a lone surrogate -- is refused whole (`CuckooReport.read`).

Where the reference fails, this answers: an item of `hosts`, `keys`, `files` or `mutexes` that is
not text (a number, null, an object) crashes the reference; here it is skipped. That is the one
deliberate difference, and a test names it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any, ClassVar

from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Sig

INT = Scalar.INT
INT64 = range(-(1 << 63), 1 << 63)


class CuckooReport:
    """A report read as the reference reads one; `None` stands for no report."""

    @staticmethod
    def read(raw: bytes) -> Any:
        """The report's JSON, or ValueError where the reference refuses it."""

        def whole(text: str) -> int:
            value = int(text)
            if value not in INT64:
                raise ValueError(f"the cuckoo report has an integer outside 64 bits: {text}")
            return value

        def constant(name: str) -> Any:
            raise ValueError(f"the cuckoo report has {name}, which JSON does not allow")

        try:
            report = json.loads(raw, parse_int=whole, parse_constant=constant)
            # a lone surrogate (`"\\ud800"`) is not text the reference's reader accepts
            json.dumps(report, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("the cuckoo report has a lone surrogate") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"the cuckoo report is not JSON: {exc.msg}") from exc
        if not isinstance(report, (dict, list)):
            raise ValueError("the cuckoo report is not a JSON object")
        return report

    @staticmethod
    def field(node: Any, name: str) -> Any:
        return node.get(name) if isinstance(node, dict) else None

    @staticmethod
    def items(node: Any) -> list[Any]:
        return node if isinstance(node, list) else []

    @staticmethod
    def text(value: Any) -> bytes | None:
        """A JSON string as the reference reads it: its UTF-8 up to the first NUL."""
        if not isinstance(value, str):
            return None
        return value.encode("utf-8").split(b"\x00", 1)[0]

    @staticmethod
    def texts(node: Any) -> list[bytes]:
        """The text items of an array; any other item is skipped (the reference crashes)."""
        return [t for t in map(CuckooReport.text, CuckooReport.items(node)) if t is not None]


class Cuckoo:
    """The module: its declaration, and its values for one report (`values`)."""

    @staticmethod
    def _fn(*params: str) -> Call:
        return Call(Sig(params, INT))

    SCHEMA: ClassVar[Record] = Record(
        {
            "network": Record(
                {
                    "dns_lookup": _fn("regex"),
                    "http_get": _fn("regex"),
                    "http_post": _fn("regex"),
                    "http_request": _fn("regex"),
                    "http_user_agent": _fn("regex"),
                    "host": _fn("regex"),
                    "tcp": _fn("regex", "int"),
                    "udp": _fn("regex", "int"),
                }
            ),
            "registry": Record({"key_access": _fn("regex")}),
            "filesystem": Record({"file_access": _fn("regex")}),
            "sync": Record({"mutex": _fn("regex")}),
        }
    )

    @staticmethod
    def module(raw: bytes | None = None) -> Module:
        """The module for a scan given the report `raw` (None: no report). The report is read
        once, here; a report the reference refuses raises ValueError."""
        values = Cuckoo.values(None if raw is None else CuckooReport.read(raw))
        return Module(Cuckoo.SCHEMA, lambda file: values)

    @staticmethod
    def _any(pattern: Any, texts: Iterable[bytes]) -> int:
        return int(any(pattern.run(t) != -1 for t in texts))

    @staticmethod
    def values(report: Any) -> dict[str, Any]:
        r = CuckooReport
        net = r.field(report, "network")
        summary = r.field(r.field(report, "behavior"), "summary")
        dns = Cuckoo._lookups(net)
        http = [
            (r.text(e.get("uri")), (r.text(e.get("method")) or b"").lower())
            for e in r.items(r.field(net, "http"))
            if isinstance(e, dict) and isinstance(e.get("uri"), str)
            and isinstance(e.get("method"), str)
        ]  # fmt: skip
        agents = [
            t for e in r.items(r.field(net, "http")) if (t := r.text(r.field(e, "user-agent")))
            is not None
        ]  # fmt: skip

        def requests(*methods: bytes) -> Callable[[Any], int]:
            return lambda p: Cuckoo._any(p, (u for u, m in http if u is not None and m in methods))

        def connections(kind: str) -> Callable[[Any, int], int]:
            pairs = Cuckoo._connections(r.field(net, kind))
            return lambda p, port: Cuckoo._any(p, (d for d, dport in pairs if dport == port))

        def listed(name: str) -> Callable[[Any], int]:
            texts = r.texts(r.field(summary, name))
            return lambda p: Cuckoo._any(p, texts)

        return {
            "network": {
                "dns_lookup": (lambda p: Cuckoo._any(p, dns),),
                "http_get": (requests(b"get"),),
                "http_post": (requests(b"post"),),
                "http_request": (requests(b"get", b"post"),),
                "http_user_agent": (lambda p: Cuckoo._any(p, agents),),
                "host": ((lambda texts: lambda p: Cuckoo._any(p, texts))(r.texts(r.field(net, "hosts"))),),
                "tcp": (connections("tcp"),),
                "udp": (connections("udp"),),
            },
            "registry": {"key_access": (listed("keys"),)},
            "filesystem": {"file_access": (listed("files"),)},
            "sync": {"mutex": (listed("mutexes"),)},
        }  # fmt: skip

    @staticmethod
    def _lookups(net: Any) -> list[bytes]:
        """The looked-up names: `domains[].domain`, or, where a report has no `domains` at all,
        the older `dns[].hostname`; an entry counts only with an `ip` and a name, both text."""
        r = CuckooReport
        name, entries = "domain", r.field(net, "domains")
        if not (isinstance(net, dict) and "domains" in net):
            name, entries = "hostname", r.field(net, "dns")
        return [
            t
            for e in r.items(entries)
            if isinstance(e, dict) and isinstance(e.get("ip"), str)
            and (t := r.text(e.get(name))) is not None
        ]  # fmt: skip

    @staticmethod
    def _connections(node: Any) -> list[tuple[bytes, int]]:
        """(dst, dport) of each connection with a text `dst` and an integer `dport`."""
        r = CuckooReport
        return [
            (dst, e["dport"])
            for e in r.items(node)
            if isinstance(e, dict) and type(e.get("dport")) is int
            and (dst := r.text(e.get("dst"))) is not None
        ]  # fmt: skip


__all__ = ["Cuckoo", "CuckooReport"]
