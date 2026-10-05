"""G7: the Socket and Snyk adapters in bench/commercial.py, with fake transports.

What matters is that every input gets an answer or is recorded as unanswered, that a missing key
is reported rather than dropped, and that the reading of each tool's output is the stated one.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


class BenchKit:
    @staticmethod
    def module():
        spec = importlib.util.spec_from_file_location(
            "bench_commercial", ROOT / "bench/commercial.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Registered first: dataclasses resolve their own module through sys.modules.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def ndjson(*items: dict) -> bytes:
        return "\n".join(json.dumps(i) for i in items).encode()


class TestSocket:
    def test_a_malware_alert_blocks_and_a_quiet_package_passes(self) -> None:
        m = BenchKit.module()
        sent: list[dict] = []

        def post(url, body, headers):
            sent.append({"url": url, "body": json.loads(body), "auth": headers["Authorization"]})
            return BenchKit.ndjson(
                {
                    "purl": "pkg:npm/evil@1.0.0",
                    "alerts": [{"type": "malware", "severity": "critical"}],
                },
                {
                    "purl": "pkg:npm/fine@2.0.0",
                    "alerts": [{"type": "unmaintained", "severity": "low"}],
                },
                {"_type": "summary"},
            )

        verdicts = m.SocketApi("key", post).verdicts(
            [("s1", "pkg:npm/evil@1.0.0"), ("s2", "pkg:npm/fine@2.0.0")]
        )
        assert [(v.sample, v.blocked) for v in verdicts] == [("s1", True), ("s2", False)]
        assert sent[0]["url"].startswith("https://api.socket.dev/")
        assert sent[0]["auth"].startswith("Basic ")
        assert [c["purl"] for c in sent[0]["body"]["components"]] == [
            "pkg:npm/evil@1.0.0",
            "pkg:npm/fine@2.0.0",
        ]

    def test_a_release_socket_does_not_answer_for_is_no_answer_not_clean(self) -> None:
        m = BenchKit.module()
        verdicts = m.SocketApi("key", lambda *a: b"").verdicts([("s", "pkg:pypi/gone@0.1")])
        assert verdicts[0].blocked is None and "no answer" in verdicts[0].detail

    def test_a_failed_request_marks_the_whole_batch_unanswered(self) -> None:
        m = BenchKit.module()

        def post(*args):
            raise OSError("unreachable")

        verdicts = m.SocketApi("key", post).verdicts([("a", "pkg:npm/a@1"), ("b", "pkg:npm/b@1")])
        assert [v.blocked for v in verdicts] == [None, None]

    def test_requests_are_batched(self) -> None:
        m = BenchKit.module()
        calls: list[int] = []

        def post(url, body, headers):
            calls.append(len(json.loads(body)["components"]))
            return b""

        m.SocketApi("key", post).verdicts([(f"s{i}", f"pkg:npm/p{i}@1") for i in range(250)])
        assert calls == [100, 100, 50]

    def test_a_package_answered_by_parts_is_matched(self) -> None:
        m = BenchKit.module()
        body = BenchKit.ndjson(
            {"type": "npm", "namespace": "@scope", "name": "x", "version": "1.0.0", "alerts": []}
        )
        assert m.SocketApi.parse(body) == {"pkg:npm/@scope/x@1.0.0": []}

    def test_a_critical_alert_of_any_type_blocks(self) -> None:
        m = BenchKit.module()
        body = BenchKit.ndjson(
            {"purl": "pkg:npm/x@1", "alerts": [{"type": "networkAccess", "severity": "critical"}]}
        )
        (verdict,) = m.SocketApi("k", lambda *a: body).verdicts([("x", "pkg:npm/x@1")])
        assert verdict.blocked


class TestSnyk:
    def test_vulnerabilities_are_read_with_every_identifier(self) -> None:
        m = BenchKit.module()
        out = json.dumps(
            [
                {
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JS-QS-1",
                            "version": "6.7.0",
                            "identifiers": {"CVE": ["CVE-2022-24999"], "CWE": []},
                        }
                    ]
                },
                {"vulnerabilities": []},
            ]
        )
        assert m.SnykCli.parse("noise before\n" + out) == [
            ("6.7.0", frozenset({"SNYK-JS-QS-1", "CVE-2022-24999"}))
        ]

    def test_a_single_project_document_is_read(self) -> None:
        m = BenchKit.module()
        out = json.dumps(
            {"vulnerabilities": [{"id": "SNYK-PY-X-1", "version": "1.0", "identifiers": {}}]}
        )
        assert m.SnykCli.parse(out) == [("1.0", frozenset({"SNYK-PY-X-1"}))]

    def test_an_error_exit_is_an_error_not_zero_findings(self) -> None:
        m = BenchKit.module()
        with pytest.raises(RuntimeError):
            m.SnykCli(lambda cmd: (2, "auth failed", 0.1)).vulnerabilities("/x")

    def test_output_without_json_is_an_error(self) -> None:
        m = BenchKit.module()
        with pytest.raises(ValueError):
            m.SnykCli.parse("Authentication failed")


class TestAvailability:
    def test_missing_keys_are_reported_with_the_reason(self) -> None:
        m = BenchKit.module()
        status = m.Commercial.availability({})
        assert "SOCKET_SECURITY_API_KEY" in status["socket"] and "SNYK_TOKEN" in status["snyk"]

    def test_present_keys_mean_the_tool_runs(self) -> None:
        m = BenchKit.module()
        assert m.Commercial.availability({"SOCKET_SECURITY_API_KEY": "x", "SNYK_TOKEN": "y"}) == {
            "socket": None,
            "snyk": None,
        }
