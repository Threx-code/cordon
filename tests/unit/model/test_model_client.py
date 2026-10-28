"""`scan --model` (`model/client.py`, `ScanEnrichment.add_model_findings`), against a stub model server that
records what it was sent: features only, never a path or a line of source; a model that cannot be
asked makes the scan incomplete; HTTPS beyond loopback; the token from the environment."""

from __future__ import annotations

import io
import json
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.model.client import ModelClient, ModelError, ModelTargets, PackageUnit

SECRET_MARKER = "do-not-send-this-source-7f3a"


class Stub:
    """A model server answering every package `verdict`, recording the bodies it got."""

    class Handler(BaseHTTPRequestHandler):
        verdict: ClassVar[str] = "malicious"
        bodies: ClassVar[list[dict[str, Any]]] = []
        status: ClassVar[int] = 200

        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            type(self).bodies.append({"auth": self.headers.get("Authorization"), "body": body})
            reply = {
                "schema": "cordon.model/v1",
                "results": [
                    {
                        "ref": p["ref"],
                        "verdict": type(self).verdict,
                        "package_score": 0.97,
                        "file_score": 0.91,
                        "reasons": ["package", "file"],
                    }
                    for p in body["packages"]
                ],
            }
            data = json.dumps(reply).encode()
            self.send_response(type(self).status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def __init__(self, verdict: str = "malicious", status: int = 200) -> None:
        handler = type("H", (Stub.Handler,), {"verdict": verdict, "bodies": [], "status": status})
        self.handler = handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class Package:
    @staticmethod
    def tarball(path: Path) -> Path:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, body in {
                "package/package.json": json.dumps(
                    {"name": "x", "scripts": {"postinstall": "node i.js"}}
                ).encode(),
                "package/i.js": f"// {SECRET_MARKER}\nrequire('child_process').exec('id')\n".encode(),
            }.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        path.write_bytes(buffer.getvalue())
        return path


class TestScanWithModel:
    def _scan(
        self,
        target: Path,
        url: str,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        *extra: str,
    ) -> tuple[int, dict[str, Any]]:
        monkeypatch.setenv("CORDON_MODEL_TOKEN", "t" * 40)
        monkeypatch.delenv("CORDON_OFFLINE", raising=False)
        code = CommandLine.run(
            ["scan", str(target), "--model", url, "--format", "json", "--no-cache", *extra]
        )
        out = capsys.readouterr().out
        return code, json.loads(out[out.index("{") :])

    def test_a_malicious_verdict_is_a_finding_and_no_source_is_sent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub = Stub("malicious")
        try:
            code, report = self._scan(
                Package.tarball(tmp_path / "x-1.0.0.tgz"), stub.url, monkeypatch, capsys
            )
        finally:
            stub.close()
        assert any(
            f["rule_id"] == "SUSPECT.MODEL.MALICIOUS_PACKAGE.001" for f in report["findings"]
        )
        (sent,) = stub.handler.bodies
        assert sent["auth"] == "Bearer " + "t" * 40
        package = sent["body"]["packages"][0]
        assert set(package) == {"ref", "dense", "tokens", "files"}
        assert SECRET_MARKER not in json.dumps(sent) and "i.js" not in json.dumps(sent)
        assert code == 1

    def test_a_benign_verdict_adds_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub = Stub("benign")
        try:
            _, report = self._scan(
                Package.tarball(tmp_path / "x-1.0.0.tgz"), stub.url, monkeypatch, capsys
            )
        finally:
            stub.close()
        assert not any(
            f["rule_id"].startswith(("SUSPECT.MODEL", "OPERATIONAL.MODEL"))
            for f in report["findings"]
        )

    def test_an_unreachable_model_makes_the_scan_incomplete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub = Stub("benign", status=401)
        try:
            _, report = self._scan(
                Package.tarball(tmp_path / "x-1.0.0.tgz"), stub.url, monkeypatch, capsys
            )
        finally:
            stub.close()
        assert report["complete"] is False
        assert any(f["rule_id"] == "OPERATIONAL.MODEL.UNAVAILABLE" for f in report["findings"])

    def test_offline_refuses_model(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("CORDON_MODEL_TOKEN", "t" * 40)
        code = CommandLine.run(
            [
                "scan",
                str(Package.tarball(tmp_path / "x.tgz")),
                "--model",
                "https://m.example.invalid",
                "--offline",
            ]
        )
        assert code == 3


class TestClient:
    def test_plain_http_beyond_loopback_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORDON_MODEL_TOKEN", "t" * 40)
        with pytest.raises(ModelError, match="HTTPS"):
            ModelClient.for_target("http://models.example.invalid")

    def test_the_token_comes_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CORDON_MODEL_TOKEN", raising=False)
        with pytest.raises(ModelError, match="CORDON_MODEL_TOKEN"):
            ModelClient.for_target("https://models.example.invalid")

    def test_a_reply_missing_a_package_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Partial(ModelClient):
            def _post(self, body: dict[str, Any]) -> dict[str, Any]:
                return {"schema": "cordon.model/v1", "results": []}

        with pytest.raises(ModelError, match="every package"):
            Partial("https://x.example.invalid/v1/model/score", "t").score(
                [PackageUnit("a", [("a.js", b"x")])]
            )

    def test_requests_are_cut_by_size_as_well_as_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A package heavy with identifiers must not push one request past what a server accepts."""
        import cordon_scanner.model.client as client

        monkeypatch.setattr(client, "MAX_REQUEST", 4000)
        units = [PackageUnit(str(i), [("a.js", b"x")]) for i in range(30)]
        groups = ModelClient.batches(units)
        assert len(groups) > 1
        assert [i for group in groups for i, _ in group] == list(range(30))
        assert all(len(group) <= client.BATCH for group in groups)
        assert all(
            len(group) == 1 or sum(len(json.dumps(e)) for _, e in group) <= 4000 for group in groups
        )

    def test_one_package_larger_than_the_cap_is_still_sent_alone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import cordon_scanner.model.client as client

        monkeypatch.setattr(client, "MAX_REQUEST", 10)
        groups = ModelClient.batches([PackageUnit(str(i), [("a.js", b"x")]) for i in range(3)])
        assert [len(g) for g in groups] == [1, 1, 1]


class TestTargets:
    def test_installed_packages_and_archives_not_first_party_source(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.js").write_text("x", encoding="utf-8")
        for name in ("node_modules/left-pad", "node_modules/@scope/lib"):
            (tmp_path / name).mkdir(parents=True)
            (tmp_path / name / "package.json").write_text("{}", encoding="utf-8")
        (tmp_path / "venv/lib/python3.12/site-packages/requests").mkdir(parents=True)
        (tmp_path / "venv/lib/python3.12/site-packages/requests/__init__.py").write_text(
            "", encoding="utf-8"
        )
        Package.tarball(tmp_path / "vendor-1.0.tgz")
        units, capped = ModelTargets.collect(tmp_path)
        assert sorted(u.location for u in units) == [
            "node_modules/@scope/lib",
            "node_modules/left-pad",
            "vendor-1.0.tgz",
            "venv/lib/python3.12/site-packages/requests",
        ]
        assert capped is False


class TestUnpackedPackage:
    """A directory that is one unpacked package is scored as one; a repository is not."""

    def test_an_npm_tarball_unpacked_to_package_is_found(self, tmp_path: Path) -> None:
        root = tmp_path / "pkg" / "package"
        root.mkdir(parents=True)
        (root / "package.json").write_text('{"name": "x"}', encoding="utf-8")
        (root / "index.js").write_text("module.exports = 1;", encoding="utf-8")
        (tmp_path / "pkg" / "package_info.json").write_text("{}", encoding="utf-8")
        units, _ = ModelTargets.collect(tmp_path / "pkg")
        assert [u.location for u in units] == ["package"]

    def test_a_package_at_the_top_is_found(self, tmp_path: Path) -> None:
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\nsetup()", encoding="utf-8"
        )
        units, _ = ModelTargets.collect(tmp_path)
        assert [u.location for u in units] == ["."]

    def test_a_git_checkout_is_a_repository_not_a_package(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
        assert ModelTargets.collect(tmp_path)[0] == []

    def test_an_archive_wrapping_the_package_further_is_followed(self, tmp_path: Path) -> None:
        root = tmp_path / "tmp" / "tmpab12" / "name" / "package"
        root.mkdir(parents=True)
        (root / "package.json").write_text("{}", encoding="utf-8")
        assert [u.location for u in ModelTargets.collect(tmp_path)[0]] == [
            "tmp/tmpab12/name/package"
        ]

    def test_a_directory_of_several_projects_is_not_one_package(self, tmp_path: Path) -> None:
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
            (tmp_path / name / "package.json").write_text("{}", encoding="utf-8")
        assert ModelTargets.collect(tmp_path)[0] == []
