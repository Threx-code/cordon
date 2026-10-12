"""The model server: a bundle is served only when it verifies, a request only when it is
authorised and well-formed. Built on a tiny model trained here on synthetic features."""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import lightgbm as lgb
import numpy as np
import pytest
from cordon_model_server.bundle import SCHEMA, Bundle, BundleError
from cordon_model_server.http import HttpServer, Service
from cordon_model_server.scoring import RequestError, Scorer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cordon_scanner.model.features import FILE_DENSE, PACKAGE_DENSE, TOKEN_DIM

TOKEN = "t" * 40


class Fixture:
    @staticmethod
    def bundle(
        root: Path, *, layout: list[str] | None = None
    ) -> tuple[Path, bytes, Ed25519PrivateKey]:
        rng = np.random.default_rng(0)
        x = rng.random((400, len(PACKAGE_DENSE) + 3)).astype(np.float32)
        y = (x[:, 0] > 0.5).astype(int)
        lgb.train(
            {"objective": "binary", "verbose": -1, "num_leaves": 4}, lgb.Dataset(x, y), 10
        ).save_model(str(root / "package.txt"))
        xf = rng.random((400, len(FILE_DENSE))).astype(np.float32)
        lgb.train(
            {"objective": "binary", "verbose": -1, "num_leaves": 4},
            lgb.Dataset(xf, (xf[:, 0] > 0.5).astype(int)),
            10,
        ).save_model(str(root / "file.txt"))
        manifest = {
            "schema": SCHEMA,
            "name": "cordon-test",
            "version": "0.0.1",
            "features": {
                "package_dense": layout or list(PACKAGE_DENSE),
                "file_dense": list(FILE_DENSE),
                "token_dim": TOKEN_DIM,
            },
            "columns": [
                *range(len(PACKAGE_DENSE)),
                len(PACKAGE_DENSE) + 5,
                len(PACKAGE_DENSE) + 9,
                len(PACKAGE_DENSE) + 100,
            ],
            "thresholds": {"package": 0.5, "file": 0.5},
            "files": {
                n: hashlib.sha256((root / n).read_bytes()).hexdigest()
                for n in ("package.txt", "file.txt")
            },
        }
        raw = json.dumps(manifest).encode()
        (root / "manifest.json").write_bytes(raw)
        key = Ed25519PrivateKey.generate()
        (root / "manifest.sig").write_bytes(key.sign(raw))
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return root, public, key

    @staticmethod
    def request(**overrides: Any) -> dict[str, Any]:
        package = {
            "ref": "p1",
            "dense": [0.9] + [0.1] * (len(PACKAGE_DENSE) - 1),
            "tokens": [5, 9],
            "files": [[0.9] + [0.1] * (len(FILE_DENSE) - 1)],
        }
        package.update(overrides)
        return {"schema": "cordon.model/v1", "packages": [package]}


class TestBundles:
    def test_a_verified_bundle_loads(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        assert Bundle.load(root, public).version == "0.0.1"

    def test_another_key_is_refused(self, tmp_path: Path) -> None:
        root, _, _ = Fixture.bundle(tmp_path)
        other = (
            Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        with pytest.raises(BundleError, match="does not verify"):
            Bundle.load(root, other)

    def test_a_changed_model_file_is_refused(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        (root / "package.txt").write_text((root / "package.txt").read_text() + "\n")
        with pytest.raises(BundleError, match="digest"):
            Bundle.load(root, public)

    def test_a_changed_manifest_is_refused(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["thresholds"]["package"] = 0.99
        (root / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(BundleError, match="does not verify"):
            Bundle.load(root, public)

    def test_another_feature_layout_is_refused(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path, layout=["something", "else"])
        with pytest.raises(BundleError, match="feature layout"):
            Bundle.load(root, public)


class TestRequests:
    @pytest.mark.parametrize(
        "bad",
        [
            {"dense": [1.0] * 3},
            {"dense": [float("nan")] * len(PACKAGE_DENSE)},
            {"dense": [True] * len(PACKAGE_DENSE)},
            {"tokens": [TOKEN_DIM]},
            {"tokens": [-1]},
            {"files": [[0.1] * 3]},
            {"files": [[0.1] * len(FILE_DENSE)] * 97},
            {"ref": ""},
            {"ref": "x" * 201},
        ],
    )
    def test_malformed_packages_are_refused(self, bad: dict[str, Any]) -> None:
        with pytest.raises(RequestError):
            Scorer.parse(Fixture.request(**bad))

    def test_the_schema_is_required(self) -> None:
        with pytest.raises(RequestError):
            Scorer.parse({"packages": []})

    def test_too_many_packages_are_refused(self) -> None:
        body = Fixture.request()
        body["packages"] = body["packages"] * 101
        with pytest.raises(RequestError):
            Scorer.parse(body)


class Running:
    def __init__(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        service = Service(
            Scorer(Bundle.load(root, public)),
            frozenset({hashlib.sha256(TOKEN.encode()).hexdigest()}),
            2,
        )
        self.server = HttpServer.build(
            service, "127.0.0.1", 0, tls_cert=None, tls_key=None, behind_tls_proxy=False
        )
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def call(
        self,
        path: str,
        body: Any = None,
        token: str | None = TOKEN,
        content_type: str = "application/json",
    ) -> tuple[int, Any]:
        data = (
            None
            if body is None
            else (body if isinstance(body, bytes) else json.dumps(body).encode())
        )
        headers = {"Content-Type": content_type}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.url + path,
            data=data,
            headers=headers,
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class TestHttp:
    def test_scoring_end_to_end(self, tmp_path: Path) -> None:
        running = Running(tmp_path)
        try:
            status, body = running.call("/v1/model/score", Fixture.request())
            assert status == 200
            (result,) = body["results"]
            assert result["ref"] == "p1" and result["verdict"] in {"malicious", "benign"}
            assert 0.0 <= result["package_score"] <= 1.0 and result["file_score"] is not None
        finally:
            running.close()

    def test_no_token_and_a_wrong_token_are_refused(self, tmp_path: Path) -> None:
        running = Running(tmp_path)
        try:
            assert running.call("/v1/model/score", Fixture.request(), token=None)[0] == 401
            assert running.call("/v1/model/score", Fixture.request(), token="w" * 40)[0] == 401
            assert running.call("/v1/model", token=None)[0] == 401
        finally:
            running.close()

    def test_health_says_nothing_but_ok(self, tmp_path: Path) -> None:
        running = Running(tmp_path)
        try:
            assert running.call("/healthz", token=None) == (200, {"status": "ok"})
        finally:
            running.close()

    def test_wrong_content_type_and_bad_json_are_refused(self, tmp_path: Path) -> None:
        running = Running(tmp_path)
        try:
            assert (
                running.call("/v1/model/score", Fixture.request(), content_type="text/plain")[0]
                == 415
            )
            assert running.call("/v1/model/score", b"{not json")[0] == 400
            assert running.call("/v1/model/score", b"[" * 100000 + b"]" * 100000)[0] == 400
        finally:
            running.close()

    def test_plain_http_is_refused_beyond_loopback(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        service = Service(Scorer(Bundle.load(root, public)), frozenset({"0" * 64}), 1)
        with pytest.raises(ValueError, match="plain HTTP"):
            HttpServer.build(
                service, "0.0.0.0", 0, tls_cert=None, tls_key=None, behind_tls_proxy=False
            )

    def test_a_server_with_no_tokens_will_not_start(self, tmp_path: Path) -> None:
        root, public, _ = Fixture.bundle(tmp_path)
        service = Service(Scorer(Bundle.load(root, public)), frozenset(), 1)
        with pytest.raises(ValueError, match="no token"):
            HttpServer.build(
                service, "127.0.0.1", 0, tls_cert=None, tls_key=None, behind_tls_proxy=False
            )


class Tls:
    @staticmethod
    def certificate(directory: Path) -> tuple[str, str]:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_path, key_path = directory / "tls.crt", directory / "tls.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return str(cert_path), str(key_path)


class TestTls:
    def test_a_stalled_handshake_does_not_block_other_clients(self, tmp_path: Path) -> None:
        import socket
        import ssl
        import time

        root, public, _ = Fixture.bundle(tmp_path)
        cert, key = Tls.certificate(tmp_path)
        service = Service(
            Scorer(Bundle.load(root, public)),
            frozenset({hashlib.sha256(TOKEN.encode()).hexdigest()}),
            2,
        )
        server = HttpServer.build(
            service, "127.0.0.1", 0, tls_cert=cert, tls_key=key, behind_tls_proxy=False
        )
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stalled = socket.create_connection(("127.0.0.1", port))  # connects, never handshakes
        try:
            context = ssl.create_default_context(cafile=cert)
            context.check_hostname = False
            start = time.monotonic()
            with urllib.request.urlopen(
                f"https://127.0.0.1:{port}/healthz", timeout=10, context=context
            ) as r:
                assert r.status == 200
            assert time.monotonic() - start < 5
        finally:
            stalled.close()
            server.shutdown()
            server.server_close()
