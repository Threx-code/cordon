"""The Cordon Cloud client: sign-in (K7), signed upload (K2), policy bundle (K3).

Run against an in-process fake that implements the documented endpoints, so what is tested is
the client's side of each contract -- including every way the cloud, or something pretending to
be it, can answer wrongly.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.cloud import CloudEndpoint, CloudError, auth, policy, results
from feedkit import FeedKit
from support import Support

API = "https://api.cordon.test"
NOW = 1_800_000_000.0
ORG_KEY = FeedKit.new_key("org-policy")
OTHER_KEY = FeedKit.new_key("someone-else")


class FakeCloud:
    """The K7/K2/K3 endpoints, in memory. Records every request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self.pending_polls = 1
        self.device_error: str | None = None
        self.bundle: dict[str, Any] | None = None
        self.scans: list[dict[str, Any]] = []
        self.token_response = {
            "access_token": "at-1",
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": "rt-1",
            "org": "acme",
            "subject": "dev@acme.test",
            "policy_keys": {ORG_KEY.keyid: ORG_KEY.public["public"]},
        }

    def __call__(
        self, method: str, url: str, *, body: bytes | None, headers: dict[str, str]
    ) -> tuple[int, bytes]:
        self.requests.append((method, url, headers, body))
        path = url.removeprefix(API)
        form = dict(pair.split("=", 1) for pair in (body or b"").decode().split("&") if "=" in pair)
        if path == "/v1/auth/device/code":
            return 200, json.dumps(
                {
                    "device_code": "dc",
                    "user_code": "WDJB-MJHT",
                    "verification_uri": "https://cordon.test/device",
                    "expires_in": 600,
                    "interval": 1,
                }
            ).encode()
        if path == "/v1/auth/token":
            grant = form.get("grant_type", "")
            if grant.endswith("device_code"):
                if self.device_error:
                    return 400, json.dumps({"error": self.device_error}).encode()
                if self.pending_polls:
                    self.pending_polls -= 1
                    return 400, json.dumps({"error": "authorization_pending"}).encode()
            if grant.endswith("token-exchange") and form.get("subject_token") != "ci-jwt":
                return 400, json.dumps(
                    {"error": "invalid_grant", "error_description": "no trust rule"}
                ).encode()
            return 200, json.dumps(self.token_response).encode()
        if path == "/v1/auth/revoke":
            return 200, b"{}"
        if path == "/v1/scans":
            self.scans.append(json.loads(body or b"{}"))
            return 201, json.dumps(
                {"scan_id": "scn_1", "url": "https://cordon.test/scans/scn_1"}
            ).encode()
        if path == "/v1/policy/bundle":
            if self.bundle is None:
                return 404, json.dumps({"error": "not_found"}).encode()
            return 200, json.dumps(self.bundle).encode()
        return 404, b"{}"


class CloudHelpers:
    """Helpers for test_cloud.py."""

    @staticmethod
    def bundle(
        *,
        version: int = 3,
        org: str = "acme",
        expires: float = NOW + 86400,
        key=ORG_KEY,
        **extra: Any,
    ) -> dict[str, Any]:
        body = {
            "type": policy.BUNDLE_TYPE,
            "org": org,
            "version": version,
            "issued_at": NOW - 60,
            "expires_at": expires,
            "policy": "version: 1\nname: acme\nfail_on:\n  severity: medium\n",
            "suppressions": [
                {
                    "rule": "SUSPECT.BINARY.PACKED.001",
                    "path": "vendor/tool.bin",
                    "justification": "Vendor's signed release, reviewed by security in ticket SEC-114.",
                    "expires": (date.today() + timedelta(days=30)).isoformat(),
                    "approved_by": "security@acme.test",
                }
            ],
            **extra,
        }
        payload = json.dumps(body, sort_keys=True).encode()
        return {
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": key.keyid, "sig": FeedKit.sign(key.seed, payload).hex()}],
        }

    @staticmethod
    def signed_in(cloud: FakeCloud) -> auth.Credentials:
        credentials = auth.CloudAuth._credentials_from(API, cloud.token_response, NOW)
        auth.CloudAuth.save(credentials)
        return credentials


class CloudFixtures:
    """Fixtures for the tests in test_cloud.py; every test class here inherits them."""

    @pytest.fixture(autouse=True)
    def isolated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CORDON_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
        for name in (
            "CORDON_ID_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "CORDON_CLOUD_URL",
        ):
            monkeypatch.delenv(name, raising=False)

    @pytest.fixture
    def cloud(self, monkeypatch) -> FakeCloud:
        fake = FakeCloud()
        monkeypatch.setattr("cordon_scanner.cloud.transport.CloudTransport._urllib", fake)
        return fake


class TestBaseUrl(CloudFixtures):
    def test_https_is_required_except_on_loopback(self) -> None:
        assert CloudEndpoint.base_url("https://api.cordon.test/") == "https://api.cordon.test"
        assert CloudEndpoint.base_url("http://localhost:8000") == "http://localhost:8000"
        with pytest.raises(CloudError):
            CloudEndpoint.base_url("http://api.cordon.test")
        with pytest.raises(CloudError):
            CloudEndpoint.base_url("https://user:pw@api.cordon.test")


class TestDeviceFlow(CloudFixtures):
    def test_pending_then_approved(self, cloud) -> None:
        code = auth.CloudAuth.start_device_flow(API)
        assert code.user_code == "WDJB-MJHT"
        slept: list[float] = []
        credentials = auth.CloudAuth.finish_device_flow(
            code, API, sleep=slept.append, clock=lambda: NOW
        )
        assert credentials.org == "acme"
        assert credentials.policy_keys == {ORG_KEY.keyid: ORG_KEY.public["public"]}
        assert slept == [1, 1], "polled at the server's interval until approved"

    def test_slow_down_backs_off(self, cloud) -> None:
        cloud.pending_polls = 0
        responses = iter([(400, b'{"error":"slow_down"}')])
        original = cloud.__call__

        def once(method, url, *, body, headers):
            if url.endswith("/v1/auth/token"):
                try:
                    return next(responses)
                except StopIteration:
                    pass
            return original(method, url, body=body, headers=headers)

        slept: list[float] = []
        code = auth.CloudAuth.start_device_flow(API, transport=once)
        auth.CloudAuth.finish_device_flow(
            code, API, transport=once, sleep=slept.append, clock=lambda: NOW
        )
        assert slept == [1, 6]

    @pytest.mark.parametrize(
        ("error", "message"), [("access_denied", "declined"), ("expired_token", "expired")]
    )
    def test_refusals_end_the_flow(self, cloud, error, message) -> None:
        cloud.device_error = error
        code = auth.CloudAuth.start_device_flow(API)
        with pytest.raises(CloudError, match=message):
            auth.CloudAuth.finish_device_flow(code, API, sleep=lambda _: None, clock=lambda: NOW)

    def test_the_stored_credential_is_private(self, cloud) -> None:
        path = auth.CloudAuth.save(auth.CloudAuth._credentials_from(API, cloud.token_response, NOW))
        if (
            os.name != "nt"
        ):  # POSIX permission bits; Windows has ACLs instead and reports every file as 0o666.
            assert path.stat().st_mode & 0o777 == 0o600
        assert auth.CloudAuth.load().access_token == "at-1"
        assert auth.CloudAuth.forget() and auth.CloudAuth.load() is None


class TestCiIdentity(CloudFixtures):
    def test_github_actions_token_is_requested_with_the_cordon_audience(self, cloud) -> None:
        env = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://gha.test/token?x=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req",
        }

        def github(method, url, *, body, headers):
            assert url == "https://gha.test/token?x=1&audience=cordon"
            assert headers["Authorization"] == "Bearer req"
            return 200, b'{"value": "ci-jwt"}'

        assert auth.CloudAuth.ambient_identity_token(env, transport=github) == (
            "ci-jwt",
            "github-actions",
        )

    def test_the_exchange_yields_a_short_lived_token(self, cloud, monkeypatch) -> None:
        monkeypatch.setenv("CORDON_ID_TOKEN", "ci-jwt")
        credentials = auth.CloudAuth.current(API, clock=lambda: NOW)
        assert credentials.access_token == "at-1"
        [(_, _, _, body)] = [r for r in cloud.requests if r[1].endswith("/v1/auth/token")]
        assert b"token-exchange" in body and b"subject_token=ci-jwt" in body

    def test_a_job_names_its_organisation_when_told_to(self, cloud, monkeypatch) -> None:
        """CircleCI, Buildkite and Azure jobs must (backend BE-04); the id is checked before it is sent."""
        monkeypatch.setenv("CORDON_ID_TOKEN", "ci-jwt")
        monkeypatch.setenv("CORDON_ORGANIZATION", "org_123-abc")
        auth.CloudAuth.current(API, clock=lambda: NOW)
        [(_, _, _, body)] = [r for r in cloud.requests if r[1].endswith("/v1/auth/token")]
        assert b"audience=cordon%3Aorg_123-abc" in body
        assert auth.CloudAuth.exchange_audience({}) == "cordon"
        with pytest.raises(CloudError):
            auth.CloudAuth.exchange_audience({"CORDON_ORGANIZATION": "../evil"})

    def test_an_untrusted_identity_is_refused_with_the_reason(self, cloud, monkeypatch) -> None:
        monkeypatch.setenv("CORDON_ID_TOKEN", "someone-elses-jwt")
        with pytest.raises(CloudError, match="trust rule"):
            auth.CloudAuth.current(API, clock=lambda: NOW)

    def test_an_expiring_sign_in_is_refreshed_and_kept(self, cloud) -> None:
        stored = CloudHelpers.signed_in(cloud)
        stored.expires_at = NOW + 10
        auth.CloudAuth.save(stored)
        cloud.token_response = {**cloud.token_response, "access_token": "at-2"}
        renewed = auth.CloudAuth.current(API, clock=lambda: NOW)
        assert renewed.access_token == "at-2"
        assert auth.CloudAuth.load().access_token == "at-2"
        assert renewed.policy_keys == stored.policy_keys


class TestSignedResults(CloudFixtures):
    @pytest.fixture
    def result(self, tmp_path):
        from cordon_scanner import Scanner

        (tmp_path / "project").mkdir()
        (tmp_path / "project" / "a.py").write_text("print('hi')\n", encoding="utf-8")
        return Scanner().scan(tmp_path / "project")

    def test_the_statement_names_the_exact_result_bytes(self, cloud, result) -> None:
        receipt = results.SignedResults.upload(
            result, CloudHelpers.signed_in(cloud), exit_code=0, reason="clean"
        )
        assert receipt.scan_id == "scn_1" and receipt.signing == "none"
        [upload] = cloud.scans
        raw = base64.b64decode(upload["results"])
        statement = json.loads(base64.b64decode(upload["envelope"]["payload"]))
        assert statement["subject"][0]["digest"]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert statement["predicateType"] == results.PREDICATE_TYPE
        assert statement["predicate"]["fingerprints"] == sorted(
            f["fingerprint"] for f in json.loads(raw)["findings"]
        )
        assert upload["org"] == "acme"
        assert statement["predicate"]["target"]["kind"] == "source"
        [(_, _, headers, _)] = [r for r in cloud.requests if r[1].endswith("/v1/scans")]
        assert headers["Authorization"] == "Bearer at-1"

    def test_a_signer_bundle_travels_with_the_upload(self, cloud, result) -> None:
        seen: list[bytes] = []

        def signer(payload: bytes):
            seen.append(payload)
            return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}

        results.SignedResults.upload(
            result, CloudHelpers.signed_in(cloud), exit_code=1, reason="findings", signer=signer
        )
        [upload] = cloud.scans
        assert upload["signing"] == "sigstore"
        assert seen == [base64.b64decode(upload["envelope"]["payload"])]

    def test_the_ai_inventory_travels_bound_by_the_signed_statement(self, cloud, tmp_path) -> None:
        from cordon_scanner import Scanner

        project = tmp_path / "agentic"
        (project / ".claude").mkdir(parents=True)
        (project / "CLAUDE.md").write_text("Run the tests before committing.\n", encoding="utf-8")
        (project / ".mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"docs": {"url": "https://user:pw@mcp.example.com/sse?key=s3"}}}
            ),
            encoding="utf-8",
        )
        scanned = Scanner().scan(project)
        document = results.SignedResults.ai_inventory(project, scanned)
        assert document is not None
        results.SignedResults.upload(
            scanned,
            CloudHelpers.signed_in(cloud),
            exit_code=0,
            reason="clean",
            ai_document=document,
        )
        [upload] = cloud.scans
        sent = base64.b64decode(upload["ai_inventory"])
        statement = json.loads(base64.b64decode(upload["envelope"]["payload"]))
        assert statement["predicate"]["ai_inventory"]["sha256"] == hashlib.sha256(sent).hexdigest()
        bom = json.loads(sent)
        names = {c["name"] for c in [*bom.get("components", []), *bom.get("services", [])]}
        assert {"CLAUDE.md", "docs"} <= names
        assert b"Run the tests" not in sent, "file contents never leave the machine"
        assert b"pw@" not in sent and b"key=s3" not in sent, "credentials in URLs are dropped"

    def test_an_archive_has_no_ai_inventory_and_uploads_without_one(
        self, cloud, result, tmp_path
    ) -> None:
        archive = tmp_path / "x.tgz"
        archive.write_bytes(b"not a directory")
        assert results.SignedResults.ai_inventory(archive, result) is None
        results.SignedResults.upload(
            result, CloudHelpers.signed_in(cloud), exit_code=0, reason="clean", ai_document=None
        )
        [upload] = cloud.scans
        assert "ai_inventory" not in upload
        assert (
            "ai_inventory"
            not in json.loads(base64.b64decode(upload["envelope"]["payload"]))["predicate"]
        )

    def test_pae_is_dsse_v1(self) -> None:
        assert results.SignedResults.pae("t", b"ab") == b"DSSEv1 1 t 2 ab"


class TestPolicyBundle(CloudFixtures):
    def test_a_signed_bundle_is_applied_and_cached(self, cloud) -> None:
        cloud.bundle = CloudHelpers.bundle()
        fetched = policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)
        assert (fetched.version, fetched.source, fetched.key_id) == (3, "fetched", ORG_KEY.keyid)
        assert fetched.suppressions[0].approved_by == "security@acme.test"
        cloud.bundle = None
        assert (
            policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW).source
            == "cached"
        )

    @pytest.mark.parametrize(
        ("served", "message"),
        [
            (lambda: CloudHelpers.bundle(key=OTHER_KEY), "not signed by a key pinned"),
            (lambda: CloudHelpers.bundle(org="globex"), "different organisation"),
        ],
    )
    def test_a_bundle_that_must_not_apply_is_refused_even_with_a_cache(
        self, cloud, served, message
    ) -> None:
        cloud.bundle = CloudHelpers.bundle()
        policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)
        cloud.bundle = served()
        with pytest.raises(policy.PolicyRejected, match=message):
            policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)

    def test_rollback_to_an_older_version_is_refused(self, cloud) -> None:
        cloud.bundle = CloudHelpers.bundle(version=5)
        policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)
        cloud.bundle = CloudHelpers.bundle(version=4)
        with pytest.raises(policy.PolicyRejected, match="older"):
            policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)

    def test_a_tampered_payload_fails_its_signature(self, cloud) -> None:
        served = CloudHelpers.bundle()
        body = json.loads(base64.b64decode(served["payload"]))
        body["suppressions"][0]["rule"] = "MALWARE.DROPPER.001"
        served["payload"] = base64.b64encode(json.dumps(body, sort_keys=True).encode()).decode()
        cloud.bundle = served
        with pytest.raises(policy.PolicyRejected):
            policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)

    def test_offline_uses_the_cache_until_it_expires(self, cloud) -> None:
        cloud.bundle = CloudHelpers.bundle(expires=NOW + 100)
        policy.CloudPolicy.fetch(CloudHelpers.signed_in(cloud), clock=lambda: NOW)
        assert (
            policy.CloudPolicy.fetch(
                CloudHelpers.signed_in(cloud), offline=True, clock=lambda: NOW + 50
            ).source
            == "cached"
        )
        with pytest.raises(CloudError, match="no current policy bundle"):
            policy.CloudPolicy.fetch(
                CloudHelpers.signed_in(cloud), offline=True, clock=lambda: NOW + 200
            )


class TestTheCommandLine(CloudFixtures):
    def test_cloud_policy_applies_the_org_policy_and_suppressions(
        self, cloud, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr("time.time", lambda: NOW)
        CloudHelpers.signed_in(cloud)
        cloud.bundle = CloudHelpers.bundle()
        project = tmp_path / "p"
        project.mkdir()
        (project / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert (
            CommandLine.main(
                ["scan", str(project), "--cloud-policy", "--cloud-url", API, "--quiet"]
            )
            == 0
        )

    def test_no_bundle_no_scan(self, cloud, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr("time.time", lambda: NOW)
        CloudHelpers.signed_in(cloud)
        project = tmp_path / "p"
        project.mkdir()
        assert (
            CommandLine.main(
                ["scan", str(project), "--cloud-policy", "--cloud-url", API, "--quiet"]
            )
            == 3
        )

    def test_an_org_suppression_that_breaks_the_rules_is_refused(
        self, cloud, tmp_path, monkeypatch
    ) -> None:
        """Held to the same rules as a repository's: here, a justification that gives no reason."""
        monkeypatch.setattr("time.time", lambda: NOW)
        CloudHelpers.signed_in(cloud)
        served = json.loads(base64.b64decode(CloudHelpers.bundle()["payload"]))
        served["suppressions"][0]["justification"] = "ok"
        payload = json.dumps(served, sort_keys=True).encode()
        cloud.bundle = {
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {"keyid": ORG_KEY.keyid, "sig": FeedKit.sign(ORG_KEY.seed, payload).hex()}
            ],
        }
        project = tmp_path / "p"
        project.mkdir()
        assert (
            CommandLine.main(
                ["scan", str(project), "--cloud-policy", "--cloud-url", API, "--quiet"]
            )
            == 3
        )

    def test_upload_never_changes_the_exit_code(self, cloud, tmp_path, monkeypatch, capsys) -> None:
        monkeypatch.setattr("time.time", lambda: NOW)
        project = tmp_path / "p"
        project.mkdir()
        (project / "a.py").write_text("x = 1\n", encoding="utf-8")
        assert (
            CommandLine.main(["scan", str(project), "--upload", "--cloud-url", API, "--quiet"]) == 0
        )
        assert "not signed in" in capsys.readouterr().err
        CloudHelpers.signed_in(cloud)
        assert CommandLine.main(["scan", str(project), "--upload", "--cloud-url", API]) == 0
        assert cloud.scans and "uploaded scan scn_1" in capsys.readouterr().err

    def test_login_and_whoami(self, cloud, monkeypatch, capsys) -> None:
        monkeypatch.setattr("time.sleep", lambda _: None)
        assert CommandLine.main(["login", "--url", API]) == 0
        out = capsys.readouterr()
        assert "WDJB-MJHT" in out.err
        assert "1 policy key(s) pinned" in out.out
        assert CommandLine.main(["whoami"]) == 0
        assert "dev@acme.test at acme" in capsys.readouterr().out
        assert CommandLine.main(["logout"]) == 0
        assert not (Path(auth.CloudAuth.config_dir()) / auth.CREDENTIALS_NAME).exists()


class TestSigningOut(CloudFixtures):
    """`cordon logout` ends the sign-in in the cloud (RFC 7009), not only the file on this machine."""

    @staticmethod
    def _revocations(cloud: FakeCloud) -> list[dict[str, str]]:
        return [
            dict(pair.split("=", 1) for pair in (body or b"").decode().split("&") if "=" in pair)
            for method, url, _, body in cloud.requests
            if url == f"{API}/v1/auth/revoke"
        ]

    def test_the_refresh_token_is_revoked_then_the_file_removed(self, cloud, capsys) -> None:
        CloudHelpers.signed_in(cloud)
        assert CommandLine.main(["logout"]) == 0
        assert self._revocations(cloud) == [
            {"token": "rt-1", "token_type_hint": "refresh_token", "client_id": "cordon-cli"}
        ]
        assert auth.CloudAuth.load() is None
        assert "here and in Cordon Cloud" in capsys.readouterr().out

    def test_without_a_refresh_token_the_access_token_is_sent(self, cloud) -> None:
        cloud.token_response.pop("refresh_token")
        credentials = CloudHelpers.signed_in(cloud)
        assert auth.CloudAuth.revoke(credentials)
        assert self._revocations(cloud)[0]["token_type_hint"] == "access_token"
        assert self._revocations(cloud)[0]["token"] == "at-1"

    def test_an_unreachable_cloud_still_signs_out_here_and_says_so(
        self, cloud, monkeypatch, capsys
    ) -> None:
        CloudHelpers.signed_in(cloud)

        def down(method, url, *, body, headers):
            raise CloudError("could not reach api.cordon.test (URLError)")

        monkeypatch.setattr("cordon_scanner.cloud.transport.CloudTransport._urllib", down)
        assert CommandLine.main(["logout"]) == 0
        assert auth.CloudAuth.load() is None
        out = capsys.readouterr()
        assert "on this machine" in out.out
        assert "stays valid until it expires" in out.err and "CLI sign-ins" in out.err
        assert "rt-1" not in out.out + out.err, "a token is never printed"

    def test_a_refusal_is_not_reported_as_revoked(self, cloud, monkeypatch, capsys) -> None:
        CloudHelpers.signed_in(cloud)
        monkeypatch.setattr(
            "cordon_scanner.cloud.transport.CloudTransport._urllib",
            lambda method, url, *, body, headers: (503, b"{}"),
        )
        assert CommandLine.main(["logout"]) == 0
        assert "stays valid" in capsys.readouterr().err

    def test_a_tampered_url_is_not_sent_the_token(self, cloud, capsys) -> None:
        credentials = CloudHelpers.signed_in(cloud)
        tampered = auth.Credentials(**{**credentials.__dict__, "url": "http://evil.example"})
        assert auth.CloudAuth.revoke(tampered) is False
        assert self._revocations(cloud) == [] and not cloud.requests

    def test_not_signed_in(self, cloud, capsys) -> None:
        assert CommandLine.main(["logout"]) == 0
        assert capsys.readouterr().out.strip() == "Not signed in."
        assert cloud.requests == []


class TestRepositoryGateModes(CloudFixtures):
    """The bundle carries each repository's gate mode. `observe` and `warn` record a failing
    verdict without failing the build; `block`, a repository not listed and an unknown mode all
    fail it, so a bundle can only ever leave the gate as strict as the policy."""

    @staticmethod
    def _failing_project(tmp_path):
        project = tmp_path / "p"
        project.mkdir()
        token = Support.assemble("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
        (project / "a.py").write_text(f'TOKEN = "{token}"\n', encoding="utf-8")
        return project

    @pytest.mark.parametrize(
        ("gates", "expected"),
        [
            ({"p": "warn"}, 0),
            ({"p": "observe"}, 0),
            ({"p": "block"}, 1),
            ({}, 1),
            ({"p": "relaxed"}, 1),
            ({"other": "warn"}, 1),
        ],
    )
    def test_the_repository_mode_decides_the_exit_code(
        self, cloud, tmp_path, monkeypatch, capsys, gates, expected
    ) -> None:
        monkeypatch.setattr("time.time", lambda: NOW)
        CloudHelpers.signed_in(cloud)
        cloud.bundle = CloudHelpers.bundle(gates=gates)
        project = self._failing_project(tmp_path)
        code = CommandLine.main(["scan", str(project), "--cloud-policy", "--cloud-url", API])
        assert code == expected
        if expected == 0:
            assert (
                "mode: the verdict is recorded, the build is not failed" in capsys.readouterr().err
            )

    def test_without_the_cloud_policy_the_verdict_stands(
        self, cloud, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr("time.time", lambda: NOW)
        project = self._failing_project(tmp_path)
        assert CommandLine.main(["scan", str(project), "--quiet"]) == 1

    def test_the_bundle_keeps_only_known_modes(self) -> None:
        parsed = policy.CloudPolicy._parse(
            {
                "org": "acme",
                "version": 1,
                "issued_at": NOW,
                "expires_at": NOW + 60,
                "gates": {"github.com/acme/app": "warn", "github.com/acme/x": "off"},
            },
            "fetched",
        )
        assert parsed.gate_mode("github.com/ACME/app") == "warn"
        assert parsed.gate_mode("github.com/acme/x") == "block"
        assert parsed.gate_mode("github.com/acme/unlisted") == "block"


class TestTheSigstoreSurface(CloudFixtures):
    """Fulcio and Rekor are out of reach in a test, so what is pinned is the sigstore API the
    signer calls: a rename there fails here instead of on a customer's first CI upload."""

    def test_the_names_the_signer_uses_exist(self) -> None:
        sigstore = pytest.importorskip("sigstore")
        from sigstore import dsse
        from sigstore.oidc import IdentityToken, detect_credential
        from sigstore.sign import SigningContext

        assert callable(detect_credential) and callable(IdentityToken)
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "cordon-results.json", "digest": {"sha256": "0" * 64}}],
            "predicateType": results.PREDICATE_TYPE,
            "predicate": {},
        }
        assert dsse.Statement(json.dumps(statement).encode()) is not None
        if not hasattr(SigningContext, "production"):
            from sigstore.models import ClientTrustConfig

            assert callable(ClientTrustConfig.production)
            assert callable(SigningContext.from_trust_config)
        assert sigstore.__version__

    def test_without_a_ci_identity_nothing_is_signed(self, monkeypatch) -> None:
        pytest.importorskip("sigstore")
        monkeypatch.setattr("sigstore.oidc.detect_credential", lambda: None)
        assert results.SignedResults.sigstore_signer(None)(b"{}") is None

    def test_sigstore_accepts_the_statement_a_scan_produces(self, tmp_path) -> None:
        pytest.importorskip("sigstore")
        from sigstore import dsse

        from cordon_scanner import Scanner

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = Scanner().scan(tmp_path)
        document = results.SignedResults.statement(
            result, results.SignedResults.results_bytes(result), exit_code=0, reason="clean"
        )
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        assert dsse.Statement(payload) is not None
