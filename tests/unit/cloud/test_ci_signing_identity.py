"""Uploads are signed only with a CI pipeline's identity, never a person's.

A keyless signature publishes the signer's identity in Sigstore's public log for good, and a
person's identity is their email address.
"""

from __future__ import annotations

import base64
import json

import pytest

from cordon_scanner.cloud.results import CiSigningIdentity, SignedResults


class Tokens:
    @staticmethod
    def of(claims: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"eyJhbGciOiJSUzI1NiJ9.{body}.c2ln"


class TestCiSigningIdentity:
    @pytest.mark.parametrize(
        "claims",
        [
            {
                "iss": "https://token.actions.githubusercontent.com",
                "repository": "acme/app",
                "workflow_ref": "acme/app/.github/workflows/ci.yml@refs/heads/main",
            },
            {
                "iss": "https://gitlab.com",
                "project_path": "acme/app",
                "pipeline_source": "push",
                "job_id": "1",
            },
            {
                "iss": "https://gitlab.acme.internal",
                "project_path": "acme/app",
                "pipeline_source": "push",
                "job_id": "1",
            },
            {"iss": "https://oidc.circleci.com/org/0f1e", "oidc.circleci.com/project-id": "p-1"},
            {
                "iss": "https://agent.buildkite.com",
                "pipeline_slug": "app",
                "organization_slug": "acme",
            },
        ],
    )
    def test_a_pipelines_own_token_is_accepted(self, claims):
        assert CiSigningIdentity.is_pipeline(Tokens.of(claims))

    @pytest.mark.parametrize(
        "claims",
        [
            {
                "iss": "https://oauth2.sigstore.dev/auth",
                "email": "dev@acme.com",
                "email_verified": True,
            },
            {"iss": "https://accounts.google.com", "email": "dev@acme.com"},
            {"iss": "https://github.com/login/oauth", "sub": "dev"},
            {
                "iss": "https://token.actions.githubusercontent.com",
                "repository": "acme/app",
                "workflow_ref": "x",
                "email": "dev@acme.com",
            },
            {"iss": "https://token.actions.githubusercontent.com"},
            {"iss": "https://gitlab.com", "project_path": "acme/app"},
            {},
        ],
    )
    def test_a_person_or_an_incomplete_token_is_refused(self, claims):
        assert not CiSigningIdentity.is_pipeline(Tokens.of(claims))

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "not-a-jwt",
            "a.b",
            "a.%%%.c",
            "a." + base64.urlsafe_b64encode(b"[1]").decode() + ".c",
        ],
    )
    def test_garbage_is_refused_without_raising(self, raw):
        assert not CiSigningIdentity.is_pipeline(raw)

    def test_a_personal_token_produces_no_signature(self, monkeypatch):
        pytest.importorskip("sigstore")
        signer = SignedResults.sigstore_signer(
            Tokens.of({"iss": "https://accounts.google.com", "email": "dev@acme.com"})
        )
        assert signer(b"payload") is None
