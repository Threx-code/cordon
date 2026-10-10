"""An environment variable naming where a credential is kept is not the credential.

Found scanning caveman's `deploy/kubernetes-ha.yaml`:
`CAVEMAN_MIDDLEWARE_TOKEN_MAP_FILE: /etc/caveman/identity/tokens.yaml` was reported HIGH as a
credential written into the manifest. `_FILE` is the convention for "read the secret from this
mounted file" (`POSTGRES_PASSWORD_FILE` in Docker's official images), which is the remediation.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config


class TestSecretEnvNames:
    RULE = "SUSPECT.K8S.SECRET_ENV_VALUE.001"

    def found(self, tmp_path, name: str, value: str) -> bool:
        manifest = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: db\nspec:\n  template:\n"
            "    spec:\n      containers:\n        - name: db\n          image: postgres:16\n"
            f"          env:\n            - name: {name}\n              value: {value}\n"
        )
        path = tmp_path / "deploy" / "db.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(manifest, encoding="utf-8")
        findings = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return any(f.rule_id == self.RULE for f in findings.findings)

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("POSTGRES_PASSWORD_FILE", "/run/secrets/db"),
            ("CAVEMAN_MIDDLEWARE_TOKEN_MAP_FILE", "/etc/caveman/identity/tokens.yaml"),
            ("API_TOKEN_PATH", "/var/run/token"),
            ("SECRET_DIR", "/etc/secrets"),
        ],
    )
    def test_a_name_for_where_it_is_kept_is_not_reported(self, tmp_path, name, value) -> None:
        assert not self.found(tmp_path, name, value)

    @pytest.mark.parametrize("name", ["POSTGRES_PASSWORD", "API_TOKEN", "FILE_SECRET"])
    def test_a_credential_value_still_is(self, tmp_path, name: str) -> None:
        assert self.found(tmp_path, name, "hunter2hunter2")
