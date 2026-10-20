"""P7: planted credentials in the sandbox, and what an install did with them."""

from __future__ import annotations

import base64
import re

from cordon_sandbox.canaries import PLANTED_ATIME, Canaries
from cordon_sandbox.observe import HOME_DIR, Observer


class TestTheDecoys:
    def test_each_run_s_values_are_its_own_and_shaped_like_the_real_thing(self) -> None:
        first, second = Canaries.generate(), Canaries.generate()
        assert first.aws_key_id != second.aws_key_id
        assert re.fullmatch(r"AKIA[A-Z2-7]{16}", first.aws_key_id)
        assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", first.github_token)
        assert re.fullmatch(r"npm_[A-Za-z0-9]{36}", first.npm_token)
        assert first.aws_secret in first.files[".aws/credentials"]

    def test_the_environment_says_ci(self) -> None:
        environment = dict(Canaries.generate().environment)
        assert environment["CI"] == "true" and environment["GITHUB_ACTIONS"] == "true"
        assert environment["NPM_TOKEN"].startswith("npm_")

    def test_planting_sets_the_read_time_in_the_past(self) -> None:
        command = Canaries.generate().plant(HOME_DIR, 10001)
        assert f"touch -a -d @{PLANTED_ATIME}" in command
        assert "chmod 0644" in command, "readable, so the install can take the bait"
        assert "chown -R" not in command, "the decoys stay root's: their times cannot be reset"
        assert "chown 10001:10001" in command and "/work/.aws" in command


class TestReads:
    def test_a_read_store_is_reported_and_the_installer_s_own_is_not(self) -> None:
        canaries = Canaries.generate()
        listing = (
            f"{PLANTED_ATIME} {HOME_DIR}/.ssh/id_rsa\n"
            f"1760000000 {HOME_DIR}/.aws/credentials\n"
            f"1760000001 {HOME_DIR}/.npmrc\n"
        )
        assert canaries.reads(listing, HOME_DIR, "npm") == [".aws/credentials"]

    def test_an_unlisted_run_is_not_a_clean_one(self) -> None:
        observations = Observer.interpret_canaries(Canaries.generate(), "", None, None, "npm")
        assert [o.kind for o in observations] == ["not_observed"]


class TestSends:
    def test_a_token_in_a_send_is_reported(self) -> None:
        canaries = Canaries.generate()
        trace = f'123 sendto(5, "POST /c HTTP/1.1\\r\\n\\r\\nt={canaries.npm_token}", 64, 0, NULL, 0) = -1 ENETUNREACH\n'
        kinds = [o.kind for o in Observer.interpret_canaries(canaries, trace, "", "", "npm")]
        assert "sent_credentials" in kinds

    def test_an_encoded_token_in_a_lookup_is_reported(self) -> None:
        canaries = Canaries.generate()
        encoded = canaries.aws_key_id.encode().hex()
        lookups = f"{encoded}.collector.example.invalid\n"
        kinds = [o.kind for o in Observer.interpret_canaries(canaries, "", lookups, "", "pypi")]
        assert "sent_credentials" in kinds

    def test_base64_in_a_send(self) -> None:
        canaries = Canaries.generate()
        blob = base64.b64encode(canaries.github_token.encode()).decode()
        trace = f'9 sendmsg(4, {{msg_iov=[{{iov_base="{blob}"}}]}}, 0) = -1\n'
        assert canaries.leaked_in(trace)

    def test_the_payload_s_own_environment_in_its_execve_is_not_a_send(self) -> None:
        """The decoys are in the payload's environment, so they appear in the trace of the
        `env -i ... sh -c` that starts it. That is the sandbox handing them over, not the
        install sending them."""
        canaries = Canaries.generate()
        trace = (
            f'7 execve("/usr/bin/env", ["env", "-i", "NPM_TOKEN={canaries.npm_token}"], 0x0) = 0\n'
        )
        assert Observer.interpret_canaries(canaries, trace, "", "", "npm") == []

    def test_an_ordinary_lookup_is_not_a_leak(self) -> None:
        canaries = Canaries.generate()
        assert canaries.leaked_in("registry.npmjs.org\nfiles.pythonhosted.org\n") == []


class TestThePlantingIsNotTheInstall:
    def test_the_decoys_are_not_persistence(self) -> None:
        canaries = Canaries.generate()
        listing = "\n".join(sorted(canaries.planted_paths(HOME_DIR))) + f"\n{HOME_DIR}/.bashrc\n"
        [observation] = Observer._interpret_home(listing, canaries.planted_paths(HOME_DIR))
        assert observation.kind == "persistence" and "/work/.bashrc" in observation.detail
        assert ".aws" not in observation.detail
