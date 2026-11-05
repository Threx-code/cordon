"""The sandbox sees more (advanced gap P7): RubyGems installs, and a second install with the clock
moved ahead, so a payload waiting for a date acts while it is watched. No package is run here;
the commands, the fetch check and the merge of the two runs are tested as text and data.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from cordon_sandbox.cli import SandboxCli
from cordon_sandbox.dns_recorder import DnsRecorder
from cordon_sandbox.fetch import ArtefactFetcher
from cordon_sandbox.isolation import IsolationError
from cordon_sandbox.observe import BASE_IMAGES, FAKETIME, Observation, Observer, Run


class TestRubyGems:
    def test_installed_from_the_file_with_no_source(self) -> None:
        image, command = Observer.install_command("rubygems", "rake-13.2.1.gem")
        assert image == BASE_IMAGES["rubygems"] and "@sha256:" in image
        assert "gem install --local" in command and "/work/rake-13.2.1.gem" in command

    def test_lookups_are_recorded_in_ruby(self) -> None:
        assert DnsRecorder.COMMANDS["rubygems"].startswith("ruby ")
        assert "UDPSocket" in DnsRecorder.SCRIPTS["rubygems"]

    def test_the_gem_is_checked_against_the_published_sha256(self, monkeypatch) -> None:
        body = b"not really a gem"
        answers = {
            "https://rubygems.org/api/v2/rubygems/example/versions/1.0.0.json": json.dumps(
                {"version": "1.0.0", "sha": hashlib.sha256(b"something else").hexdigest()}
            ).encode(),
            "https://rubygems.org/gems/example-1.0.0.gem": body,
        }
        monkeypatch.setattr(ArtefactFetcher, "_get", staticmethod(lambda url, accept: answers[url]))
        with pytest.raises(IsolationError, match="does not match"):
            ArtefactFetcher.fetch("rubygems", "example@1.0.0")
        answers["https://rubygems.org/api/v2/rubygems/example/versions/1.0.0.json"] = json.dumps(
            {"version": "1.0.0", "sha": hashlib.sha256(body).hexdigest()}
        ).encode()
        assert ArtefactFetcher.fetch("rubygems", "example@1.0.0").filename == "example-1.0.0.gem"


class TestTheClockPass:
    def test_only_the_install_sees_the_shifted_clock(self) -> None:
        shifted = Observer.traced_command("npm install x", "nonce", "", None, clock_shift_days=400)
        assert f"LD_PRELOAD={FAKETIME}" in shifted and "FAKETIME=+400d" in shifted
        # The tracer itself is outside the payload's environment: strace runs on real time.
        assert shifted.index("strace") < shifted.index("LD_PRELOAD")
        assert "LD_PRELOAD" not in Observer.traced_command("npm install x", "nonce", "", None)

    def test_what_only_the_shifted_run_did_is_added(self) -> None:
        def run(*observations: Observation) -> Run:
            return Run(
                backend=None,
                image="i",
                command="c",
                exit_status=0,
                timed_out=False,
                observations=observations,
                output_tail="",
                guarantees=("g",),
                traced=True,
            )  # type: ignore[arg-type]

        merged = SandboxCli.with_clock_pass(
            run(Observation("executed", "/bin/uname")),
            run(
                Observation("executed", "/bin/uname"),
                Observation("network", "connect 203.0.113.9:443"),
            ),
            400,
        )
        assert [o.detail for o in merged.observations] == [
            "/bin/uname",
            "only with the clock 400 days ahead: connect 203.0.113.9:443",
        ]
        assert any("400 days ahead" in g for g in merged.guarantees)
