"""The component that runs untrusted code, and what it refuses to do.

Nothing here executes anything. The tests that matter most are about refusal:
the flag that has to be typed, the isolation that has to exist, and the fact
that neither has an override. Those are the properties that make the component
safe to ship, and they are testable without a container runtime -- which is
important, because a test suite that needs one would skip exactly the assertions
that matter on the machines that do not have one.

The parts that need a runtime are marked and skipped when it is absent, rather
than silently passing.
"""

from __future__ import annotations

import pytest

from cordon_sandbox import cli
from cordon_sandbox.isolation import Backend, IsolationError, available_backend
from cordon_sandbox.observe import PERSISTENCE_PREFIXES, _interpret, install_command


def has_runtime() -> bool:
    try:
        available_backend()
    except IsolationError:
        return False
    return True


class TestItRefusesByDefault:
    def test_nothing_runs_without_the_flag(self, capsys) -> None:
        """The flag carries no information the command does not already imply.
        It exists so that running untrusted code is never something somebody
        did by accident."""
        assert cli.main(["pypi", "requests"]) == cli.BAD_INVOCATION
        assert "Pass --sandbox" in capsys.readouterr().err

    def test_the_refusal_explains_itself(self, capsys) -> None:
        cli.main(["npm", "left-pad"])
        assert "installs and runs the package you name" in capsys.readouterr().err

    def test_the_help_says_it_executes(self) -> None:
        text = cli.build_parser().format_help()
        assert "EXECUTES" in text


class TestItRefusesWithoutIsolation:
    def test_a_missing_runtime_is_an_error_not_a_warning(self, monkeypatch, capsys) -> None:
        """A sandbox that degrades to running untrusted code on the host when
        its backend is missing is worse than no sandbox, because the person who
        asked for it believes they are protected."""
        monkeypatch.setattr(
            "cordon_sandbox.cli.available_backend",
            lambda: (_ for _ in ()).throw(IsolationError("no container runtime is available")),
        )
        assert cli.main(["pypi", "requests", "--sandbox"]) == cli.FAILED
        assert "no container runtime" in capsys.readouterr().err

    def test_there_is_no_override(self) -> None:
        """Asserted against the parser rather than trusted to review: an
        `--allow-unsafe` added later would silently remove the property this
        whole component rests on."""
        options = cli.build_parser().format_help()
        for forbidden in ("--force", "--allow-unsafe", "--no-isolation", "--unsafe"):
            assert forbidden not in options

    def test_isolation_is_established_before_anything_is_downloaded(self, monkeypatch) -> None:
        """A missing runtime should be discovered before the network is
        touched, so a refusal costs nothing and leaks nothing."""
        order: list[str] = []

        def backend():
            order.append("isolation")
            raise IsolationError("none")

        def fetch(ecosystem, package):  # pragma: no cover - must not be reached
            order.append("fetch")
            raise AssertionError("fetched before isolation was established")

        monkeypatch.setattr("cordon_sandbox.cli.available_backend", backend)
        monkeypatch.setattr("cordon_sandbox.cli.fetch", fetch)
        cli.main(["pypi", "requests", "--sandbox"])
        assert order == ["isolation"]


class TestTheScannerCannotReachIt:
    def test_the_scanner_does_not_import_the_sandbox(self) -> None:
        """The scanner's promise is that it never executes what it scans, and a
        promise with an entry point into execution is not one."""
        import subprocess
        import sys

        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import cordon_scanner, cordon_scanner.cli.main, sys; "
                "print(any(m.startswith('cordon_sandbox') for m in sys.modules))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert probe.stdout.strip() == "False"


class TestWhatItSaysAboutIsolation:
    def test_a_rootless_runtime_says_so(self) -> None:
        claims = Backend(command="podman", version="5", rootless=True).guarantees
        assert any("rootless" in c for c in claims)

    def test_a_root_owned_runtime_says_that_is_weaker(self) -> None:
        claims = Backend(command="docker", version="27", rootless=False).guarantees
        assert any("weaker" in c for c in claims)

    def test_it_never_claims_a_read_only_root(self) -> None:
        """It used to, and the claim made the component useless: a payload
        writing to /etc/cron.d simply failed, and the run reported "the install
        failed" rather than "it tried to persist"."""
        for rootless in (True, False):
            claims = Backend(command="x", version="1", rootless=rootless).guarantees
            assert not any("read-only root" in c for c in claims)
            assert any("discarded afterwards" in c for c in claims)


class TestInterpretation:
    def test_writes_outside_the_install_tree_are_persistence(self) -> None:
        diff = "A /etc/cron.d/updater\nC /usr/local/bin\nA /work/site/six.py\n"
        kinds = [o.kind for o in _interpret(diff, 0, timed_out=False)]
        assert kinds == ["persistence"]

    def test_ordinary_install_writes_are_not_reported(self) -> None:
        diff = "A /work/site/six.py\nC /work\nA /tmp/pip-build\n"
        assert _interpret(diff, 0, timed_out=False) == []

    def test_a_timeout_says_what_was_not_observed(self) -> None:
        observations = _interpret("", -1, timed_out=True)
        assert observations[0].kind == "timeout"
        assert "not observed" in observations[0].detail

    def test_every_persistence_prefix_is_outside_a_package_tree(self) -> None:
        for prefix in PERSISTENCE_PREFIXES:
            assert not prefix.startswith(("/work", "/tmp"))


class TestInstallCommands:
    def test_lifecycle_scripts_are_left_enabled(self) -> None:
        """They are the reason to run anything at all. `--ignore-scripts` would
        produce a clean observation of a package whose whole payload is a
        postinstall hook."""
        _, npm = install_command("npm", "pkg.tgz")
        assert "--ignore-scripts" not in npm

    def test_the_install_reads_the_local_artefact_not_the_network(self) -> None:
        _, pip = install_command("pypi", "pkg.tar.gz")
        assert "--no-index" in pip
        _, npm = install_command("npm", "pkg.tgz")
        assert "--offline" in npm

    def test_an_unknown_ecosystem_is_refused(self) -> None:
        with pytest.raises(IsolationError):
            install_command("cargo", "pkg.crate")


@pytest.mark.skipif(not has_runtime(), reason="no container runtime available")
class TestAgainstARealRuntime:
    def test_a_backend_reports_a_version(self) -> None:
        backend = available_backend()
        assert backend.version
        assert backend.command
