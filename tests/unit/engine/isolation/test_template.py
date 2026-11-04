"""engine.isolation.template: workers forked from a clean template behave as spawned ones do (each
unit's result or why it has none), and the template's own traps are closed: no worker inherits a
channel to another, interrupts are the parent's, and nothing outlives the parent."""

from __future__ import annotations

import multiprocessing
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from cordon_scanner.engine.isolation.supervisor import Bounds, Reason, Supervisor, Unit, WorkerMain
from cordon_scanner.engine.isolation.template import Template

pytestmark = pytest.mark.skipif(not Template.available(), reason="no fork on this platform")


class Planted:
    """What a planted unit does in its worker."""

    @staticmethod
    def setup() -> None:
        return None

    @staticmethod
    def run(item: tuple[str, object]) -> object:
        kind, arg = item
        if kind == "echo":
            return arg
        if kind == "die":
            os._exit(9)
        if kind == "sockets":  # this worker and how many sockets it holds, after a pause so that
            time.sleep(float(arg))  # type: ignore[arg-type]  # the units spread across the workers
            return os.getpid(), sum(
                1 for fd in Path("/proc/self/fd").iterdir() if Planted.is_socket(fd)
            )
        if kind == "pid":
            return os.getpid()
        if kind == "sleep":
            time.sleep(float(arg))  # type: ignore[arg-type]
            return "woke"
        raise AssertionError(kind)

    @staticmethod
    def is_socket(fd: Path) -> bool:
        try:
            return str(fd.readlink()).startswith("socket:")
        except OSError:
            return False


class Harness:
    @staticmethod
    def supervisor(
        template: Template, bounds: Bounds | None = None, workers: int = 2
    ) -> Supervisor:
        module = Planted.__module__
        supervisor = Supervisor(
            multiprocessing.get_context("spawn"),
            (f"{module}:Planted.setup", ()),
            f"{module}:Planted.run",
            bounds or Bounds(),
            workers,
        )
        supervisor.template = template
        return supervisor


class TemplateFixtures:
    """Fixtures for the tests in test_template.py; every test class here inherits them."""

    @pytest.fixture
    def template(self):
        started = Template.start(WorkerMain.from_template)
        assert started is not None
        try:
            yield started
        finally:
            started.close()


class TestWorkersFromTheTemplate(TemplateFixtures):
    def test_every_result_comes_back_by_its_index(self, template) -> None:
        units = [Unit(i, ("echo", i * 3), 1) for i in range(10)]
        assert Harness.supervisor(template, workers=3).run(units).results == {
            i: i * 3 for i in range(10)
        }

    def test_a_worker_that_dies_costs_only_its_unit(self, template) -> None:
        units = [Unit(0, ("echo", "a"), 1), Unit(1, ("die", None), 1), Unit(2, ("echo", "b"), 1)]
        outcome = Harness.supervisor(template).run(units)
        assert outcome.results == {0: "a", 2: "b"}
        assert outcome.failed == {1: Reason.DIED}

    def test_a_hang_meets_the_backstop_and_is_killed_through_the_template(self, template) -> None:
        units = [Unit(0, ("sleep", 60), 1), Unit(1, ("echo", "after"), 1)]
        outcome = Harness.supervisor(template, Bounds(cpu_floor=0.5, wall_factor=2.0)).run(units)
        assert outcome.failed == {0: Reason.WALL}
        assert outcome.results == {1: "after"}

    def test_each_worker_holds_one_socket_its_own(self, template) -> None:
        units = [Unit(i, ("sockets", 0.5), 1) for i in range(4)]
        outcome = Harness.supervisor(template, workers=4).run(units)
        pids = {pid for pid, _ in outcome.results.values()}
        assert len(pids) >= 2, "the units must reach later workers for this to test anything"
        # no channel to the template or another worker, in the last worker forked as in the first
        assert {count for _, count in outcome.results.values()} == {1}

    def test_workers_are_the_template_s_children_not_the_parent_s(self, template) -> None:
        outcome = Harness.supervisor(template, workers=1).run([Unit(0, ("pid", None), 1)])
        with pytest.raises(ChildProcessError):
            os.waitpid(outcome.results[0], os.WNOHANG)  # not ours to reap


class TestTheTemplateLeavesNothingBehind(TemplateFixtures):
    SCRIPT = textwrap.dedent(
        """
        import time
        from cordon_scanner.engine.isolation.template import Template
        from cordon_scanner.engine.isolation.supervisor import WorkerMain
        def idle(sock):
            time.sleep(600)
        t = Template.start(idle)
        sock, pid = t.fork_worker()
        print(t.pid, pid, flush=True)
        time.sleep(600)
        """
    )

    @staticmethod
    def alive(pid: int) -> bool:
        try:
            return Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2] != "Z"
        except OSError:
            return False

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux's")
    def test_killing_the_parent_ends_the_template_and_its_workers(self) -> None:
        script = self.SCRIPT
        parent = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
        try:
            template_pid, worker_pid = map(int, parent.stdout.readline().split())  # type: ignore[union-attr]
            assert self.alive(template_pid) and self.alive(worker_pid)
            parent.send_signal(signal.SIGKILL)
            parent.wait()
            # gone within seconds, polled: a single fixed sleep raced a loaded host
            until = time.monotonic() + 10.0
            while time.monotonic() < until and (self.alive(template_pid) or self.alive(worker_pid)):
                time.sleep(0.05)
            assert not self.alive(template_pid)
            assert not self.alive(worker_pid)
        finally:
            parent.kill()
            parent.wait()
            parent.stdout.close()  # type: ignore[union-attr]

    def test_an_interrupt_is_the_parent_s(self, template) -> None:
        sock, pid = template.fork_worker()
        try:
            # until the kernel shows SIGINT ignored in both: a fixed sleep raced a loaded host
            for watched in (template.pid, pid):
                assert self.ignores_interrupts(watched), f"{watched} never ignored SIGINT"
            os.kill(template.pid, signal.SIGINT)
            os.kill(pid, signal.SIGINT)
            time.sleep(0.2)
            assert template.alive(pid)[0]
            assert self.alive(template.pid)
        finally:
            sock.close()
            template.kill(pid)
            template.wait(pid)

    alive = staticmethod(alive)

    @staticmethod
    def ignores_interrupts(pid: int, within: float = 10.0) -> bool:
        """Whether `pid`'s ignored-signal mask (SigIgn in /proc/<pid>/status) holds SIGINT, waiting
        up to `within` seconds for it to be set."""
        until = time.monotonic() + within
        while time.monotonic() < until:
            for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
                if line.startswith("SigIgn:") and int(line.split()[1], 16) & (
                    1 << (signal.SIGINT - 1)
                ):
                    return True
            time.sleep(0.01)
        return False


class TestAChildWhoseParentHasGone:
    """PR_SET_PDEATHSIG is armed only for a parent that ends after it: a parent killed between the fork
    and the `prctl` left the template or its worker reparented and alive (5 of 30 runs of the kill
    test on a loaded host, on the release code as on the branch). After arming, the child checks."""

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux's")
    def test_a_child_whose_parent_is_not_the_one_that_forked_it_ends(self) -> None:
        script = (
            "from cordon_scanner.engine.isolation.template import Lifeline\n"
            "import os\n"
            "Lifeline.die_with_parent(os.getppid() + 1_000_000)\n"
            "print('alive')\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
        )
        assert done.returncode == 1
        assert "alive" not in done.stdout
        assert "Traceback" not in done.stderr, done.stderr

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux's")
    def test_a_child_whose_parent_is_still_there_runs_on(self) -> None:
        script = (
            "from cordon_scanner.engine.isolation.template import Lifeline\n"
            "import os\n"
            "Lifeline.die_with_parent(os.getppid())\n"
            "print('alive')\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
        )
        assert done.returncode == 0
        assert "alive" in done.stdout
