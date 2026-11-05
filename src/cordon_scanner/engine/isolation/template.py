"""The template: the clean process supervised workers are forked from (item 28, detector isolation).

A worker spawned for each scan built its engine again, about 1.1-1.5 s a scan (measured, review 28).
Instead, at a scan's start, after the engine is built and before anything is read, the scanner forks
one template: our code and rule pack, no scanned byte. When detection needs workers, it asks the
template, which forks each one, so every worker is a fork of that clean state however many are asked
for and however late. A worker forked from the parent at detection time would inherit what the
parent had read by then.

The template takes fixed commands only, never data: `F` (fork a worker; its end of a fresh socket
pair is passed back with `socket.send_fds`, with its pid), `P <pid>` (alive?), `S <pid>` (its exit
status, waiting for it), `K <pid>` (kill it) and `Q` (end). It is every worker's parent, so it alone
kills and reaps them: a pid the parent signalled could have been reused since the worker died. It
keeps no end of a worker's socket pair, so no later worker inherits a channel to an earlier one.
It ignores SIGINT (the parent owns shutdown), dies with the parent (PR_SET_PDEATHSIG on Linux, and
end-of-file on its control socket everywhere), and kills its workers when it ends.

Platforms without fork (Windows) have no template: workers are spawned there, as before.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import stat
import sys
import warnings
from pathlib import Path
from typing import Any


class Lines:
    """One command or answer per line on a stream socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock, self.buffer = sock, b""

    def read(self) -> str | None:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode("ascii")

    def write(self, line: str) -> None:
        self.sock.sendall(line.encode("ascii") + b"\n")


class Lifeline:
    """What a template or a worker sets right after it is forked."""

    @staticmethod
    def die_with_parent(parent: int) -> None:
        """Linux: the kernel sends SIGKILL when the parent ends (prctl PR_SET_PDEATHSIG).

        `parent` is the forking process's pid, read before the fork. The signal is armed only
        for a parent that ends after `prctl`: one that ended between the fork and it left the
        child reparented, never signalled, and alive (a template and its worker outlived a killed
        scan in 5 of 30 runs on a loaded host). So the parent is checked after arming, and a
        child whose parent has already gone ends itself."""
        if not sys.platform.startswith("linux"):
            return
        with contextlib.suppress(OSError, AttributeError):
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
        if os.getppid() != parent:
            os._exit(1)

    @staticmethod
    def leave_interrupts_to_the_parent() -> None:
        signal.signal(signal.SIGINT, signal.SIG_IGN)


class TemplateMain:
    """What runs in the template process: forks, polls, reaps and kills its workers."""

    @staticmethod
    def serve(control: socket.socket, worker_main: Any, parent: int) -> None:
        Lifeline.die_with_parent(parent)
        Lifeline.leave_interrupts_to_the_parent()
        TemplateMain.close_inherited_sockets(control)
        lines, children = Lines(control), set[int]()
        try:
            while (command := lines.read()) is not None and command != "Q":
                verb, _, arg = command.partition(" ")
                if verb == "F":
                    TemplateMain.fork(control, lines, children, worker_main)
                elif verb == "P":
                    lines.write(TemplateMain.poll(int(arg), children))
                elif verb == "S":
                    lines.write(TemplateMain.status(int(arg), children, block=True))
                elif verb == "K" and int(arg) in children:
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(arg), signal.SIGKILL)
        finally:
            for pid in list(children):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(pid, 0)
            os._exit(0)

    @staticmethod
    def close_inherited_sockets(control: socket.socket) -> None:
        """Every socket the host held when it forked the template, closed here but `control`.

        A fork copies every descriptor, close-on-exec or not, so each worker held whatever the host
        had open at the template's start: another scan's template and worker channels, a connection
        a caller left open. A worker reading scanned content holds no channel but its own (macOS CI:
        a worker held 3 sockets, 5 Nov). Sockets only: a file or a pipe the host opened may be state
        a detector reads. The standard streams (0 to 2) are the host's and stay.

        Each is replaced by /dev/null, not freed: the host's socket objects are copied here too, and
        one collected later closes its number, which by then could be a new worker's channel."""
        listing = Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
        try:
            names = [entry.name for entry in listing.iterdir()]
            null = os.open(os.devnull, os.O_RDWR)
        except OSError:
            return
        try:
            keep = {control.fileno(), null}
            for name in names:
                if not name.isdigit() or (fd := int(name)) <= 2 or fd in keep:
                    continue
                with contextlib.suppress(OSError):  # the listing's own descriptor, closed already
                    if stat.S_ISSOCK(os.fstat(fd).st_mode):
                        os.dup2(null, fd)
        finally:
            os.close(null)

    @staticmethod
    def fork(control: socket.socket, lines: Lines, children: set[int], worker_main: Any) -> None:
        ours, theirs = socket.socketpair()
        parent = os.getpid()
        pid = os.fork()
        if pid == 0:  # the worker
            control.close()
            ours.close()
            Lifeline.die_with_parent(parent)
            Lifeline.leave_interrupts_to_the_parent()
            try:
                worker_main(theirs)
            finally:
                os._exit(0)
        children.add(pid)
        # The pid and the socket in one message: a line read by plain recv() could take the bytes
        # a separate message carried its descriptor with, and drop the descriptor.
        socket.send_fds(control, [f"W {pid}\n".encode("ascii")], [ours.fileno()])
        ours.close()  # neither end stays here: no later worker inherits a channel to this one
        theirs.close()

    @staticmethod
    def poll(pid: int, children: set[int]) -> str:
        return TemplateMain.status(pid, children, block=False)

    @staticmethod
    def status(pid: int, children: set[int], *, block: bool) -> str:
        """`alive`, or `exit <code>` (a signal as its negative number, as multiprocessing shows it)."""
        if pid not in children:
            return "exit 0"
        try:
            done, status = os.waitpid(pid, 0 if block else os.WNOHANG)
        except ChildProcessError:
            children.discard(pid)
            return "exit 0"
        if done == 0:
            return "alive"
        children.discard(pid)
        code = -os.WTERMSIG(status) if os.WIFSIGNALED(status) else os.WEXITSTATUS(status)
        return f"exit {code}"


class Template:
    """The parent's handle on its template: ask it for workers, and their fate."""

    def __init__(self, control: socket.socket, pid: int) -> None:
        self.control, self.pid, self.lines = control, pid, Lines(control)

    @staticmethod
    def available() -> bool:
        return hasattr(os, "fork") and hasattr(socket, "send_fds")

    @staticmethod
    def fork_from_host() -> int:
        """`os.fork()` of the host, for the template, with Python 3.15's fork-with-threads warning
        said here instead of raised.

        The template is forked from the host because it must carry the host's state -- detectors a
        caller passed `Scanner`, rule packs already loaded, patched settings -- which a spawned
        interpreter would not have (measured: every scan in a threaded host failed that way). 3.15
        warns whenever another thread is alive at a fork (3.12-3.14 do not): a lock that thread held
        is copied into the child locked. What runs in the child is only `TemplateMain.serve`, a loop
        of socket reads, forks and waits over locks CPython re-initialises after a fork (the GIL, the
        import lock, logging's); it touches no lock a library thread of the host could hold. The
        workers are forked from the template, single-threaded, so the warning does not apply to them.
        The CLI forks before it starts a thread and never meets it."""
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r"This process \(pid=\d+\) is multi-threaded",
                category=DeprecationWarning,
            )
            return os.fork()

    @staticmethod
    def start(worker_main: Any) -> Template | None:
        """The template, forked now: call it before anything scanned is read. `worker_main` is what
        each worker runs with its socket. None where the platform cannot fork."""
        if not Template.available():
            return None
        ours, theirs = socket.socketpair()
        parent = os.getpid()
        pid = Template.fork_from_host()
        if pid == 0:
            ours.close()
            TemplateMain.serve(theirs, worker_main, parent)  # never returns
        theirs.close()
        ours.set_inheritable(False)
        return Template(ours, pid)

    def fork_worker(self) -> tuple[socket.socket, int]:
        """A new worker's socket (this process's end) and its pid."""
        self.lines.write("F")
        if self.lines.buffer:
            raise OSError("the template's control stream is out of step")
        data, fds, _, _ = socket.recv_fds(self.control, 64, 1)
        answer = data.decode("ascii").strip()
        if not answer.startswith("W ") or not fds:
            for fd in fds:
                os.close(fd)
            raise OSError(f"the template did not fork a worker: {answer!r}")
        sock = socket.socket(fileno=fds[0])
        sock.set_inheritable(False)
        return sock, int(answer[2:])

    def alive(self, pid: int) -> tuple[bool, int | None]:
        self.lines.write(f"P {pid}")
        return Template.answer(self.lines.read())

    def wait(self, pid: int) -> int | None:
        self.lines.write(f"S {pid}")
        return Template.answer(self.lines.read())[1]

    def kill(self, pid: int) -> None:
        self.lines.write(f"K {pid}")

    @staticmethod
    def answer(line: str | None) -> tuple[bool, int | None]:
        if line == "alive":
            return True, None
        if line is not None and line.startswith("exit "):
            return False, int(line[5:])
        return False, None

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.lines.write("Q")
        with contextlib.suppress(ChildProcessError):
            os.waitpid(self.pid, 0)
        self.control.close()


__all__ = ["Template"]
