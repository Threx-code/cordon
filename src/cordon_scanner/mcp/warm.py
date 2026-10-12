"""A warm scanner for the MCP server: load once, fork a child per tool call.

A tool call used to start a fresh interpreter, and before scanning anything that interpreter
imported the scanner, compiled the rule pack, registered the detectors and parsed the shipped
advisories: about four seconds, every call, for a one-dependency project. The scan itself is a
fraction of a second. So a helper process does that work once, and each call is a fork of it.

```
  MCP server (threads)                       warm helper (one thread, never serves)
  ---------------------                      ---------------------------------------
  start() --spawn-->                         import scanner, rules, detectors, advisories
                     <-- {"ready": true} --
  run(argv, cwd) ---- {"id", "argv", ...} -> fork --> child: own session, cwd, stdout/err to the
                     <-- {"id", "pid"} -----            call's files, CommandLine.main(argv)
     poll: cancel? deadline? -> killpg(pid)                      |
                     <-- {"id", "exit"} ---- reap <--------------+
```

What does not change from the cold path: the child is its own process session, so a deadline or a
cancellation ends it and everything it started; it has the server's scanning environment; its
output goes to files and is capped when read back. A fork cannot be taken from the server itself,
which runs threads; the helper has exactly one.

When it is not used: before it is ready, after it has died, on Windows (no fork), and when
`CORDON_MCP_WARM=off`. Each of those runs the call cold, as before - slower, never different.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
from typing import IO, Any, Final

#: Exit status reported for a child the helper could not account for.
LOST: Final = 70


class WarmScanner:
    """The server's side: starts the helper, sends it calls, follows each to its exit."""

    def __init__(self, environment: dict[str, str]) -> None:
        self._environment = environment
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()
        self._next = 0
        self._ready = threading.Event()
        self._dead = threading.Event()
        #: id -> {"pid": int | None, "exit": int | None, "done": Event}
        self._calls: dict[int, dict[str, Any]] = {}

    @staticmethod
    def wanted(environment: dict[str, str]) -> bool:
        return (
            os.name == "posix" and environment.get("CORDON_MCP_WARM", "").strip().lower() != "off"
        )

    def start(self, cwd: str) -> None:
        self._process = subprocess.Popen(  # our own interpreter and module, list form
            [sys.executable, "-P", "-m", "cordon_scanner.mcp.warm"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env=self._environment,
            text=True,
            encoding="utf-8",
            bufsize=1,
            start_new_session=True,
        )
        self._reader = threading.Thread(target=self._read, name="cordon-warm-reader", daemon=True)
        self._reader.start()

    @property
    def ready(self) -> bool:
        return self._ready.is_set() and not self._dead.is_set()

    def _read(self) -> None:
        stream = self._process.stdout if self._process is not None else None
        for line in stream or ():
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("ready"):
                self._ready.set()
                continue
            call = self._calls.get(message.get("id", -1))
            if call is None:
                continue
            if "pid" in message:
                call["pid"] = int(message["pid"])
                call["started"].set()
            if "exit" in message:
                call["exit"] = int(message["exit"])
                call["started"].set()
                call["done"].set()
        # The helper is gone: every call still waiting is told so, and nothing new is sent to it.
        self._dead.set()
        for call in list(self._calls.values()):
            call["started"].set()
            call["done"].set()

    def submit(self, argv: list[str], *, cwd: str, out: str, err: str) -> int:
        """Send one call; returns its id. Raises `OSError` when the helper cannot take it."""
        with self._lock:
            if not self.ready or self._process is None or self._process.stdin is None:
                raise OSError("the warm scanner is not available")
            self._next += 1
            ident = self._next
            self._calls[ident] = {
                "pid": None,
                "exit": None,
                "started": threading.Event(),
                "done": threading.Event(),
            }
            request = {"id": ident, "argv": argv, "cwd": cwd, "out": out, "err": err}
            self._process.stdin.write(json.dumps(request) + "\n")
            self._process.stdin.flush()
        return ident

    def finished(self, ident: int) -> bool:
        done: threading.Event = self._calls[ident]["done"]
        return done.is_set()

    def exit_code(self, ident: int) -> int:
        """The call's exit status; `LOST` when the helper died before reporting it."""
        call = self._calls.pop(ident)
        return LOST if call["exit"] is None else call["exit"]

    def end(self, ident: int) -> None:
        """End the call's child and everything it started: TERM, then KILL after a grace period."""
        call = self._calls[ident]
        call["started"].wait(5)
        pid = call["pid"]
        if pid is None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(pid, signal.SIGTERM)
        if not call["done"].wait(3):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pid, signal.SIGKILL)
            call["done"].wait(5)

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        with contextlib.suppress(OSError, ValueError):
            if process.stdin is not None:
                process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if self._reader is not None:
            self._reader.join(timeout=5)
        with contextlib.suppress(OSError, ValueError):
            if process.stdout is not None:
                process.stdout.close()
        self._process = None


class WarmHelper:
    """The helper's side: `python -m cordon_scanner.mcp.warm`. One thread, by construction."""

    @staticmethod
    def warm() -> None:
        """Everything a scan would otherwise rebuild per process."""
        from cordon_scanner.cli.main import CommandLine  # noqa: F401 - imported to be inherited
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.intel.advisories import AdvisoryDatabase
        from cordon_scanner.rules.loader import RuleLoader

        RuleLoader.load_builtin()
        Registry.default_detectors()
        AdvisoryDatabase.bundled()._load_all()

    @staticmethod
    def child(request: dict[str, Any]) -> int:
        """In the forked child: become the call's own session and run the scanner."""
        os.setsid()
        os.chdir(request["cwd"])
        null = os.open(os.devnull, os.O_RDONLY)
        out = os.open(request["out"], os.O_WRONLY | os.O_TRUNC)
        err = os.open(request["err"], os.O_WRONLY | os.O_TRUNC)
        os.dup2(null, 0)
        os.dup2(out, 1)
        os.dup2(err, 2)
        sys.stdin = open(0, encoding="utf-8", closefd=False)  # noqa: SIM115 - the process's own fd
        sys.stdout = open(1, "w", encoding="utf-8", closefd=False)  # noqa: SIM115
        sys.stderr = open(2, "w", encoding="utf-8", closefd=False)  # noqa: SIM115
        from cordon_scanner.cli.main import CommandLine

        try:
            code = CommandLine.main(list(request["argv"]))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        except BaseException:  # the child reports; it never takes the helper down
            import traceback

            traceback.print_exc()
            code = LOST
        with contextlib.suppress(Exception):
            sys.stdout.flush()
            sys.stderr.flush()
        return int(code or 0)

    @staticmethod
    def send(stream: IO[str], message: dict[str, Any]) -> None:
        stream.write(json.dumps(message) + "\n")
        stream.flush()

    @classmethod
    def serve(cls) -> int:
        cls.warm()
        if threading.active_count() != 1:
            # Forking a process that runs threads can copy a held lock into the child. Refuse to
            # serve rather than risk it: the server runs every call cold instead.
            return 1
        protocol = sys.stdout
        cls.send(protocol, {"ready": True})
        children: dict[int, int] = {}
        stdin = sys.stdin.fileno()
        buffered = ""
        open_input = True
        while open_input or children:
            if open_input:
                readable, _, _ = select.select([stdin], [], [], 0.05)
                if readable:
                    chunk = os.read(stdin, 1 << 16).decode("utf-8", "replace")
                    if not chunk:
                        open_input = False
                    buffered += chunk
                    while "\n" in buffered:
                        line, buffered = buffered.split("\n", 1)
                        try:
                            request = json.loads(line)
                        except ValueError:
                            continue
                        pid = os.fork()
                        if pid == 0:
                            os._exit(cls.child(request))
                        children[pid] = int(request["id"])
                        cls.send(protocol, {"id": request["id"], "pid": pid})
            else:
                time.sleep(0.05)
            while children:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    children.clear()
                    break
                if pid == 0:
                    break
                ident = children.pop(pid, None)
                if ident is not None:
                    cls.send(protocol, {"id": ident, "exit": os.waitstatus_to_exitcode(status)})
        return 0


if __name__ == "__main__":
    raise SystemExit(WarmHelper.serve())
