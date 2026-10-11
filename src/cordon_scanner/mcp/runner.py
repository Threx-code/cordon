"""The scanner, run as a child process for one tool call.

A child, not a function call in the server: a scan that hangs, takes gigabytes or crashes ends with
its process, and the server keeps serving. Each run has a deadline and a cancellation flag; either
one ends the child's whole process group, so nothing it started outlives the call. Output goes to
temporary files rather than pipes, so a large result cannot deadlock the child, and is capped when
read back.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

MAX_OUTPUT: Final = 64 << 20
MAX_ERROR: Final = 64 << 10
POLL: Final = 0.05


class Cancelled(Exception):
    """The client cancelled the call; nothing more is sent for it."""


class TimedOut(Exception):
    """The run passed its deadline and was ended."""


@dataclass(frozen=True, slots=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str
    seconds: float
    truncated: bool

    def json(self) -> Any:
        return json.loads(self.stdout)


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        #: Set when the server is past its queue bound: the call is answered "busy", not run.
        self.busy = False

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class Runner:
    """Runs `cordon-scanner` -- this installation's, by module -- with the server's settings."""

    def __init__(
        self,
        *,
        offline: bool,
        private_network: bool = False,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.offline = offline
        base = dict(os.environ if environment is None else environment)
        if offline:
            # The scanner's own air-gapped switch: no feed, no registry, nothing.
            base["CORDON_OFFLINE"] = "1"
        if not private_network:
            # What a scan connects to can be named by what an agent passed in: an MCP server's URL,
            # an image's registry. Such a name may lead only to the public network (`core.netguard`).
            base["CORDON_PUBLIC_NETWORK_ONLY"] = "1"
        else:
            base.pop("CORDON_PUBLIC_NETWORK_ONLY", None)
        base["NO_COLOR"] = "1"
        base["PYTHONIOENCODING"] = "utf-8"
        base.pop("PYTHONSTARTUP", None)
        self.environment = base

    def command(self, args: list[str]) -> list[str]:
        # -P: the working directory is not put on the import path, so a file in it named like a
        # module cannot be imported in the scanner's place. Not -I, which would also drop a
        # `pip install --user` installation's own site-packages.
        return [sys.executable, "-P", "-m", "cordon_scanner", *args]

    def run(
        self, args: list[str], *, timeout: float, token: CancelToken, cwd: Path | None = None
    ) -> Run:
        start = time.monotonic()
        with (
            tempfile.TemporaryFile() as out,
            tempfile.TemporaryFile() as err,
            tempfile.TemporaryDirectory(prefix="cordon-mcp-cwd-") as neutral,
        ):
            cwd = cwd or Path(neutral)
            kwargs: dict[str, Any] = {}
            if os.name == "posix":
                kwargs["start_new_session"] = True
            else:  # pragma: no cover - Windows
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
            process = subprocess.Popen(  # noqa: S603 - our own interpreter and module, list form
                self.command(args),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                cwd=str(cwd),
                env=self.environment,
                **kwargs,
            )
            try:
                while process.poll() is None:
                    if token.cancelled:
                        raise Cancelled
                    if time.monotonic() - start > timeout:
                        raise TimedOut(f"the scan passed its {timeout:.0f}s deadline and was ended")
                    time.sleep(POLL)
            finally:
                if process.poll() is None:
                    self._end(process)
            out.seek(0)
            body = out.read(MAX_OUTPUT + 1)
            err.seek(0)
            error = err.read(MAX_ERROR)
        return Run(
            exit_code=process.returncode,
            stdout=body[:MAX_OUTPUT].decode("utf-8", "replace"),
            stderr=error.decode("utf-8", "replace"),
            seconds=time.monotonic() - start,
            truncated=len(body) > MAX_OUTPUT,
        )

    @staticmethod
    def _end(process: subprocess.Popen[bytes]) -> None:
        """End the child and everything it started: TERM, then KILL after a grace period."""
        if os.name == "posix":
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        else:  # pragma: no cover - Windows
            process.kill()
            process.wait(timeout=5)
