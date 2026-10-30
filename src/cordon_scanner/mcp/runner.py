"""The scanner, run as a child process for one tool call.

A child, not a function call in the server: a scan that hangs, takes gigabytes or crashes ends with
its process, and the server keeps serving. Each run has a deadline and a cancellation flag; either
one ends the child's whole process group, so nothing it started outlives the call. Output goes to
temporary files rather than pipes, so a large result cannot deadlock the child, and is capped when
read back.
"""

from __future__ import annotations

import contextlib
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

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.mcp.warm import WarmScanner

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
        return ScannedJson.loads(self.stdout)


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()
        #: Set when the server is past its queue bound: the call is answered "busy", not run.
        self.busy = False
        #: When the whole call must end (monotonic seconds): every scan it runs shares this budget,
        #: so a call that scans many packages cannot run for hours.
        self.deadline: float | None = None

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
        model_host: str | None = None,
    ) -> None:
        self.offline = offline
        base = dict(os.environ if environment is None else environment)
        if offline:
            # The scanner's own air-gapped switch: no feed, no registry, nothing.
            base["CORDON_OFFLINE"] = "1"
        else:
            base.pop("CORDON_OFFLINE", None)
        if not private_network:
            # What a scan connects to can be named by what an agent passed in: an MCP server's URL,
            # an image's registry. Such a name may lead only to the public network (`core.netguard`).
            base["CORDON_PUBLIC_NETWORK_ONLY"] = "1"
            if model_host:
                # The model server the operator named (often on a private address, inside the
                # organisation) is the one exception, and only it: no agent input reaches this.
                allowed = {
                    h.strip()
                    for h in base.get("CORDON_ALLOWED_PRIVATE_HOSTS", "").split(",")
                    if h.strip()
                }
                base["CORDON_ALLOWED_PRIVATE_HOSTS"] = ",".join(sorted(allowed | {model_host}))
        else:
            base.pop("CORDON_PUBLIC_NETWORK_ONLY", None)
        base["NO_COLOR"] = "1"
        base["PYTHONIOENCODING"] = "utf-8"
        base.pop("PYTHONSTARTUP", None)
        self.environment = base
        #: The warm scanner (`mcp.warm`), started by `start_warm`; until it is ready, or if it
        #: dies, a call runs cold.
        self.warm: WarmScanner | None = None
        self._warm_home: tempfile.TemporaryDirectory[str] | None = None

    def start_warm(self) -> None:
        """Start the warm scanner in the background. Calls made before it is ready run cold."""
        if self.warm is not None or not WarmScanner.wanted(self.environment):
            return
        self._warm_home = tempfile.TemporaryDirectory(prefix="cordon-mcp-warm-")
        self.warm = WarmScanner(self.environment)
        try:
            self.warm.start(self._warm_home.name)
        except OSError:
            self.warm = None

    def close(self) -> None:
        if self.warm is not None:
            self.warm.close()
            self.warm = None
        if self._warm_home is not None:
            self._warm_home.cleanup()
            self._warm_home = None

    def command(self, args: list[str]) -> list[str]:
        # -P: the working directory is not put on the import path, so a file in it named like a
        # module cannot be imported in the scanner's place. Not -I, which would also drop a
        # `pip install --user` installation's own site-packages.
        return [sys.executable, "-P", "-m", "cordon_scanner", *args]

    def run(
        self, args: list[str], *, timeout: float, token: CancelToken, cwd: Path | None = None
    ) -> Run:
        start = time.monotonic()
        if token.deadline is not None:
            timeout = min(timeout, token.deadline - start)
            if timeout <= 0:
                raise TimedOut("the call passed its deadline before this scan could start")
        warm = self.warm
        if warm is not None and warm.ready:
            with contextlib.suppress(OSError):
                return self._run_warm(
                    warm, args, timeout=timeout, token=token, cwd=cwd, start=start
                )
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
    def _run_warm(
        warm: WarmScanner,
        args: list[str],
        *,
        timeout: float,
        token: CancelToken,
        cwd: Path | None,
        start: float,
    ) -> Run:
        """One call as a fork of the warm scanner; same deadline, cancellation and caps as cold.
        Raises `OSError` when the helper cannot take the call, and the caller runs it cold."""
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-cwd-") as neutral:
            out_path = Path(neutral) / ".out"
            err_path = Path(neutral) / ".err"
            out_path.touch(mode=0o600)
            err_path.touch(mode=0o600)
            work = cwd or Path(neutral)
            ident = warm.submit(args, cwd=str(work), out=str(out_path), err=str(err_path))
            try:
                while not warm.finished(ident):
                    if token.cancelled:
                        raise Cancelled
                    if time.monotonic() - start > timeout:
                        raise TimedOut(f"the scan passed its {timeout:.0f}s deadline and was ended")
                    time.sleep(POLL)
            except BaseException:
                warm.end(ident)
                warm.exit_code(ident)
                raise
            code = warm.exit_code(ident)
            if not warm.ready:
                # The helper died with this call in it: the status is unknown, so it is run again
                # cold rather than reported as a scan result.
                raise OSError("the warm scanner ended during the call")
            with out_path.open("rb") as out:
                body = out.read(MAX_OUTPUT + 1)
            with err_path.open("rb") as err:
                error = err.read(MAX_ERROR)
        return Run(
            exit_code=code,
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
            # The scanner starts worker processes; ending only the parent would leave them
            # running. taskkill /T ends the tree, named by its absolute path, never searched for.
            taskkill = (
                Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
            )
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run(  # noqa: S603 - absolute system path, fixed argv
                    [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
            with contextlib.suppress(OSError):
                process.kill()
            process.wait(timeout=5)
