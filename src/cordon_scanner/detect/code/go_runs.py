"""Go code that runs what it receives, or writes the CI job's environment, when it is imported.

`received_and_run`: data read from a connection handed to a process start. `ci_environment_write`:
a package whose load path writes `GITHUB_ENV` or `GITHUB_PATH`. Moved beside `capability/detector.py` (0.7.0
layout: a long module only shrinks); `CapabilityDetector` calls these and labels what they return.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.load_path import LoadPath
from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class GoRuns:
    _GO_CONNECTION: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?P<conn>[A-Za-z_]\w{0,40})\s*,\s*[A-Za-z_]\w{0,40}\s*:?=\s*"
        r"(?:[A-Za-z_][\w.]{0,60}\.)?(?:Dial(?:Timeout|Context|TCP|UDP)?|Accept)\s*\("
    )
    _GO_EXEC: ClassVar[re.Pattern[str]] = re.compile(
        r"\bexec\.Command(?:Context)?\s*\(\s*(?P<first>[^,)\s]+)"
    )

    @classmethod
    def received_and_run(cls, content: FileContent) -> list[CapabilityHit]:
        """A Go function that runs what arrives on a network connection it opened.

        `conn := Dial(...)`, a line read from `conn`, split into arguments, `exec.Command(args[0],
        args[1:]...)` and the output written back to `conn`: the command channel of
        `boltdb-go/bolt` 1.3.1, served from the Go module mirror for three years (review 98).
        Recorded at the process start as `fetch_exec`: what runs is whatever the other end sent.
        One function at a time; the first argument to `exec.Command` must not be a literal."""
        text = content.text
        if "exec.Command" not in text or ("Dial" not in text and "Accept" not in text):
            return []

        for found in LoadPath.GO_FUNC.finditer(text):
            depth, index = 1, found.end()
            limit = min(len(text), index + 200_000)
            while index < limit and depth:
                depth += text[index] == "{"
                depth -= text[index] == "}"
                index += 1
            body = text[found.end() : index]
            for connection in cls._GO_CONNECTION.finditer(body):
                conn = re.escape(connection["conn"])
                after = body[connection.end() :]
                reads = re.search(
                    rf"(?:\b{conn}\s*\.\s*Read\w*\(|\(\s*{conn}\s*\)\s*\.\s*(?:ReadString|ReadLine|ReadBytes|Scan|Decode)\b|NewScanner\(\s*{conn}\s*\))",
                    after,
                )
                if reads is None:
                    continue
                for run in cls._GO_EXEC.finditer(after, reads.start()):
                    if run["first"].startswith(('"', "`")):
                        continue
                    offset = found.end() + connection.end() + run.start()
                    start = len(text[:offset].encode("utf-8"))
                    # The connection it reads from is the egress: `d.Dial` on a `net.Dialer` value
                    # is a connection whatever the variable is called.
                    dialled = found.end() + connection.start()
                    egress = len(text[:dialled].encode("utf-8"))
                    return [
                        CapabilityHit(
                            capability=Capability.EGRESS,
                            rule_id="CAP.GO.RECEIVED_RUN",
                            byte_start=egress,
                            byte_end=egress + 1,
                            line=text.count("\n", 0, dialled) + 1,
                        ),
                        CapabilityHit(
                            capability=Capability.FETCH_EXEC,
                            rule_id="CAP.GO.RECEIVED_RUN",
                            byte_start=start,
                            byte_end=start + 1,
                            line=text.count("\n", 0, offset) + 1,
                        ),
                    ]
        return []

    #: The CI job's environment and PATH files: what a step writes there, every later step runs with.
    _CI_ENV_FILE: ClassVar[re.Pattern[str]] = re.compile(r"\bGITHUB_(?:ENV|PATH)\b")
    _GO_FILE_WRITE: ClassVar[re.Pattern[str]] = re.compile(
        r"\bos\.(?:OpenFile\([^\n]{0,200}O_(?:APPEND|WRONLY|RDWR)|WriteFile\(|Create\()"
    )

    @classmethod
    def ci_environment_write(cls, content: FileContent) -> list[CapabilityHit]:
        """A Go package that, when imported, writes the CI job's environment or PATH file.

        Every later step of the job runs with what is written there: a proxy pointed at the
        attacker, a PATH entry ahead of the real `go`. The 2025 `BufferZoneCorp/*` modules did it
        from `init()`, the name split as `_env("GITHUB_", "ENV")` (resolved by
        `detect/go_eval.py`), and stripped `go.sum` lines so the next download is not checked
        (review 98). Only from the load path -- `init()` or a package-level initialiser -- where
        nothing in the importing program asked for it; a GitHub Action written in Go writes the
        file from `main`, which is what an action is for."""
        text = content.text
        if cls._CI_ENV_FILE.search(text) is None:
            return []
        writes = list(cls._GO_FILE_WRITE.finditer(text))
        if not writes:
            return []
        candidates = []
        for write in writes:
            start = len(text[: write.start()].encode("utf-8"))
            candidates.append(
                CapabilityHit(
                    capability=Capability.PERSIST,
                    rule_id="CAP.GO.CI_ENV_WRITE",
                    byte_start=start,
                    byte_end=start + 1,
                    line=text.count("\n", 0, write.start()) + 1,
                )
            )

        on_load = [
            hit
            for hit in candidates
            if LoadPath.in_go_load_path(content, [hit], (Capability.PERSIST,))
        ]
        return on_load[:1]


__all__ = ["GoRuns"]
