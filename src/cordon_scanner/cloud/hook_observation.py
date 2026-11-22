"""What an agent hook may tell the control plane about what an agent did: which tool, on which subject, under which decision, and when. Never what was said or returned.

A hook receives the tool call as the agent made it: its name, its input (the command, the file, the prompt behind it) and, after the call, its output. The observed capability of an agent is built from
counts of those calls, so the record is made by an allowlist of four fields: the tool's name (kept only if it looks like a name), the digest of the subject the decision was made about (taken from the
decision's own subject, never from the hook input), the id of the decision (its `inputs_digest`) and the time. Whatever else the hook input holds, a prompt, an output, an argument, a path, stays on the machine
and is not looked at.

`HookObservation.counts` folds records into how many times each tool was called on each subject, which is all the platform needs to say what an agent has been observed to use.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.records import Instants

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from datetime import datetime

    from cordon_scanner.decide.decision.outcome import Decision


class HookObservation:
    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"tool", "subject_digest", "decision_id", "observed_at"}
    )
    #: A tool's name: letters, digits and the few marks tool names carry (`mcp__server__tool`, `Bash`, `fs.read`). Anything else, or anything longer, is not a name and is recorded as `unknown`: a hook
    #: input is the agent's, and a field that should hold a name can hold anything.
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:/-]{1,100}$")
    UNKNOWN: ClassVar[str] = "unknown"

    @classmethod
    def tool_of(cls, hook_input: Mapping[str, Any]) -> str:
        name = hook_input.get("tool_name")
        return name if isinstance(name, str) and cls.NAME.match(name) else cls.UNKNOWN

    @classmethod
    def of(
        cls,
        hook_input: Mapping[str, Any],
        *,
        subject_digest: str,
        decision: Decision,
        clock: datetime,
    ) -> dict[str, str]:
        """The record of one tool call. Raises ValueError for a subject digest that is not one: a record with no subject says nothing the platform can count."""
        if not ArtifactDigests.is_digest(subject_digest):
            raise ValueError(
                "a hook observation needs the sha256 digest of the subject the decision was about"
            )
        return {
            "tool": cls.tool_of(hook_input),
            "subject_digest": subject_digest,
            "decision_id": decision.inputs_digest,
            "observed_at": Instants.text(clock),
        }

    @classmethod
    def problems(cls, record: object) -> list[str]:
        """What is wrong with a document that claims to be a hook observation: a key outside the four, a missing one, a value that is not a short string."""
        if not isinstance(record, dict):
            return ["not an object"]
        found = [
            f"unexpected key {key!r}" for key in sorted(map(str, record)) if key not in cls.FIELDS
        ]
        found += [f"missing key {key!r}" for key in sorted(cls.FIELDS - set(record))]
        found += [
            f"{key!r} is not a short string"
            for key, value in record.items()
            if key in cls.FIELDS and not (isinstance(value, str) and len(value) <= 100 + 64)
        ]
        tool = record.get("tool")
        if isinstance(tool, str) and tool != cls.UNKNOWN and not cls.NAME.match(tool):
            found.append("'tool' is not a name")
        return found

    @staticmethod
    def counts(records: Iterable[Mapping[str, str]]) -> dict[tuple[str, str], int]:
        """How many times each tool was called on each subject."""
        return dict(Counter((record["tool"], record["subject_digest"]) for record in records))


__all__ = ["HookObservation"]
