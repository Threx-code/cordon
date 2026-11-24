"""`pr-comment`: the pull-request comment for a build gate's decisions, and the one notification a REVIEW result raises.

Reads what `decide --lock` printed (standard input), writes the comment as markdown (standard output) and, with
`--notification-out`, the notification record when the result is REVIEW. The action posts the first and hands the second to the
platform; a REVIEW result also names the owner in the comment so the repository host notifies them.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError, ExitCode

if TYPE_CHECKING:
    import argparse
    from pathlib import Path
    from typing import TextIO


class PrCommentCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        comment = sub.add_parser(
            "pr-comment",
            help="the pull-request comment for `decide --lock` output (stdin), with its REVIEW notification",
        )
        comment.add_argument(
            "--base", required=True, help="the platform's https base URL the three links use"
        )
        comment.add_argument(
            "--owner", default=None, help="who a REVIEW result is for: a user or `org/team`"
        )
        comment.add_argument("--pr", required=True, help="the pull request, e.g. owner/repo#12")
        comment.add_argument(
            "--notification-out", default=None, help="write the REVIEW notification record here"
        )

    @classmethod
    def run(
        cls, args: argparse.Namespace, stdin: TextIO | None = None, stdout: TextIO | None = None
    ) -> int:
        from cordon_scanner.cloud.agent.pr_comment import PrComment
        from cordon_scanner.decide.decision.outcome import Decision
        from cordon_scanner.decide.decision.records import DecisionError

        try:
            document = json.loads((stdin or sys.stdin).read())
            results = [
                (str(item["subject"]), Decision.from_json(item["decision"]))
                for item in document["decisions"]
            ]
            body = PrComment.render(results, args.base, args.owner)
            note = PrComment.notification(results, args.owner, args.pr) if args.owner else None
        except (ValueError, KeyError, TypeError, DecisionError) as problem:
            raise ConfigError(
                f"pr-comment: not the output of `decide --lock`, or a bad option: {problem}"
            ) from problem
        (stdout or sys.stdout).write(body)
        if args.notification_out and note is not None:
            cls._write(args.notification_out, note)
        return int(ExitCode.CLEAN)

    @staticmethod
    def _write(path: Path | str, note: dict[str, object]) -> None:
        from pathlib import Path as _Path

        _Path(path).write_text(json.dumps(note, sort_keys=True) + "\n", encoding="utf-8")
