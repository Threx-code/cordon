"""`decide`: the decision function, asked from a file or a pipe by something that is not the scanner.

An editor extension, a CI step or a hook gives the question as JSON on standard input (the compiled policy, the artifact, its
evidence, the time and the context) and gets the decision as JSON on standard output, from the same `PointRuntime.ask` every
enforcement point uses, so the answer does not depend on who asks. `--lock` decides every artifact of a lock at the build gate
and `--release` decides a release on its provenance; both exit 1 when the gate does not pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, TextIO

from cordon_scanner.foundation.errors import ConfigError, ExitCode


class DecideCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        from cordon_scanner.decide.points import PointRuntime

        decide = sub.add_parser("decide", help="ask the decision function: JSON in, a decision out")
        decide.add_argument(
            "--point",
            choices=PointRuntime.POINTS,
            default="cli",
            help="where the question comes from",
        )
        mode = decide.add_mutually_exclusive_group()
        mode.add_argument(
            "--lock", action="store_true", help="decide every artifact of a lock at the build gate"
        )
        mode.add_argument(
            "--release", action="store_true", help="decide a release on its provenance"
        )

    @classmethod
    def run(
        cls, args: argparse.Namespace, stdin: TextIO | None = None, stdout: TextIO | None = None
    ) -> int:
        from cordon_scanner.decide.build_gate import BuildGate
        from cordon_scanner.decide.decision.evidence import (
            ArtifactRef,
            Context,
            EvidenceSet,
            Provenance,
        )
        from cordon_scanner.decide.decision.records import DecisionError, Instants
        from cordon_scanner.decide.decision.table import CompiledPolicy
        from cordon_scanner.decide.points import PointRuntime

        out = stdout or sys.stdout
        try:
            question = json.loads((stdin or sys.stdin).read())
            policy = CompiledPolicy.from_json(question["policy"])
            policy.verify()
            clock = Instants.parse(question["clock"])
            context = Context.from_json({**question.get("context", {}), "point": args.point})
            keywords: dict[str, Any] = {
                "environment": context.environment,
                "scope_path": context.scope_path,
            }
            if args.lock:
                artifacts = [ArtifactRef.from_json(item) for item in question["artifacts"]]
                evidence = question.get("evidence", {})
                verdict = BuildGate.locked(
                    artifacts,
                    lambda artifact: EvidenceSet.from_json(evidence[artifact.subject_id]),
                    policy,
                    clock,
                    **keywords,
                )
                return cls._gate(verdict, out)
            if args.release:
                provenance = question.get("provenance")
                verdict = BuildGate.release(
                    ArtifactRef.from_json(question["artifact"]),
                    Provenance.from_json(provenance) if provenance is not None else None,
                    policy,
                    clock,
                    sbom=bool(question.get("sbom", False)),
                    evidence=EvidenceSet.from_json(question["evidence"])
                    if "evidence" in question
                    else None,
                    **keywords,
                )
                return cls._gate(verdict, out)
            decision = PointRuntime.ask(
                args.point,
                ArtifactRef.from_json(question["artifact"]),
                EvidenceSet.from_json(question.get("evidence", {})),
                policy,
                clock,
                actor=context.actor,
                relation=context.relation,
                online=context.online,
                bundle_age_s=context.bundle_age_s,
                intel_age_s=context.intel_age_s,
                **keywords,
            )
        except (ValueError, KeyError, TypeError, DecisionError) as problem:
            raise ConfigError(
                f"the question is not one the decision function can read: {problem}"
            ) from problem
        out.write(json.dumps(decision.to_json(), sort_keys=True) + "\n")
        return int(ExitCode.CLEAN)

    @staticmethod
    def _gate(verdict: Any, out: TextIO) -> int:
        document = {
            "state": verdict.state,
            "passes": verdict.passes,
            "decisions": [
                {"subject": artifact.subject_id, "decision": decision.to_json()}
                for artifact, decision in verdict.decisions
            ],
        }
        out.write(json.dumps(document, sort_keys=True) + "\n")
        return int(ExitCode.CLEAN if verdict.passes else ExitCode.FINDINGS)
