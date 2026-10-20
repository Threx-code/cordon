"""The tool-call guard (`cordon_scanner.judge.calls`) on AgentDefense's tool calls.

    docker run --rm --network none -v cordon-bench-public:/p:ro -v "$PWD:/w:ro" -w /w \\
      -e PYTHONPATH=/w/src python:3.12-slim python bench/tool_call_guard.py /p/agentdefense

Three sets, reported apart because they test different things:

* attacks with content: `attacks/{combined_attacks,encoding_attacks,novel_2024_2025,mcpsecbench}`
  -- the payload is in the arguments (`$(whoami)`, base64 SQL, `/etc/passwd`, `__proto__`);
* `tool_poisoning/tool_poisoning_attacks.json` -- the attack is named by labels in the arguments
  (`_hidden_payload: "AWS credential exfiltration"`), so what a guard can test there is the hidden
  argument itself, not the behaviour the label describes;
* every benign call: `benign_baseline` and `expanded_benign_operations`, and the benign rows of the
  attack files.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from cordon_scanner.judge.calls import ToolCallGuard


class AgentDefenseCalls:
    CONTENT = ("combined_attacks", "encoding_attacks", "novel_2024_2025", "mcpsecbench")

    @staticmethod
    def _request(record: dict) -> dict:
        return record.get("request") or record.get("mcp_request") or {}

    @classmethod
    def load(cls, root: Path) -> list[tuple[str, str, bool, str, str, dict]]:
        out = []
        for name in cls.CONTENT:
            document = json.loads((root / "attacks" / f"{name}.json").read_text(encoding="utf-8"))
            rows = (
                document.get("attacks")
                or document.get("tests")
                or next(v for v in document.values() if isinstance(v, list))
            )
            for row in rows:
                request = cls._request(row)
                if request.get("method") != "tools/call":
                    continue
                params = request.get("params") or {}
                malicious = str(row.get("expected", "blocked")).lower() in ("blocked", "block")
                out.append(
                    (
                        name,
                        row.get("id", ""),
                        malicious,
                        row.get("subcategory") or row.get("category", ""),
                        params.get("name", ""),
                        params.get("arguments") or {},
                    )
                )
        poisoning = root / "tool_poisoning" / "tool_poisoning_attacks.json"
        for row in json.loads(poisoning.read_text(encoding="utf-8")):
            params = (cls._request(row).get("params")) or {}
            out.append(
                (
                    "tool_poisoning",
                    row.get("id", ""),
                    True,
                    row.get("category", ""),
                    params.get("name", ""),
                    params.get("arguments") or {},
                )
            )
        for path, key in (
            ("benign_baseline/benign_baseline.json", None),
            ("benign_baseline/expanded_benign_operations.json", "tests"),
        ):
            file = root / path
            if not file.is_file():
                continue
            rows = json.loads(file.read_text(encoding="utf-8"))
            for row in rows[key] if key else rows:
                params = (cls._request(row).get("params")) or {}
                out.append(
                    (
                        "benign",
                        row.get("id", ""),
                        False,
                        row.get("category", ""),
                        params.get("name", ""),
                        params.get("arguments") or {},
                    )
                )
        consolidated = root / "consolidated" / "benign_tests.json"
        if consolidated.is_file():
            document = json.loads(consolidated.read_text(encoding="utf-8"))
            rows = (
                document
                if isinstance(document, list)
                else next(v for v in document.values() if isinstance(v, list))
            )
            for row in rows:
                # Prompts written to look alarming and be harmless ("How can I kill a Python
                # process?"), passed as the argument a chat or search tool would get.
                out.append(
                    (
                        "benign",
                        row.get("id", ""),
                        False,
                        row.get("category", ""),
                        "ask",
                        {"query": row.get("prompt", "")},
                    )
                )
        return out


class GuardBench:
    @staticmethod
    def main() -> None:
        calls = AgentDefenseCalls.load(Path(sys.argv[1]))
        tally: Counter = Counter()
        missed: Counter = Counter()
        flagged_benign = []
        for group, ident, malicious, category, name, arguments in calls:
            verdict = ToolCallGuard.check(name, arguments)
            kind = (
                "benign"
                if not malicious
                else ("labels" if group == "tool_poisoning" else "content")
            )
            tally[(kind, verdict.blocked)] += 1
            if malicious and not verdict.blocked:
                missed[(group, category)] += 1
                if group != "tool_poisoning" and "--show" in sys.argv:
                    print("  MISS", group, category, name, json.dumps(arguments)[:160])
            if not malicious and verdict.blocked:
                flagged_benign.append(
                    (
                        group,
                        ident,
                        name,
                        [f.rule for f in verdict.findings],
                        json.dumps(arguments)[:140],
                    )
                )
        for kind in ("content", "labels", "benign"):
            hit, n = tally[(kind, True)], tally[(kind, True)] + tally[(kind, False)]
            word = "flagged" if kind == "benign" else "blocked"
            print(f"{kind:8} {word} {hit}/{n} ({100 * hit / max(n, 1):.1f}%)")
        print("missed:", missed.most_common(40))
        for row in flagged_benign:
            print("  BENIGN FLAGGED", row)


if __name__ == "__main__":
    GuardBench.main()
