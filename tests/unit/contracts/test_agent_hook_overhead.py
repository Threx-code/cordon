"""The pre-tool hook's own overhead stays under 300 ms at the 95th percentile.

One thousand hook calls are made through `AgentHook.respond` against a fixture policy with a local bundle and no network: a mix of the four gated calls, allowed and denied, each with a fresh
decision (the policy's cache is not warmed by a repeat). The time of each call is taken with a monotonic clock; the 95th percentile of the thousand must be under the budget.

Measured record (the machine is written into the failure message of the test below):
    n = 1000 calls, p95 = 4.5 ms (4.46 and 4.74 in two runs; max 11.7 ms), machine = aarch64 Linux container, 12 cpus, python 3.12.14
The budget is 300 ms. This is the hook function with a local bundle, not the start of the agent process that runs it.
"""

from __future__ import annotations

import os
import platform
import time
from pathlib import Path
from typing import Any

from test_agent_hook import APPROVER, DENY, Scan, World

from cordon_scanner.cloud.agent_hook import AgentHook
from kits.bundle_kit import T0

BUDGET_MS = 300.0
CALLS = 1000
COMMANDS = (
    ("Bash", {"command": "npm install left-pad@{n}.0.0"}),
    ("Bash", {"command": "pip install requests=={n}"}),
    ("Bash", {"command": "claude mcp add files{n} -- npx -y @acme/files{n}"}),
    ("Skill", {"skill": "pdf-tools-{n}"}),
    ("Bash", {"command": "ls -la build{n}"}),
)


class Timing:
    @staticmethod
    def machine() -> str:
        return f"{platform.machine()} {platform.system()} {os.cpu_count()} cpus, python {platform.python_version()}"

    @staticmethod
    def p95(samples: list[float]) -> float:
        ordered = sorted(samples)
        return ordered[int(len(ordered) * 0.95) - 1]

    @staticmethod
    def hook(tool: str, template: dict[str, str], n: int) -> dict[str, Any]:
        return World.hook(tool, **{key: value.format(n=n) for key, value in template.items()})


class TestTheHookOverhead:
    def test_the_95th_percentile_of_a_thousand_calls_is_under_the_budget(
        self, tmp_path: Path
    ) -> None:
        scan = Scan()
        runtime, store = World.build(tmp_path, scan, DENY)
        samples: list[float] = []
        for n in range(CALLS):
            tool, template = COMMANDS[n % len(COMMANDS)]
            scan.category = "suspicious" if n % 3 == 0 else None
            hook_input = Timing.hook(tool, template, n)
            start = time.perf_counter_ns()
            AgentHook.respond(
                runtime, store, hook_input, T0, environment="production", approver=APPROVER
            )
            samples.append((time.perf_counter_ns() - start) / 1e6)
        p95 = Timing.p95(samples)
        print(
            f"hook overhead: n={len(samples)} p95={p95:.2f} ms max={max(samples):.2f} ms on {Timing.machine()}"
        )
        assert len(samples) == CALLS
        assert p95 < BUDGET_MS, f"p95 {p95:.1f} ms is over {BUDGET_MS} ms on {Timing.machine()}"
