#!/usr/bin/env python3
"""The real-world agent-configuration corpus: what popular agent repositories actually commit.

Lists the most-starred public repositories under agent-related GitHub topics, then fetches, as
text, the agent files each one commits -- instruction files, MCP configurations, agent settings.
Nothing fetched is run. The corpus is split by a hash of the repository name: one half calibrates
how noisy each Agent Threat Rule is on real instruction files (`scripts/import_atr.py
--instruction-corpus`), the other half is held out to measure false alarms, so the number reported
was not used to tune anything.

    python bench/fetch_agent_configs.py --out corpus-dir
    python bench/fetch_agent_configs.py --out corpus-dir --half calibrate   # print that half

Unauthenticated: the GitHub search API allows ten requests a minute, which this paces to.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TOPICS = (
    "mcp-server",
    "model-context-protocol",
    "mcp",
    "claude-code",
    "cursor",
    "ai-agents",
    "coding-agent",
    "llm-agent",
    "agentic-ai",
    "claude",
    "copilot",
    "ai-coding",
)
PATHS = (
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".claude/settings.json",
    ".gemini/settings.json",
)
INSTRUCTION_FILES = frozenset(
    {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
     "copilot-instructions.md"}
)  # fmt: skip
_HEADERS = {"User-Agent": "cordon-agent-config-study", "Accept": "application/vnd.github+json"}


def half_of(repository: str) -> str:
    """`calibrate` or `evaluate`, fixed by the repository's name."""
    digest = hashlib.sha256(repository.encode("utf-8")).digest()
    return "calibrate" if digest[0] % 2 == 0 else "evaluate"


FRESH_TOPICS = (
    "langchain",
    "llamaindex",
    "rag",
    "openai",
    "gemini",
    "anthropic",
    "chatgpt",
    "llm",
    "generative-ai",
    "ai-assistant",
    "autonomous-agents",
    "vscode-extension",
)
"""Topics for a fresh corpus that shares no repository with the first: what a number is measured
on after the first corpus has been read to understand errors."""


def repositories(topics: tuple[str, ...] = TOPICS) -> list[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for topic in topics:
        for page in range(1, 11):
            url = (
                "https://api.github.com/search/repositories"
                f"?q=topic:{topic}&sort=stars&order=desc&per_page=100&page={page}"
            )
            items: list[dict[str, object]] = []
            for _ in range(6):
                try:
                    with urllib.request.urlopen(
                        urllib.request.Request(url, headers=_HEADERS), timeout=30
                    ) as response:
                        items = json.load(response).get("items", [])
                    break
                except urllib.error.HTTPError as error:
                    if error.code in (403, 429):
                        time.sleep(65)
                        continue
                    break
                except (urllib.error.URLError, TimeoutError, OSError):
                    time.sleep(5)
            found.update(
                (str(i["full_name"]), str(i.get("default_branch") or "HEAD")) for i in items
            )
            time.sleep(6.5)
            if len(items) < 100:
                break
    return sorted(found)


def fetch(out: Path, repository: str, branch: str, path: str) -> bool:
    url = f"https://raw.githubusercontent.com/{repository}/{branch}/{path}"
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": _HEADERS["User-Agent"]}), timeout=20
        ) as response:
            body = response.read(2_000_000)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False
    target = out / "files" / repository.replace("/", "__") / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--half", choices=("calibrate", "evaluate"))
    parser.add_argument("--fresh", action="store_true", help="collect from FRESH_TOPICS instead")
    parser.add_argument(
        "--exclude",
        type=Path,
        help="a repos.json from an earlier corpus; its repositories are skipped",
    )
    args = parser.parse_args()
    if args.half:
        for repo in sorted((args.out / "files").iterdir()):
            if repo.is_dir() and half_of(repo.name.replace("__", "/", 1)) == args.half:
                print(repo)
        return 0
    repos = repositories(FRESH_TOPICS if args.fresh else TOPICS)
    if args.exclude:
        seen = {name for name, _ in json.loads(args.exclude.read_text())}
        repos = [(name, branch) for name, branch in repos if name not in seen]
    (args.out).mkdir(parents=True, exist_ok=True)
    (args.out / "repos.json").write_text(json.dumps(repos))
    jobs = [(r, b, p) for r, b in repos for p in PATHS]
    with ThreadPoolExecutor(12) as pool:
        fetched = sum(pool.map(lambda job: fetch(args.out, *job), jobs))
    print(f"{len(repos)} repositories, {fetched} agent files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
