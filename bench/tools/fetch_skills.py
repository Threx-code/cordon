#!/usr/bin/env python3
"""The real-world agent-skill corpus: what popular public skill repositories actually ship.

A skill is a directory holding a `SKILL.md` and whatever scripts and references sit beside it.
This lists the most-starred public repositories under skill-related GitHub topics, downloads each
one's archive once, and keeps every skill directory in it -- as text, never run. The corpus is
split by a hash of the repository name, as `fetch_agent_configs.py` splits its own: one half to
calibrate against, the other held out to measure false alarms on, so the number reported was not
used to tune anything.

    python bench/tools/fetch_skills.py --out corpus-dir
    python bench/tools/fetch_skills.py --out corpus-dir --half evaluate     # list that half

Run inside a container with network. `GITHUB_TOKEN`, when set, raises the search API's limit.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fetch_agent_configs import AgentConfigCorpus

TOPICS = (
    "claude-skills",
    "agent-skills",
    "claude-code-skills",
    "claude-skill",
    "skills",
    "ai-skills",
    "anthropic-skills",
    "skill-md",
    "codex-skills",
)
MAX_ARCHIVE = 64 << 20
MAX_FILE = 1 << 20
TEXT = (".md", ".py", ".sh", ".js", ".ts", ".mjs", ".json", ".yaml", ".yml", ".txt", ".toml", ".rb", ".ps1", ".bash")  # fmt: skip


class SkillCorpus:
    @staticmethod
    def headers() -> dict[str, str]:
        found = {"User-Agent": "cordon-skill-study", "Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            found["Authorization"] = f"Bearer {token}"
        return found

    @staticmethod
    def repositories() -> list[tuple[str, str]]:
        found: set[tuple[str, str]] = set()
        for topic in TOPICS:
            for page in range(1, 11):
                url = (
                    "https://api.github.com/search/repositories"
                    f"?q=topic:{topic}&sort=stars&order=desc&per_page=100&page={page}"
                )
                items: list[dict[str, object]] = []
                for _ in range(6):
                    try:
                        request = urllib.request.Request(url, headers=SkillCorpus.headers())
                        with urllib.request.urlopen(request, timeout=30) as response:
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
                time.sleep(2.5)
                if len(items) < 100:
                    break
        return sorted(found)

    @staticmethod
    def fetch(out: Path, repository: str, branch: str) -> int:
        """Every skill directory of the repository, as text files; how many were kept."""
        url = f"https://codeload.github.com/{repository}/tar.gz/{branch}"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "cordon-skill-study"})
            with urllib.request.urlopen(request, timeout=120) as response:
                body = response.read(MAX_ARCHIVE + 1)
        except (urllib.error.URLError, TimeoutError, OSError):
            return 0
        if len(body) > MAX_ARCHIVE:
            return 0
        files: dict[str, bytes] = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                for member in archive:
                    if member.isfile() and member.size <= MAX_FILE:
                        handle = archive.extractfile(member)
                        if handle is not None:
                            files[member.name.split("/", 1)[-1]] = handle.read()
        except (tarfile.TarError, EOFError, OSError):
            return 0
        skills = {
            path.rsplit("/", 1)[0] if "/" in path else ""
            for path in files
            if path.rsplit("/", 1)[-1] == "SKILL.md"
        }
        kept = 0
        for skill in sorted(skills):
            prefix = f"{skill}/" if skill else ""
            target = (
                out
                / "skills"
                / f"{repository.replace('/', '__')}__{skill.replace('/', '__') or 'root'}"
            )
            for path, data in files.items():
                if path.startswith(prefix) and path.lower().endswith(TEXT):
                    destination = target / path[len(prefix) :]
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
            kept += 1
        return kept

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--half", choices=("calibrate", "evaluate"))
        args = parser.parse_args()
        if args.half:
            for skill in sorted((args.out / "skills").iterdir()):
                repository = "/".join(skill.name.split("__")[:2])
                if AgentConfigCorpus.half_of(repository) == args.half:
                    print(skill)
            return 0
        repos = SkillCorpus.repositories()
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "repos.json").write_text(json.dumps(repos), encoding="utf-8")
        with ThreadPoolExecutor(8) as pool:
            kept = sum(pool.map(lambda job: SkillCorpus.fetch(args.out, *job), repos))
        print(f"{len(repos)} repositories, {kept} skills")
        return 0


if __name__ == "__main__":
    sys.exit(SkillCorpus.main())
