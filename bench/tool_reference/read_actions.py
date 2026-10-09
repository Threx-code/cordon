"""GitHub's own dependency graph (its SBOM API) for each repository's workflows and actions."""

import json
import time
import urllib.request
from pathlib import Path

for index in json.loads(Path("/data/actions/index.json").read_text(encoding="utf-8")):
    repo = index["repo"]
    folder = Path("/data/actions") / repo.replace("/", "__") / ".reference"
    folder.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/dependency-graph/sbom",
        headers={"User-Agent": "cordon-bench", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            sbom = json.load(response)
        packages = [
            p
            for p in sbom["sbom"]["packages"]
            if "pkg:githubactions/" in json.dumps(p.get("externalRefs", []))
        ]
        (folder / "sbom.json").write_text(json.dumps(packages, indent=1), encoding="utf-8")
    except Exception as exc:
        (folder / "sbom.json").write_text(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"[:200]}), encoding="utf-8"
        )
    time.sleep(2)
