"""conda's own reading of each environment file (conda.env.env.from_file)."""

import json
from pathlib import Path

from conda.env.env import from_file
from conda.models.match_spec import MatchSpec

for repo in sorted(Path("/data/conda").iterdir()):
    if not repo.is_dir():
        continue
    out = {}
    for path in [*repo.rglob("environment.yml"), *repo.rglob("environment.yaml")]:
        if ".reference" in path.parts:
            continue
        rel = path.relative_to(repo).as_posix()
        try:
            env = from_file(str(path))
            deps = env.dependencies
            out[rel] = {
                "conda": [{"name": MatchSpec(s).name, "spec": s} for s in deps.get("conda", [])],
                "pip": list(deps.get("pip", [])),
            }
        except Exception as exc:
            out[rel] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    (repo / ".reference").mkdir(exist_ok=True)
    (repo / ".reference" / "conda.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
