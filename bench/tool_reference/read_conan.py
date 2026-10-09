"""Conan's own reading of conanfile.txt and conan.lock."""

import json
from pathlib import Path

from conans.client.loader import ConanFileTextLoader as Loader

for repo in sorted(Path("/data/conan").iterdir()):
    if not repo.is_dir():
        continue
    out = {}
    for path in repo.rglob("conanfile.txt"):
        rel = path.relative_to(repo).as_posix()
        try:
            loader = Loader(path.read_text(encoding="utf-8-sig"))
            out[rel] = {
                "requires": list(loader.requirements),
                "tool_requires": list(loader.tool_requirements),
                "test_requires": list(getattr(loader, "test_requirements", [])),
            }
        except Exception as exc:
            out[rel] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    for path in repo.rglob("conan.lock"):
        rel = path.relative_to(repo).as_posix()
        try:
            lock = json.loads(
                path.read_text(encoding="utf-8-sig")
            )  # as Conan's own load() reads it
            out[rel] = {
                k: lock.get(k, []) for k in ("requires", "build_requires", "python_requires")
            }
            # Conan 1 (lock 0.4): the graph's nodes, each with its reference; node 0 is the consumer.
            nodes = (lock.get("graph_lock") or {}).get("nodes") or {}
            out[rel]["requires"] += [
                n["ref"] for k, n in nodes.items() if k != "0" and n.get("ref")
            ]
        except Exception as exc:
            out[rel] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    (repo / ".reference").mkdir(exist_ok=True)
    (repo / ".reference" / "conan.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
