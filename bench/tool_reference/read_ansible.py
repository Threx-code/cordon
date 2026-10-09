"""ansible-galaxy's own reading of each requirements file (GalaxyCLI._parse_requirements_file)."""

import json
from pathlib import Path

from ansible.cli.galaxy import GalaxyCLI
from ansible.galaxy.collection.concrete_artifact_manager import _get_meta_from_src_dir

cli = GalaxyCLI(["ansible-galaxy", "install", "-r", "x"])
cli.parse()
# What `ansible-galaxy install` sets up before reading a requirements file: its role reader
# needs the Galaxy context.
from ansible.galaxy import Galaxy  # noqa: E402
from ansible.galaxy.collection.concrete_artifact_manager import ConcreteArtifactsManager  # noqa: E402

cli.galaxy = Galaxy()
cli.lazy_role_api = None
artifacts = ConcreteArtifactsManager(b"/tmp/galaxy-artifacts", validate_certs=False)
for repo in sorted(Path("/data/ansible").iterdir()):
    if not repo.is_dir():
        continue
    out = {}
    for path in [*repo.rglob("requirements.yml"), *repo.rglob("requirements.yaml")]:
        if ".reference" in path.parts:
            continue
        rel = path.relative_to(repo).as_posix()
        try:
            parsed = cli._parse_requirements_file(
                str(path), artifacts_manager=artifacts, validate_signature_options=False
            )
            out[rel] = {
                "collections": [
                    {"name": r.fqcn, "version": r.ver, "src": str(r.src), "type": r.type}
                    for r in parsed.get("collections", [])
                ],
                "roles": [
                    {"name": r.name, "version": r.version, "src": r.src}
                    for r in parsed.get("roles", [])
                ],
            }
        except Exception as exc:
            out[rel] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    for path in repo.rglob("galaxy.yml"):
        if ".reference" in path.parts:
            continue
        rel = path.relative_to(repo).as_posix()
        try:
            meta = _get_meta_from_src_dir(str(path.parent).encode())
            out[rel] = {
                "collections": [
                    {"name": n, "version": v, "type": "galaxy"}
                    for n, v in (meta.get("dependencies") or {}).items()
                ],
                "roles": [],
            }
        except Exception as exc:
            out[rel] = {"error": f"{type(exc).__name__}: {exc}"[:200]}
    (repo / ".reference").mkdir(exist_ok=True)
    (repo / ".reference" / "ansible.json").write_text(
        json.dumps(out, indent=1, default=str), encoding="utf-8"
    )
