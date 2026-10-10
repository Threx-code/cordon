"""Conan 1's own evaluation of each conanfile.py Conan 2 cannot load (`from conans import ...`):
the recipe loaded as `conan info` loads its consumer (`loader.load_consumer` with a profile), its
requirements() run, and its build_requirements() run through Conan's own
`GraphManager._get_recipe_build_requires` -- without resolving anything, so no remote is needed.
Evaluated for Linux, Windows and macOS, the requirements of all three kept.

A recipe is Python, so this runs sandboxed (sandbox.sh): no network, the files read-only, each
recipe evaluated in a copy. Writes conan1_py.json beside the Conan 2 results."""

import json
import shutil
import tempfile
import traceback
from pathlib import Path

from conans.client.conan_api import Conan
from conans.client.graph.graph import CONTEXT_BUILD
from conans.client.graph.graph_manager import GraphManager
from conans.client.profile_loader import profile_from_args

api = Conan()
api.create_app()
app = api.app


class Conan1:
    @staticmethod
    def requirements(recipe: Path, system: str) -> list[dict[str, object]]:
        profile = profile_from_args(
            None, [f"os={system}"], None, None, None, str(recipe.parent), app.cache
        )
        profile.process_settings(app.cache)
        conanfile = app.loader.load_consumer(str(recipe), profile)
        if hasattr(conanfile, "requirements"):
            conanfile.requirements()
        found = [
            {"ref": str(r.ref), "build": False, "test": False} for r in conanfile.requires.values()
        ]
        for (_name, _context), reference in GraphManager._get_recipe_build_requires(
            conanfile, CONTEXT_BUILD
        ).items():
            test = bool(getattr(reference, "force_host_context", False))
            found.append({"ref": str(reference), "build": not test, "test": test})
        return found


out_root = Path("/out/conan")
for repo in sorted(Path("/data/conan").iterdir()):
    if not repo.is_dir():
        continue
    previous = out_root / repo.name / "conan_py.json"
    failed = {
        rel
        for rel, result in (
            json.loads(previous.read_text(encoding="utf-8")).items() if previous.exists() else ()
        )
        if result.get("errors") and not result.get("requires")
    }
    out: dict[str, object] = {}
    for rel in sorted(failed):
        recipe = repo / rel
        work = Path(tempfile.mkdtemp())
        shutil.copytree(recipe.parent, work / "r", dirs_exist_ok=True)
        found: dict[str, dict[str, object]] = {}
        errors = []
        for system in ("Linux", "Windows", "Macos"):
            try:
                for requirement in Conan1.requirements(work / "r" / "conanfile.py", system):
                    found.setdefault(str(requirement["ref"]), requirement)
            except Exception:
                errors.append(f"{system}: {traceback.format_exc(limit=1)[-300:]}")
        out[rel] = {"requires": list(found.values()), "errors": errors}
        shutil.rmtree(work, ignore_errors=True)
    (out_root / repo.name).mkdir(parents=True, exist_ok=True)
    (out_root / repo.name / "conan1_py.json").write_text(
        json.dumps(out, indent=1, default=str), encoding="utf-8"
    )
