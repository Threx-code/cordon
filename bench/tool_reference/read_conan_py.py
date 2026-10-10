"""Conan 2's own evaluation of each conanfile.py: the recipe loaded as `conan graph info` loads its
root, and configured as the graph builder configures it (`run_configure_method`, which runs
requirements() and build_requirements()) -- without resolving anything, so no remote is needed.
A requirement chosen by `if self.settings.os == ...` depends on the profile, so each recipe is
evaluated for Linux, Windows and macOS and the requirements of all three are kept.

A recipe is Python, so this runs sandboxed (sandbox.sh): no network, the files read-only, each
recipe evaluated in a copy."""

import json
import shutil
import tempfile
import traceback
from pathlib import Path

from conan.api.conan_api import ConanAPI

try:  # where Conan 2.20 and later keep them
    from conan.internal.methods import run_configure_method
    from conan.internal.model.options import Options
except ImportError:  # earlier 2.x
    from conans.client.conanfile.configure import run_configure_method
    from conans.model.options import Options

api = ConanAPI()


class Conan2:
    @staticmethod
    def requirements(recipe: Path, system: str) -> list[dict[str, object]]:
        host = api.profiles.get_profile([api.profiles.get_default_host()])
        build = api.profiles.get_profile([api.profiles.get_default_build()])
        host.settings["os"] = system
        node = api.graph._load_root_consumer_conanfile(str(recipe), host, build)
        run_configure_method(node.conanfile, Options(), host.options, None)
        return [
            {"ref": str(r.ref), "build": bool(r.build), "test": bool(r.test)}
            for r in node.conanfile.requires.values()
        ]


out_root = Path("/out/conan")
for repo in sorted(Path("/data/conan").iterdir()):
    if not repo.is_dir():
        continue
    out: dict[str, object] = {}
    for recipe in repo.rglob("conanfile.py"):
        if ".reference" in recipe.parts:
            continue
        rel = recipe.relative_to(repo).as_posix()
        work = Path(tempfile.mkdtemp())
        shutil.copytree(recipe.parent, work / "r", dirs_exist_ok=True)
        found: dict[str, dict[str, object]] = {}
        errors = []
        for system in ("Linux", "Windows", "Macos"):
            try:
                for requirement in Conan2.requirements(work / "r" / "conanfile.py", system):
                    found.setdefault(str(requirement["ref"]), requirement)
            except Exception:
                errors.append(f"{system}: {traceback.format_exc(limit=1)[-300:]}")
        out[rel] = {"requires": list(found.values()), "errors": errors}
        shutil.rmtree(work, ignore_errors=True)
    (out_root / repo.name).mkdir(parents=True, exist_ok=True)
    (out_root / repo.name / "conan_py.json").write_text(
        json.dumps(out, indent=1, default=str), encoding="utf-8"
    )
