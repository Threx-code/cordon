"""The move tool (`scripts/move_modules.py`): references follow a module, nothing else changes."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from support import ROOT as REPO

SCRIPT = REPO / "scripts" / "move_modules.py"
_spec = importlib.util.spec_from_file_location("move_modules", SCRIPT)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
Moves = _mod.Moves

MOVES = {"core/models": "foundation/models", "core/engine": "engine/engine"}


class TestRewrite:
    def test_imports_of_every_form(self) -> None:
        text = (
            "from cordon_scanner.core.models import Finding\n"
            "import cordon_scanner.core.models as m\n"
            "from cordon_scanner.core import models\n"
        )
        assert Moves.rewrite_python(text, MOVES) == (
            "from cordon_scanner.foundation.models import Finding\n"
            "import cordon_scanner.foundation.models as m\n"
            "from cordon_scanner.foundation import models\n"
        )

    def test_one_from_split_by_where_its_names_went(self) -> None:
        text = "def f():\n    from cordon_scanner.core import models, engine, cache\n"
        assert Moves.rewrite_python(text, MOVES) == (
            "def f():\n"
            "    from cordon_scanner.foundation import models\n"
            "    from cordon_scanner.engine import engine\n"
            "    from cordon_scanner.core import cache\n"
        )

    def test_a_patch_target_string_follows(self) -> None:
        text = 'mock.patch("cordon_scanner.core.engine.Engine.scan")\n'
        assert Moves.rewrite_python(text, MOVES) == (
            'mock.patch("cordon_scanner.engine.engine.Engine.scan")\n'
        )

    def test_a_longer_name_and_comments_are_left_alone(self) -> None:
        text = (
            "# cordon_scanner.core.models moved\n"
            "from cordon_scanner.core.models_extra import X\n"
            'x = "cordon_scanner.core.modelsX"\n'
        )
        assert Moves.rewrite_python(text, MOVES) == text

    def test_entry_points(self) -> None:
        text = 'engine = "cordon_scanner.core.engine:Engine"\n'
        assert Moves.rewrite_text(text, MOVES) == 'engine = "cordon_scanner.engine.engine:Engine"\n'


class TestShim:
    def test_the_old_path_is_the_same_module(self, tmp_path: Path) -> None:
        pkg = tmp_path / "cordon_scanner"
        (pkg / "core").mkdir(parents=True)
        (pkg / "foundation").mkdir()
        for d in (pkg, pkg / "core", pkg / "foundation"):
            (d / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "foundation" / "models.py").write_text("_private = 1\n", encoding="utf-8")
        (pkg / "core" / "models.py").write_text(
            Moves.shim("core/models", "foundation/models", "0.8.0"), encoding="utf-8"
        )
        code = (
            "import cordon_scanner.foundation.models as new\n"
            "from cordon_scanner.core import models as old\n"
            "from cordon_scanner.core.models import _private\n"
            "assert old is new and _private == 1\n"
        )
        done = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                f"import sys; sys.path.insert(0, {str(tmp_path)!r})\n{code}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stderr


class TestHeldFiles:
    def test_a_held_file_is_left_alone_then_followed(self, tmp_path: Path) -> None:
        TestRun.repository(tmp_path)
        src = tmp_path / "src" / "cordon_scanner"
        held = src / "core" / "user.py"
        Moves.run("foundation", "0.8.0", tmp_path, skip=frozenset({held}))
        assert held.read_text(encoding="utf-8") == "from cordon_scanner.core.models import X\n"
        assert Moves.follow([held], tmp_path) == [held]
        assert held.read_text(encoding="utf-8") == (
            "from cordon_scanner.foundation.models import X\n"
        )


class TestRun:
    @staticmethod
    def repository(tmp_path: Path) -> None:
        src = tmp_path / "src" / "cordon_scanner"
        (src / "core").mkdir(parents=True)
        (tmp_path / "tests" / "unit").mkdir(parents=True)
        for folder in ("bench", "scripts"):
            (tmp_path / folder).mkdir()
        (src / "__init__.py").write_text("", encoding="utf-8")
        (src / "core" / "__init__.py").write_text("", encoding="utf-8")
        (src / "core" / "models.py").write_text("X = 1\n", encoding="utf-8")
        (src / "core" / "user.py").write_text(
            "from cordon_scanner.core.models import X\n", encoding="utf-8"
        )
        (tmp_path / "pyproject.toml").write_text(
            'a = "cordon_scanner.core.models:X"\n', encoding="utf-8"
        )
        (tmp_path / "tests" / "unit" / "test_models.py").write_text("X = 2\n", encoding="utf-8")
        (tmp_path / "tests" / "unit" / "test_user.py").write_text(
            "from unit.test_models import X\n", encoding="utf-8"
        )
        layout = {
            "modules": {"core/models": "foundation/models", "core/user": "core/user"},
            "tests": {"test_models.py": "foundation", "test_user.py": ""},
        }
        (tmp_path / "tests" / "unit" / "package_layout.json").write_text(
            json.dumps(layout), encoding="utf-8"
        )
        for args in (
            ["init", "-q"],
            ["add", "."],
            ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"],
        ):
            subprocess.run(["git", *args], cwd=tmp_path, check=True)

    def test_a_move_in_a_repository(self, tmp_path: Path) -> None:
        TestRun.repository(tmp_path)
        src = tmp_path / "src" / "cordon_scanner"
        moved, tests = Moves.run("foundation", "0.8.0", tmp_path)
        assert moved == {"core/models": "foundation/models"}
        assert tests == {"test_models.py": "foundation"}
        unit = tmp_path / "tests" / "unit"
        assert (unit / "foundation" / "test_models.py").is_file()
        assert not (unit / "test_models.py").exists()
        assert (unit / "test_user.py").read_text(encoding="utf-8") == (
            "from unit.foundation.test_models import X\n"
        )
        assert (src / "foundation" / "models.py").read_text(encoding="utf-8") == "X = 1\n"
        assert (src / "core" / "user.py").read_text(encoding="utf-8") == (
            "from cordon_scanner.foundation.models import X\n"
        )
        assert "foundation.models:X" in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
        after = json.loads(
            (tmp_path / "tests" / "unit" / "package_layout.json").read_text(encoding="utf-8")
        )
        assert after["modules"] == {
            "core/user": "core/user",
            "foundation/models": "foundation/models",
        }
        assert after["shims"] == {"core/models": {"to": "foundation/models", "until": "0.8.0"}}
