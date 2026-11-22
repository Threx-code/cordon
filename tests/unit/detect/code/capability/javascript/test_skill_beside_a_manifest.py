"""What the agent is told to run is a skill's script; the rest of a package that ships a SKILL.md is the package's own code.

A skill's scripts run when the agent uses the skill, unasked, so they take the install grade (a detached
child there is `MALWARE.INSTALL.BACKGROUND.001`, critical). `LoadPath.skill_script` called a script a skill's
when a `SKILL.md` stood up to four directories above it, and a published MCP server that ships a usage
`SKILL.md` beside its `package.json` was then judged entirely as install-time code: its `dist/index.js`, its
detached editor launch, its release script, a handler that shells out to its own terminal. Where a package
manifest sits in the SKILL.md's folder, a script is the skill's when the SKILL.md names it (its path or its
file name) or it sits in the conventional `scripts/` folder; the setup a skill tells the agent to run is
still read as install code. A skill with no manifest, or under `skills/<name>/`, is unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from cordon_scanner import Scanner
from cordon_scanner.detect.code.capability.load_path import LoadPath
from cordon_scanner.foundation.config.settings import Config

BACKGROUND = "MALWARE.INSTALL.BACKGROUND.001"
SKILL = "---\nname: tool\ndescription: How to use the tool.\n---\nUse the tool.\n"
DETACHED = (
    "import { spawn } from 'node:child_process';\n"
    "export function startWorker() {\n"
    "  const child = spawn(process.execPath, ['worker.js'], { detached: true, stdio: 'ignore' });\n"
    "  child.unref();\n"
    "}\n"
)


class Tree:
    @staticmethod
    def write(root: Path, files: dict[str, str]) -> Path:
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    @staticmethod
    def manifest(main: str) -> str:
        return json.dumps({"name": "tool", "version": "1.0.0", "main": main, "bin": {"tool": main}})

    @staticmethod
    def background(root: Path) -> bool:
        return bool(Tree.background_paths(root))

    @staticmethod
    def background_paths(root: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return {
            f.location.path.removeprefix(str(root).rstrip("/") + "/")
            for f in result.findings
            if f.rule_id == BACKGROUND
        }

    @staticmethod
    def skill_script(path: str, *others: str, named: tuple[str, ...] = ()) -> bool:
        tree = SimpleNamespace(
            tree_paths=frozenset((path, *others)), skill_named_paths=frozenset(named)
        )
        return LoadPath.skill_script(path, tree)  # type: ignore[arg-type]


class TestAPackageThatShipsASkillDocument:
    def test_the_packages_own_entry_is_not_a_skill_script(self, tmp_path):
        root = Tree.write(
            tmp_path,
            {
                "package.json": Tree.manifest("dist/index.js"),
                "SKILL.md": SKILL,
                "dist/index.js": DETACHED,
            },
        )
        assert not Tree.background(root)

    def test_nothing_beside_the_manifest_below_the_document_is_one_either(self):
        tree = ("package.json", "SKILL.md", "dist/index.js", "src/a.py", "lib/deep/er/x.js")
        for path in ("dist/index.js", "src/a.py", "lib/deep/er/x.js", "index.js"):
            assert not Tree.skill_script(path, *tree)

    def test_a_python_package_with_a_skill_document_is_not_a_skill_either(self):
        tree = ("pyproject.toml", "SKILL.md", "pkg/__init__.py", "pkg/api.py")
        assert not Tree.skill_script("pkg/api.py", *tree)
        assert not Tree.skill_script("pkg/__init__.py", *tree)

    def test_the_scripts_folder_still_ships_a_skills_scripts(self, tmp_path):
        assert Tree.skill_script("scripts/run.js", "package.json", "SKILL.md", "scripts/run.js")
        root = Tree.write(
            tmp_path,
            {
                "package.json": Tree.manifest("scripts/run.js"),
                "SKILL.md": SKILL,
                "scripts/run.js": DETACHED,
            },
        )
        assert Tree.background(root)


class TestWhatTheSkillDocumentNames:
    def test_a_script_the_document_tells_the_agent_to_run_is_the_skills(self, tmp_path):
        files = {
            "package.json": Tree.manifest("dist/index.js"),
            "SKILL.md": SKILL + "Run `node dist/setup.js` once before the first use.\n",
            "dist/index.js": DETACHED,
            "dist/setup.js": DETACHED,
        }
        names = Tree.background_paths(Tree.write(tmp_path, files))
        assert names == {"dist/setup.js"}, names

    def test_a_script_named_by_its_file_name_alone_is_the_skills(self, tmp_path):
        files = {
            "package.json": Tree.manifest("dist/index.js"),
            "SKILL.md": SKILL + "Start the helper with helper.js, then use the tool.\n",
            "dist/index.js": DETACHED,
            "tools/helper.js": DETACHED,
        }
        assert Tree.background_paths(Tree.write(tmp_path, files)) == {"tools/helper.js"}

    def test_a_name_that_is_only_part_of_a_longer_one_does_not_count(self, tmp_path):
        files = {
            "package.json": Tree.manifest("dist/index.js"),
            "SKILL.md": SKILL + "See my-helper.js.map and reindex.json for the layout.\n",
            "dist/index.js": DETACHED,
            "tools/helper.js": DETACHED,
        }
        assert not Tree.background(Tree.write(tmp_path, files))

    def test_a_script_the_document_never_names_is_the_packages_own(self, tmp_path):
        files = {
            "package.json": Tree.manifest("dist/index.js"),
            "SKILL.md": SKILL + "Run `node dist/setup.js` once before the first use.\n",
            "dist/index.js": DETACHED,
            "dist/setup.js": "console.log('ready');\n",
        }
        assert not Tree.background(Tree.write(tmp_path, files))


class TestASkillThatIsNotAPackage:
    def test_a_skill_with_no_manifest_keeps_its_scripts_beside_and_below_it(self, tmp_path):
        assert Tree.skill_script("helper.js", "SKILL.md", "helper.js")
        assert Tree.skill_script("a/b/tool.py", "SKILL.md", "a/b/tool.py")
        root = Tree.write(tmp_path, {"SKILL.md": SKILL, "helper.js": DETACHED})
        assert Tree.background(root)

    def test_a_skills_folder_is_a_skills_whatever_else_is_at_the_root(self, tmp_path):
        assert Tree.skill_script(
            "skills/tool/index.js", "package.json", "skills/tool/SKILL.md", "skills/tool/index.js"
        )
        root = Tree.write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "bundle", "version": "1.0.0"}),
                "skills/tool/SKILL.md": SKILL,
                "skills/tool/index.js": DETACHED,
            },
        )
        assert Tree.background(root)

    def test_a_skill_folder_inside_a_package_that_has_its_own_manifest_is_still_a_skill(self):
        paths = ("package.json", "plugin/SKILL.md", "plugin/helper.js")
        assert Tree.skill_script("plugin/helper.js", *paths)
