"""In a published npm package, a publishing script nothing runs for a consumer warns; one that runs blocks.

Review 98 G6: `SUSPECT.REGISTRY.SELF_PUBLISH.001` was the only blocker on 35 benign units -- release
tooling (`tasks/admin/register.js`) and a person-run spam publisher whose `auto.js` nothing requires,
no hook runs and no entry point names (its six labelled siblings adjudicated clause (c), no consumer
payload). Named as `main`, loaded by an entry point, or run by an install hook, it still blocks.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import ClassVar

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.REGISTRY.SELF_PUBLISH.001"
PUBLISHER = (
    "const fs = require('fs');\n"
    "const { exec } = require('child_process');\n"
    "const data = JSON.parse(fs.readFileSync('package.json'));\n"
    "data.name = 'next-' + Date.now();\n"
    "fs.writeFileSync('package.json', JSON.stringify(data));\n"
    "exec('npm publish --access public');\n"
)


class PublishKit:
    @staticmethod
    def severities(tmp_path: Path, manifest: dict, files: dict[str, str]) -> list[Severity]:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            members = {
                "package/package.json": json.dumps({"name": "p", "version": "1.0.0", **manifest})
            }
            for name, text in {**members, **files}.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        findings = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return [f.severity for f in findings if f.rule_id == RULE]


class TestAPublishingScriptNothingRuns:
    def test_it_is_reported_below_the_gate(self, tmp_path: Path) -> None:
        found = PublishKit.severities(
            tmp_path, {"scripts": {"start": "next start"}}, {"package/auto.js": PUBLISHER}
        )
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_a_publishing_command_a_person_runs_is_reported_below_the_gate(
        self, tmp_path: Path
    ) -> None:
        found = PublishKit.severities(
            tmp_path, {"bin": {"pub": "bin/pub.js"}}, {"package/bin/pub.js": PUBLISHER}
        )
        assert found and all(s <= Severity.MEDIUM for s in found)


class TestAPublishingScriptThatRuns:
    def test_as_the_main_entry(self, tmp_path: Path) -> None:
        found = PublishKit.severities(tmp_path, {"main": "auto.js"}, {"package/auto.js": PUBLISHER})
        assert any(s >= Severity.HIGH for s in found)

    def test_loaded_by_the_entry(self, tmp_path: Path) -> None:
        files = {"package/index.js": "require('./lib/auto');\n", "package/lib/auto.js": PUBLISHER}
        found = PublishKit.severities(tmp_path, {}, files)
        assert any(s >= Severity.HIGH for s in found)

    def test_run_by_an_install_hook(self, tmp_path: Path) -> None:
        found = PublishKit.severities(
            tmp_path, {"scripts": {"postinstall": "node auto.js"}}, {"package/auto.js": PUBLISHER}
        )
        assert any(s >= Severity.HIGH for s in found)

    def test_a_source_tree_is_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "auto.js").write_text(PUBLISHER, encoding="utf-8")
        found = [f.severity for f in Scanner().scan(tmp_path).findings if f.rule_id == RULE]
        assert any(s >= Severity.HIGH for s in found)


class TestASelfRenamingPublishLoop:
    """Item 57, the owner's exception (notes/57-self-propagating-publish.md): a script that renames its own
    package and republishes in a loop blocks, though only a person runs it. Keyed on
    what the file does. Inert: the loop runs zero times, the publish is a dry run to a registry that
    does not resolve, and the new name is a constant."""

    HEAD = (
        "const fs = require('fs');\n"
        "const { execSync } = require('child_process');\n"
        "const data = JSON.parse(fs.readFileSync('package.json'));\n"
    )
    PUBLISH = "  execSync('npm publish --dry-run --registry https://registry.invalid');\n"
    WRITE = "  fs.writeFileSync('package.json', JSON.stringify(data));\n"
    MANIFEST: ClassVar[dict[str, object]] = {"scripts": {"start": "node index.js"}}

    def severities(self, tmp_path: Path, body: str) -> list[Severity]:
        return PublishKit.severities(
            tmp_path, self.MANIFEST, {"package/tools/republish.js": self.HEAD + body}
        )

    def test_renaming_itself_and_republishing_in_a_loop_blocks(self, tmp_path: Path) -> None:
        body = (
            "for (let i = 0; i < 0; i++) {\n  data.name = 'example-renamed';\n"
            + self.WRITE
            + self.PUBLISH
            + "}\n"
        )
        assert Severity.HIGH in self.severities(tmp_path, body)

    def test_a_rename_through_an_index_and_a_timer_blocks(self, tmp_path: Path) -> None:
        body = (
            "setInterval(() => {\n  data['name'] = 'example-renamed';\n"
            + self.WRITE
            + self.PUBLISH
            + "}, 1e9);\n"
        )
        assert Severity.HIGH in self.severities(tmp_path, body)

    def test_a_rename_by_object_assign_blocks(self, tmp_path: Path) -> None:
        body = (
            "for (let i = 0; i < 0; i++) {\n  Object.assign(data, { name: 'example-renamed' });\n"
            + self.WRITE
            + self.PUBLISH
            + "}\n"
        )
        assert Severity.HIGH in self.severities(tmp_path, body)

    def test_a_rename_by_a_spread_rebuild_blocks(self, tmp_path: Path) -> None:
        body = (
            "for (let i = 0; i < 0; i++) {\n"
            "  fs.writeFileSync('package.json', JSON.stringify({ ...data, name: 'example-renamed' }));\n"
            + self.PUBLISH
            + "}\n"
        )
        assert Severity.HIGH in self.severities(tmp_path, body)

    def test_a_manifest_path_built_by_path_join_still_counts(self, tmp_path: Path) -> None:
        body = (
            "const path = require('path');\n"
            "for (let i = 0; i < 0; i++) {\n  data.name = 'example-renamed';\n"
            "  fs.writeFileSync(path.join(__dirname, 'package.json'), JSON.stringify(data));\n"
            + self.PUBLISH
            + "}\n"
        )
        assert Severity.HIGH in self.severities(tmp_path, body)

    def test_a_workspace_release_loop_that_bumps_versions_keeps_its_ceiling(
        self, tmp_path: Path
    ) -> None:
        # Lerna- or changesets-style release tooling: a loop, versions bumped, each published. It never
        # renames, so it is release tooling, not self-propagation (outer-layer review of note 57).
        body = (
            "const packages = [data];\n"
            "for (const pkg of packages) {\n  pkg.version = '1.0.1';\n"
            + self.WRITE
            + self.PUBLISH
            + "}\n"
        )
        found = self.severities(tmp_path, body)
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_moving_it_under_tools_does_not_lower_it(self, tmp_path: Path) -> None:
        body = (
            "for (let i = 0; i < 0; i++) {\n  data.name = 'example-renamed';\n"
            + self.WRITE
            + self.PUBLISH
            + "}\n"
        )
        found = PublishKit.severities(
            tmp_path, self.MANIFEST, {"package/scripts/build/republish.js": self.HEAD + body}
        )
        assert Severity.HIGH in found

    def test_a_release_script_that_publishes_without_renaming_keeps_its_ceiling(
        self, tmp_path: Path
    ) -> None:
        body = "for (let i = 0; i < 0; i++) {\n" + self.PUBLISH + "}\n"
        found = self.severities(tmp_path, body)
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_the_same_rename_without_a_loop_or_timer_keeps_its_ceiling(
        self, tmp_path: Path
    ) -> None:
        body = (
            "data.name = 'example-renamed';\n"
            + self.WRITE.strip()
            + "\n"
            + self.PUBLISH.strip()
            + "\n"
        )
        found = self.severities(tmp_path, body)
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_a_version_bump_without_a_publish_is_not_a_publishing_script(
        self, tmp_path: Path
    ) -> None:
        body = "for (let i = 0; i < 0; i++) {\n  data.version = '0.0.0';\n" + self.WRITE + "}\n"
        assert Severity.HIGH not in self.severities(tmp_path, body)

    def test_a_class_property_named_name_is_no_rename(self, tmp_path: Path) -> None:
        # `this.name = ...` in a release loop that publishes: not the manifest's own name.
        body = (
            "class Job { constructor(n) { this.name = n; } }\n"
            "for (let i = 0; i < 0; i++) {\n  new Job('x');\n" + self.WRITE + self.PUBLISH + "}\n"
        )
        found = self.severities(tmp_path, body)
        assert found and all(s <= Severity.MEDIUM for s in found)

    def test_the_same_loop_as_python_source_text_keeps_its_ceiling(self, tmp_path: Path) -> None:
        # A Python file whose strings hold the JavaScript loop (as this test file does): the shape is
        # read from JavaScript only.
        loop = (
            "for (let i = 0; i < 0; i++) { data.name = 'example-renamed'; "
            + self.WRITE.strip()
            + " "
            + self.PUBLISH.strip()
            + " }"
        )
        source = (
            "import subprocess\n"
            f"SNIPPET = {(self.HEAD + loop)!r}\n"
            "subprocess.run(['npm', 'publish'])\n"
        )
        found = PublishKit.severities(tmp_path, self.MANIFEST, {"package/tools/notes.py": source})
        assert Severity.HIGH not in found
