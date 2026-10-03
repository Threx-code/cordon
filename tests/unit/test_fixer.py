"""G18 fix pull requests on the runner: every value checked before anything is touched, only the one
dependency's lockfile and manifest entries changed, nothing executed, and a branch pushed but never
forced. End to end against a real local git repository."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud import runner
from cordon_scanner.cloud.fixer import DependencyFixer, FixRefused, FixSpec

API = "https://api.cordon.test"
INTEGRITY = "sha512-" + "Q" * 86 + "=="


class FixerKit:
    @staticmethod
    def npm_options(**over: Any) -> dict[str, Any]:
        options = {
            "ecosystem": "npm",
            "name": "lodash",
            "from_version": "4.17.20",
            "to_version": "4.17.21",
            "branch": "cordon/fix-lodash-4.17.21",
            "commit_message": "Bump lodash from 4.17.20 to 4.17.21",
            "payload": {
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": INTEGRITY,
                "dependencies_from": {},
                "dependencies_to": {},
            },
        }
        options.update(over)
        return options

    @staticmethod
    def pypi_options(**over: Any) -> dict[str, Any]:
        options = {
            "ecosystem": "pypi",
            "name": "requests",
            "from_version": "2.31.0",
            "to_version": "2.32.0",
            "branch": "cordon/fix-requests-2.32.0",
            "commit_message": "Bump requests from 2.31.0 to 2.32.0",
            "payload": {"hashes": ["a" * 64, "b" * 64]},
        }
        options.update(over)
        return options

    @staticmethod
    def lock_v3() -> dict:
        return {
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"lodash": "^4.17.20"}},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-old",
                },
                "node_modules/other/node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "x",
                    "integrity": "y",
                },
                "node_modules/lodash-es": {"version": "4.17.20", "resolved": "z", "integrity": "w"},
            },
        }

    @staticmethod
    def write(root: Path, files: dict[str, Any]) -> None:
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                content if isinstance(content, str) else json.dumps(content, indent=2) + "\n"
            )


class TestFixSpec:
    def test_good_options_parse(self):
        spec = FixSpec.from_options(FixerKit.npm_options())
        assert (spec.name, spec.to_version, spec.branch) == (
            "lodash",
            "4.17.21",
            "cordon/fix-lodash-4.17.21",
        )
        assert FixSpec.from_options(FixerKit.pypi_options()).payload["hashes"] == [
            "a" * 64,
            "b" * 64,
        ]

    @pytest.mark.parametrize(
        "over",
        [
            {"ecosystem": "cargo"},
            {"name": "../../etc"},
            {"name": "Lodash Evil"},
            {"to_version": "4.17.20"},
            {"to_version": "1.0; rm -rf"},
            {"branch": "main"},
            {"branch": "cordon/fix-../x"},
            {"commit_message": ""},
            {
                "payload": {
                    **FixerKit.npm_options()["payload"],
                    "resolved": "https://evil.example/lodash/-/lodash-4.17.21.tgz",
                }
            },
            {
                "payload": {
                    **FixerKit.npm_options()["payload"],
                    "resolved": "https://registry.npmjs.org/evil/-/evil-4.17.21.tgz",
                }
            },
            {
                "payload": {
                    **FixerKit.npm_options()["payload"],
                    "resolved": "http://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                }
            },
            {
                "payload": {
                    **FixerKit.npm_options()["payload"],
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz?x=1",
                }
            },
            {"payload": {**FixerKit.npm_options()["payload"], "integrity": "sha1-abc"}},
            {"payload": {**FixerKit.npm_options()["payload"], "dependencies_to": {"a": 1}}},
        ],
    )
    def test_anything_not_exactly_right_is_refused(self, over):
        with pytest.raises(FixRefused):
            FixSpec.from_options(FixerKit.npm_options(**over))

    @pytest.mark.parametrize("hashes", [[], ["xyz"], ["A" * 64], "a" * 64, ["a" * 64] * 201])
    def test_pypi_hashes_must_be_sha256(self, hashes):
        with pytest.raises(FixRefused):
            FixSpec.from_options(FixerKit.pypi_options(payload={"hashes": hashes}))

    def test_a_scoped_npm_package_tarball_path(self):
        options = FixerKit.npm_options(
            name="@babel/core",
            branch="cordon/fix-babel-core-4.17.21",
            payload={
                **FixerKit.npm_options()["payload"],
                "resolved": "https://registry.npmjs.org/@babel/core/-/core-4.17.21.tgz",
            },
        )
        assert FixSpec.from_options(options).name == "@babel/core"


class TestNpm:
    def test_every_entry_at_the_old_version_moves_and_others_are_untouched(self, tmp_path):
        FixerKit.write(
            tmp_path,
            {
                "package-lock.json": FixerKit.lock_v3(),
                "package.json": {"dependencies": {"lodash": "^4.17.20"}},
            },
        )
        changed = DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.npm_options()))
        assert changed == ["package-lock.json", "package.json"]
        lock = json.loads((tmp_path / "package-lock.json").read_text())
        for key in ("node_modules/lodash", "node_modules/other/node_modules/lodash"):
            entry = lock["packages"][key]
            assert entry == {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": INTEGRITY,
            }
        assert lock["packages"]["node_modules/lodash-es"]["version"] == "4.17.20", (
            "a name that merely starts the same is not it"
        )
        assert (
            json.loads((tmp_path / "package.json").read_text())["dependencies"]["lodash"]
            == "^4.17.21"
        )

    def test_the_v2_legacy_tree_moves_too_and_formatting_is_kept(self, tmp_path):
        lock = FixerKit.lock_v3()
        lock["lockfileVersion"] = 2
        lock["dependencies"] = {
            "lodash": {"version": "4.17.20"},
            "other": {"version": "1.0.0", "dependencies": {"lodash": {"version": "4.17.20"}}},
        }
        FixerKit.write(tmp_path, {"package-lock.json": lock})
        DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.npm_options()))
        text = (tmp_path / "package-lock.json").read_text()
        assert text.endswith("\n") and '\n  "name": "app"' in text
        tree = json.loads(text)["dependencies"]
        assert (
            tree["lodash"]["version"] == "4.17.21"
            and tree["other"]["dependencies"]["lodash"]["version"] == "4.17.21"
        )

    @pytest.mark.parametrize(
        "spec, expected",
        [
            ("4.17.20", "4.17.21"),
            ("=4.17.20", "4.17.21"),
            ("~4.17.20", "~4.17.21"),
            (">=4", ">=4"),
            ("latest", "latest"),
        ],
    )
    def test_manifest_pins_move_and_open_ranges_are_left_to_the_lock(
        self, tmp_path, spec, expected
    ):
        FixerKit.write(
            tmp_path,
            {
                "package-lock.json": FixerKit.lock_v3(),
                "package.json": {"devDependencies": {"lodash": spec}},
            },
        )
        DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.npm_options()))
        assert (
            json.loads((tmp_path / "package.json").read_text())["devDependencies"]["lodash"]
            == expected
        )

    def test_a_v1_lockfile_is_refused_with_the_command_to_run(self, tmp_path):
        FixerKit.write(
            tmp_path,
            {
                "package-lock.json": {
                    "lockfileVersion": 1,
                    "dependencies": {"lodash": {"version": "4.17.20"}},
                }
            },
        )
        with pytest.raises(FixRefused, match=r"npm install lodash@4\.17\.21"):
            DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.npm_options()))

    def test_a_version_with_different_dependencies_is_refused(self, tmp_path):
        FixerKit.write(tmp_path, {"package-lock.json": FixerKit.lock_v3()})
        options = FixerKit.npm_options()
        options["payload"]["dependencies_to"] = {"new-dep": "^1"}
        with pytest.raises(FixRefused, match="changes its own dependencies"):
            DependencyFixer.apply(tmp_path, FixSpec.from_options(options))
        assert (
            json.loads((tmp_path / "package-lock.json").read_text())["packages"][
                "node_modules/lodash"
            ]["version"]
            == "4.17.20"
        )

    def test_no_entry_and_node_modules_and_symlinks_are_not_followed(self, tmp_path):
        FixerKit.write(tmp_path, {"node_modules/x/package-lock.json": FixerKit.lock_v3()})
        outside = tmp_path.parent / f"{tmp_path.name}-outside"
        outside.mkdir()
        FixerKit.write(outside, {"package-lock.json": FixerKit.lock_v3()})
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
        with pytest.raises(FixRefused, match="no npm lockfile here records"):
            DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.npm_options()))
        assert (
            json.loads((outside / "package-lock.json").read_text())["packages"][
                "node_modules/lodash"
            ]["version"]
            == "4.17.20"
        )
        shutil.rmtree(outside)


class TestPypi:
    def test_a_plain_pin_and_one_with_extras_and_markers_move(self, tmp_path):
        FixerKit.write(
            tmp_path,
            {
                "requirements.txt": "flask==3.0.0\nRequests==2.31.0\nrequests-mock==1.0\n",
                "services/api/requirements-dev.txt": "requests[socks]==2.31.0 ; python_version >= '3.8'  # pinned\r\n",
            },
        )
        changed = DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.pypi_options()))
        assert changed == ["requirements.txt", "services/api/requirements-dev.txt"]
        assert (
            tmp_path / "requirements.txt"
        ).read_text() == "flask==3.0.0\nRequests==2.32.0\nrequests-mock==1.0\n"
        assert (
            tmp_path / "services/api/requirements-dev.txt"
        ).read_bytes() == b"requests[socks]==2.32.0 ; python_version >= '3.8'  # pinned\r\n"

    def test_a_hashed_pin_gets_the_new_versions_hashes(self, tmp_path):
        FixerKit.write(
            tmp_path,
            {
                "requirements.txt": (
                    "requests==2.31.0 \\\n"
                    f"    --hash=sha256:{'1' * 64} \\\n"
                    f"    --hash=sha256:{'2' * 64}\n"
                    "six==1.16.0\n"
                )
            },
        )
        DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.pypi_options()))
        assert (tmp_path / "requirements.txt").read_text() == (
            "requests==2.32.0 \\\n"
            f"    --hash=sha256:{'a' * 64} \\\n"
            f"    --hash=sha256:{'b' * 64}\n"
            "six==1.16.0\n"
        )

    def test_a_tool_lock_is_refused_with_what_to_do(self, tmp_path):
        FixerKit.write(
            tmp_path,
            {
                "poetry.lock": '[[package]]\nname = "requests"\n',
                "requirements.txt": "flask==3.0.0\n",
            },
        )
        with pytest.raises(FixRefused, match=r"poetry\.lock"):
            DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.pypi_options()))

    def test_no_pin_is_refused(self, tmp_path):
        FixerKit.write(tmp_path, {"requirements.txt": "requests>=2\n"})
        with pytest.raises(FixRefused, match="no requirements file here pins"):
            DependencyFixer.apply(tmp_path, FixSpec.from_options(FixerKit.pypi_options()))


class FixRunKit:
    @staticmethod
    def git(*args: str, cwd: Path) -> str:
        return subprocess.run(
            ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
        ).stdout

    @staticmethod
    def origin(tmp_path: Path) -> Path:
        """A bare repository standing in for the code host, holding an app on `main`."""
        seed = tmp_path / "seed"
        seed.mkdir()
        FixerKit.write(
            seed,
            {
                "package-lock.json": FixerKit.lock_v3(),
                "package.json": {"dependencies": {"lodash": "4.17.20"}},
            },
        )
        for args in (
            ("init", "-q", "-b", "main"),
            ("add", "."),
            ("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"),
        ):
            FixRunKit.git(*args, cwd=seed)
        bare = tmp_path / "origin.git"
        FixRunKit.git("clone", "-q", "--bare", str(seed), str(bare), cwd=tmp_path)
        return bare

    @staticmethod
    def local_git(bare: Path):
        """Lets the real git reach the local bare repository: the runner allows only https, so the
        test (and only the test) re-opens the file protocol."""

        def run(command, *, env, capture_output, timeout, check):
            opened = []
            for i, part in enumerate(command):
                if (
                    part == "-c"
                    and i + 1 < len(command)
                    and command[i + 1] == "protocol.file.allow=never"
                ):
                    continue
                if part == "protocol.file.allow=never":
                    continue
                opened.append(part)
            env = {**env, "GIT_ALLOW_PROTOCOL": "file"}
            return subprocess.run(
                opened, env=env, capture_output=capture_output, timeout=timeout, check=check
            )

        def fetch(target, config, into):
            destination = into / "repo"
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", f"file://{bare}", str(destination)],
                check=True,
                capture_output=True,
            )
            return destination

        return run, {"git": fetch}


class FixRunFixtures:
    @pytest.fixture
    def config(self, tmp_path) -> runner.RunnerConfig:
        work = tmp_path / "work"
        work.mkdir()
        return runner.RunnerConfig(
            url=API,
            token="rt",
            runner_id="r1",
            allowed_hosts=frozenset({"github.com"}),
            work_dir=work,
            make_fixes=True,
        )

    @staticmethod
    def job(**options: Any) -> runner.Job:
        return runner.Job(
            id="job_1",
            lease_id="lease_1",
            lease_seconds=300,
            kind="fix",
            target={"type": "git", "url": "https://github.com/acme/app", "token": "ghs_x"},
            options=FixerKit.npm_options(**options),
        )


class TestExecuteFix(FixRunFixtures):
    @pytest.fixture(autouse=True)
    def _heartbeats(self, monkeypatch):
        monkeypatch.setattr(runner.CloudRunner, "heartbeat", staticmethod(lambda *a, **k: True))

    @pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
    def test_the_change_is_committed_and_pushed_to_a_new_branch(self, config, tmp_path):
        bare = FixRunKit.origin(tmp_path)
        run, fetchers = FixRunKit.local_git(bare)
        outcome = runner.CloudRunner.execute_fix(self.job(), config, fetchers=fetchers, run=run)
        assert outcome["status"] == "succeeded", outcome
        branch, commit = outcome["fix"]["branch"], outcome["fix"]["commit"]
        assert branch == "cordon/fix-lodash-4.17.21" and len(commit) == 40
        assert FixRunKit.git("rev-parse", f"refs/heads/{branch}", cwd=bare).strip() == commit
        assert FixRunKit.git("log", "-1", "--format=%an <%ae>%n%s", branch, cwd=bare).strip() == (
            "Cordon <fix@cordon.dev>\nBump lodash from 4.17.20 to 4.17.21"
        )
        changed = FixRunKit.git("diff", "--name-only", "main", branch, cwd=bare).split()
        assert changed == ["package-lock.json", "package.json"]
        assert not list(config.work_dir.iterdir()), "the workspace is removed"

    @pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
    def test_an_existing_branch_is_never_overwritten(self, config, tmp_path):
        bare = FixRunKit.origin(tmp_path)
        run, fetchers = FixRunKit.local_git(bare)
        assert (
            runner.CloudRunner.execute_fix(self.job(), config, fetchers=fetchers, run=run)["status"]
            == "succeeded"
        )
        before = FixRunKit.git("rev-parse", "refs/heads/cordon/fix-lodash-4.17.21", cwd=bare)
        again = runner.CloudRunner.execute_fix(
            self.job(commit_message="Different"), config, fetchers=fetchers, run=run
        )
        assert again["status"] == "refused" and "could not be pushed" in again["error"]
        assert (
            FixRunKit.git("rev-parse", "refs/heads/cordon/fix-lodash-4.17.21", cwd=bare) == before
        )

    def test_a_runner_without_make_fixes_refuses(self, config):
        config.make_fixes = False
        outcome = runner.CloudRunner.execute_fix(self.job(), config)
        assert outcome["status"] == "refused" and "--make-fixes" in outcome["error"]

    def test_bad_options_or_targets_are_refused_before_any_clone(self, config):
        fetched = []
        fetchers = {"git": lambda *a: fetched.append(a)}
        assert (
            runner.CloudRunner.execute_fix(self.job(ecosystem="cargo"), config, fetchers=fetchers)[
                "status"
            ]
            == "refused"
        )
        job = self.job()
        object.__setattr__(job, "target", {**job.target, "ref": "feature"})
        assert runner.CloudRunner.execute_fix(job, config, fetchers=fetchers)["status"] == "refused"
        object.__setattr__(job, "target", {"type": "git", "url": "https://evil.example/x"})
        assert runner.CloudRunner.execute_fix(job, config, fetchers=fetchers)["status"] == "refused"
        assert fetched == []

    def test_execute_routes_fix_jobs(self, config, monkeypatch):
        seen = []
        monkeypatch.setattr(
            runner.CloudRunner,
            "execute_fix",
            staticmethod(
                lambda job, config, **k: seen.append(job.id) or {"status": "refused", "error": "x"}
            ),
        )
        runner.CloudRunner.execute(self.job(), config)
        assert seen == ["job_1"]


class TestLease:
    def test_fix_jobs_are_offered_only_by_a_runner_that_makes_them(self, tmp_path):
        offered = []

        def transport(method, url, *, body, headers):
            offered.append(json.loads(body)["capabilities"])
            return 204, b""

        base = {
            "url": API,
            "token": "rt",
            "runner_id": "r1",
            "allowed_hosts": frozenset({"github.com"}),
            "work_dir": tmp_path,
        }
        runner.CloudRunner.lease(runner.RunnerConfig(**base), transport=transport)
        runner.CloudRunner.lease(runner.RunnerConfig(**base, make_fixes=True), transport=transport)
        assert offered == [["scan:git", "scan:artifact"], ["scan:git", "scan:artifact", "fix:git"]]

    def test_a_fix_job_is_read_as_one_and_anything_else_as_a_scan(self, tmp_path):
        config = runner.RunnerConfig(
            url=API,
            token="rt",
            runner_id="r1",
            allowed_hosts=frozenset({"github.com"}),
            work_dir=tmp_path,
            make_fixes=True,
        )

        def answering(kind):
            leased = {
                "job_id": "j",
                "lease_id": "l",
                "kind": kind,
                "target": {"type": "git", "url": "https://github.com/a/b"},
                "options": {},
            }
            return lambda method, url, *, body, headers: (200, json.dumps(leased).encode())

        assert runner.CloudRunner.lease(config, transport=answering("fix")).kind == "fix"
        assert runner.CloudRunner.lease(config, transport=answering("weird")).kind == "scan"
