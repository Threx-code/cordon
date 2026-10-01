"""K6: `cordon runner`. A fake control plane, a fake git, and every way a job must be refused."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.main import main as cli_main
from cordon_scanner.cloud import runner

API = "https://api.cordon.test"


class ControlPlane:
    def __init__(self, jobs: list[dict[str, Any]], *, heartbeat_status: int = 200) -> None:
        self.jobs = list(jobs)
        self.heartbeat_status = heartbeat_status
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, method, url, *, body, headers):
        path = url.removeprefix(API)
        payload = json.loads(body or b"{}")
        self.calls.append((path, payload))
        assert headers["Authorization"] == "Bearer rt"
        if path == "/v1/runner/jobs/lease":
            return (200, json.dumps(self.jobs.pop(0)).encode()) if self.jobs else (204, b"")
        if path.endswith("/heartbeat"):
            return self.heartbeat_status, b"{}"
        if path.endswith("/result"):
            return 204, b""
        if path == "/v1/scans":
            return 201, b'{"scan_id": "scn_9"}'
        return 404, b"{}"

    def results(self) -> list[dict[str, Any]]:
        return [payload for path, payload in self.calls if path.endswith("/result")]


def job(target: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "job_id": "job_1",
        "lease_id": "lease_1",
        "lease_expires_in": 300,
        "target": target,
        "options": {"org": "acme"},
        **extra,
    }


@pytest.fixture
def config(tmp_path) -> runner.RunnerConfig:
    return runner.RunnerConfig(
        url=API,
        token="rt",
        runner_id="r1",
        allowed_hosts=frozenset({"github.com"}),
        work_dir=tmp_path,
        poll_seconds=0,
    )


class FakeGit:
    def __init__(self, files: dict[str, str] | None = None, returncode: int = 0) -> None:
        self.files = files or {"app.py": "x = 1\n"}
        self.returncode = returncode
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []

    def __call__(self, command, *, env, capture_output, timeout, check):
        self.commands.append(command)
        self.environments.append(env)
        destination = Path(command[-1])
        destination.mkdir(parents=True)
        for name, text in self.files.items():
            (destination / name).write_text(text, encoding="utf-8")
        return type("Completed", (), {"returncode": self.returncode})()


def fetchers(git: FakeGit):
    return {"git": lambda target, cfg, into: runner.fetch_git(target, cfg, into, run=git)}


class TestAJob:
    def test_a_git_job_is_cloned_scanned_uploaded_and_reported(self, config) -> None:
        plane = ControlPlane(
            [
                job(
                    {
                        "type": "git",
                        "url": "https://github.com/acme/app",
                        "ref": "main",
                        "token": "ghs_x",
                    }
                )
            ]
        )
        git = FakeGit()
        leased = runner.lease(config, transport=plane)
        outcome = runner.execute(leased, config, transport=plane, fetchers=fetchers(git))
        assert outcome == {"status": "succeeded", "exit_code": 0, "scan_id": "scn_9"}
        [command] = git.commands
        assert command[:9] == [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "core.symlinks=false",
            "-c",
            "submodule.recurse=false",
        ]
        assert "--depth" in command and command[-2] == "https://github.com/acme/app"
        assert all("ghs_x" not in part for part in command), "the token is never an argument"
        [environment] = git.environments
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
        assert not any(p.name.startswith("cordon-job-") for p in config.work_dir.iterdir()), (
            "the workspace is removed"
        )

    @pytest.mark.parametrize("ref", ["refs/pull/1204/head", "4f2a9c1e0b7d", "a" * 40])
    def test_a_pull_request_or_commit_is_fetched_exactly(self, config, tmp_path, ref) -> None:
        steps: list[list[str]] = []
        environments: list[dict[str, str]] = []

        def git(command, *, env, capture_output, timeout, check):
            steps.append(command)
            environments.append(env)
            return type("Completed", (), {"returncode": 0})()

        target = {
            "type": "git",
            "url": "https://github.com/acme/app",
            "ref": ref,
            "token": "ghs_x",
        }
        destination = runner.fetch_git(target, config, tmp_path, run=git)
        verbs = [step[9 : 12 if step[9] == "-C" else 10] for step in steps]
        assert verbs == [
            ["init"],
            ["-C", str(destination), "remote"],
            ["-C", str(destination), "fetch"],
            ["-C", str(destination), "checkout"],
        ]
        assert steps[1][-3:] == ["add", "origin", "https://github.com/acme/app"]
        assert steps[2][-2:] == ["origin", ref]
        assert steps[3][-1] == "FETCH_HEAD"
        assert all(
            step[:9] == steps[0][:9] and "core.hooksPath=/dev/null" in step for step in steps
        )
        assert all("ghs_x" not in part for step in steps for part in step), (
            "the token is never an argument"
        )
        assert all(
            env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
            for env in environments
        )

    def test_a_branch_is_still_cloned_by_name(self, config, tmp_path) -> None:
        git = FakeGit()
        runner.fetch_git(
            {"type": "git", "url": "https://github.com/acme/app", "ref": "main"},
            config,
            tmp_path,
            run=git,
        )
        [command] = git.commands
        assert "clone" in command and command[command.index("--branch") + 1] == "main"

    def test_a_failed_fetch_step_refuses_the_job(self, config, tmp_path) -> None:
        def git(command, *, env, capture_output, timeout, check):
            return type("Completed", (), {"returncode": 128 if "fetch" in command else 0})()

        with pytest.raises(runner.JobRefused, match="clone failed"):
            runner.fetch_git(
                {
                    "type": "git",
                    "url": "https://github.com/acme/app",
                    "ref": "refs/pull/9/head",
                },
                config,
                tmp_path,
                run=git,
            )

    @pytest.mark.parametrize(
        ("target", "reason"),
        [
            (
                {"type": "git", "url": "https://internal.corp/repo"},
                "not on this runner's allowed hosts",
            ),
            ({"type": "git", "url": "http://github.com/acme/app"}, "only https"),
            (
                {"type": "git", "url": "https://user:pw@github.com/acme/app"},
                "must not carry credentials",
            ),
            (
                {
                    "type": "git",
                    "url": "https://github.com/acme/app",
                    "ref": "--upload-pack=touch /tmp/x",
                },
                "not a branch",
            ),
            ({"type": "svn", "url": "https://github.com/acme/app"}, "does not handle"),
            ({"type": "artifact", "url": "https://github.com/acme/app.tgz"}, "sha256"),
        ],
    )
    def test_a_job_the_runner_will_not_do_is_refused(self, config, target, reason) -> None:
        plane = ControlPlane([job(target)])
        outcome = runner.execute(
            runner.lease(config, transport=plane),
            config,
            transport=plane,
            fetchers=fetchers(FakeGit()),
        )
        assert outcome["status"] == "refused"
        assert reason in outcome["error"]

    def test_a_lost_lease_abandons_the_job(self, config) -> None:
        plane = ControlPlane(
            [job({"type": "git", "url": "https://github.com/acme/app"})],
            heartbeat_status=409,
        )
        outcome = runner.execute(
            runner.lease(config, transport=plane),
            config,
            transport=plane,
            fetchers=fetchers(FakeGit()),
        )
        assert outcome["status"] == "abandoned"
        assert not [c for c in plane.calls if c[0] == "/v1/scans"], (
            "nothing is uploaded for a job that is no longer ours"
        )

    def test_an_artifact_is_checked_against_its_digest(self, config, tmp_path) -> None:
        data = b"not really a tarball"

        def opener(request, timeout):
            return io.BytesIO(data)

        good = {
            "url": "https://github.com/acme/app/releases/a.bin",
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        assert runner.fetch_artifact(good, config, tmp_path, opener=opener).read_bytes() == data
        with pytest.raises(runner.JobRefused, match="does not match"):
            runner.fetch_artifact({**good, "sha256": "0" * 64}, config, tmp_path, opener=opener)


class TestTheLoop:
    def test_it_reports_every_outcome_and_backs_off_when_idle(self, config, monkeypatch) -> None:
        real = runner.fetch_git
        monkeypatch.setattr(
            runner,
            "fetch_git",
            lambda target, cfg, into: real(target, cfg, into, run=FakeGit()),
        )
        plane = ControlPlane(
            [
                job({"type": "git", "url": "https://github.com/acme/app"}),
                job({"type": "git", "url": "https://elsewhere.test/x"}),
            ]
        )
        slept: list[float] = []

        def sleep(seconds):
            slept.append(seconds)
            if len(slept) >= 2:
                raise KeyboardInterrupt

        config.poll_seconds = 5
        with pytest.raises(KeyboardInterrupt):
            runner.serve(config, transport=plane, sleep=sleep, log=lambda _: None)
        assert [r["status"] for r in plane.results()] == ["succeeded", "refused"]
        assert slept == [5, 10]


class TestTheCommand:
    def test_it_needs_a_token_and_an_allowlist(self, monkeypatch) -> None:
        monkeypatch.delenv("CORDON_RUNNER_TOKEN", raising=False)
        assert cli_main(["runner", "--url", API, "--allow-host", "github.com", "--once"]) == 3
        monkeypatch.setenv("CORDON_RUNNER_TOKEN", "rt")
        assert cli_main(["runner", "--url", API, "--once"]) == 3

    def test_idle_polling_stops_backing_off_at_half_a_minute(self, config, monkeypatch) -> None:
        plane = ControlPlane([])
        slept: list[float] = []

        def sleep(seconds: float) -> None:
            slept.append(seconds)
            if len(slept) == 8:
                raise KeyboardInterrupt

        cfg = runner.RunnerConfig(**{**config.__dict__, "poll_seconds": 5})
        with pytest.raises(KeyboardInterrupt):
            runner.serve(cfg, transport=plane, sleep=sleep, log=lambda _: None)
        assert slept == [5, 10, 20, 30, 30, 30, 30, 30]
