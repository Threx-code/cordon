"""Deciding whether a refresh is worth proposing to a reviewer.

The three refresh workflows stage their output and then ask this: is there
anything here a person should look at. `git diff --cached --quiet` cannot
answer it, because every refresh stamps the time it ran into a metadata sidecar
and a digest manifest that hashes it, so the index always differs. Left that
way, a weekly job that found nothing opens a pull request and files an issue
anyway, every week, for a diff that is one timestamp.

The stamp cannot simply be dropped. `detect/iac.py` reads it and tells the user
that "resources added to a provider since then have no policy at all", which is
false after a run that read the sources and found them unmoved. The stamp is the
record of when the data was last confirmed, so it has to keep moving -- just not
weekly.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "refresh_movement.py"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "t@example.test")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "names.txt").write_text("# Refreshed: 2026-01-01\nalpha\nbeta\n")
    # Committed with an earlier stamp than the refresh will write, so restamping
    # genuinely dirties the index. A baseline of "now" would match the restamp
    # byte for byte and the tests would pass without deciding anything.
    (tmp_path / "data" / "meta.json").write_text(json.dumps({"built_at": stamp(days_ago=5)}))
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "baseline")
    return tmp_path


def stamp(*, days_ago: float) -> str:
    when = dt.datetime.now(dt.UTC) - dt.timedelta(days=days_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def verdict(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["python3", str(SCRIPT), *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def restamp(repo: Path, *, days_ago: float = 0) -> None:
    """What every refresh does whether or not the data moved."""
    (repo / "data" / "meta.json").write_text(json.dumps({"built_at": stamp(days_ago=days_ago)}))


class TestTheDataDecidesFirst:
    def test_moved_data_is_always_worth_proposing(self, repo: Path) -> None:
        (repo / "data" / "names.txt").write_text("# Refreshed: 2026-06-01\nalpha\nbeta\ngamma\n")
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "substantive"
        )

    def test_a_new_data_file_counts_as_movement(self, repo: Path) -> None:
        (repo / "data" / "extra.txt").write_text("# Refreshed: 2026-06-01\ndelta\n")
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "substantive"
        )

    def test_a_deleted_data_file_counts_as_movement(self, repo: Path) -> None:
        (repo / "data" / "names.txt").unlink()
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "substantive"
        )


class TestATimestampIsNotAChange:
    """The regression. Two refreshes fifteen minutes apart pushed branches and
    filed issues whose entire diff was `built_at`, because the sidecar and the
    digest that hashes it are staged alongside the data."""

    def test_a_restamped_run_over_identical_data_proposes_nothing(self, repo: Path) -> None:
        restamp(repo)
        git(repo, "add", "-A")

        # The condition this exists for: the index really does differ, so the
        # check the workflows used to make says there is something to push.
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet"], cwd=repo, capture_output=True
        )
        assert staged.returncode != 0, "the scenario no longer reproduces a dirty index"

        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "none"
        )

    def test_a_moved_fetch_date_header_is_not_movement(self, repo: Path) -> None:
        """The allowlist files carry the date they were fetched. It moves daily
        on its own and says nothing about the names under it."""
        (repo / "data" / "names.txt").write_text("# Refreshed: 2026-09-23\nalpha\nbeta\n")
        git(repo, "add", "-A")
        assert verdict(repo, "--data", "data/*.txt", "--ignore-line", "^# Refreshed:") == "none"

    def test_a_name_moving_under_that_header_still_is(self, repo: Path) -> None:
        (repo / "data" / "names.txt").write_text("# Refreshed: 2026-09-23\nalpha\nbeta\ngamma\n")
        git(repo, "add", "-A")
        assert (
            verdict(repo, "--data", "data/*.txt", "--ignore-line", "^# Refreshed:") == "substantive"
        )


class TestTheStampIsStillKeptCurrent:
    """Not proposing a timestamp weekly must not become never proposing one.
    `detect/advisory.py` warns past 45 days and `detect/iac.py` past 60, and
    both warnings are about data nobody has confirmed lately."""

    def test_an_aged_stamp_is_proposed_on_its_own(self, repo: Path) -> None:
        git(repo, "rm", "-q", "--cached", "data/meta.json")
        (repo / "data" / "meta.json").write_text(json.dumps({"built_at": stamp(days_ago=95)}))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "an old confirmation")
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "confirmation"
        )

    @pytest.mark.parametrize(
        ("age", "interval", "expected"),
        [
            (29, 30, "none"),
            (31, 30, "confirmation"),
            (39, 40, "none"),
            (41, 40, "confirmation"),
        ],
    )
    def test_the_interval_is_the_boundary(
        self, repo: Path, age: float, interval: float, expected: str
    ) -> None:
        git(repo, "rm", "-q", "--cached", "data/meta.json")
        (repo / "data" / "meta.json").write_text(json.dumps({"built_at": stamp(days_ago=age)}))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "a dated confirmation")
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                str(interval),
            )
            == expected
        )

    def test_an_unreadable_stamp_is_proposed_rather_than_assumed_fresh(self, repo: Path) -> None:
        """A stamp that cannot be parsed is not evidence the data was confirmed
        recently, so it errs towards asking somebody to look."""
        git(repo, "rm", "-q", "--cached", "data/meta.json")
        (repo / "data" / "meta.json").write_text(json.dumps({"built_at": "not a date"}))
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "a broken stamp")
        restamp(repo)
        git(repo, "add", "-A")
        assert (
            verdict(
                repo,
                "--data",
                "data/*.txt",
                "--stamp",
                "data/meta.json",
                "--confirm-after-days",
                "30",
            )
            == "confirmation"
        )

    def test_a_refresh_with_no_stamp_never_proposes_a_confirmation(self, repo: Path) -> None:
        """The allowlist refresh. Nothing reads the date in its headers, so
        there is no date to keep current and only the names can be worth
        proposing."""
        (repo / "data" / "names.txt").write_text("# Refreshed: 2026-09-23\nalpha\nbeta\n")
        git(repo, "add", "-A")
        assert verdict(repo, "--data", "data/*.txt", "--ignore-line", "^# Refreshed:") == "none"
