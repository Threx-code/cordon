"""brew through Cordon (`sources/install/managers/homebrew.py`, `cli/commands/install/homebrew.py`).

The brew answers are real (`homebrew_captures/CAPTURES.md`); the registry client is the real one with only its HTTP replaced, so a
bottle's digest is checked by the product's own code.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.install.homebrew import HomebrewTools
from cordon_scanner.intel.registries.registry_image import Pull, RegistryImage, RegistryImageError
from cordon_scanner.sources.install.managers.homebrew import HomebrewPlanner
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "homebrew_captures"
COWSAY_DIGEST = "345e99255a69e9cb188a5a8e6bd8e6f50c334830c8a72877fc6b504c95e5cbd1"


class Brew:
    """What `brew` printed, by the command asked."""

    BOTTLE = (CAPTURES / "cowsay.bottle.tar.gz").read_bytes()

    @staticmethod
    def text(name: str) -> str:
        return (CAPTURES / name).read_text(encoding="utf-8")

    @classmethod
    def answers(cls, info: str, deps: str = "", outdated: str = "") -> Any:
        def ask(argv: Any) -> str:
            verb = argv[0]
            if verb == "info":
                return info
            if verb == "deps":
                return deps
            if verb == "outdated":
                return outdated
            raise AssertionError(f"unexpected brew command: {list(argv)}")

        return ask


class Response(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.headers: dict[str, str] = {}


class FakeGhcr(RegistryImage):
    """The real client; only the HTTP is replaced by what ghcr.io served for the cowsay bottle."""

    def __init__(self, data: bytes | None = None) -> None:
        super().__init__("ghcr.io", "homebrew/core/cowsay")
        self.data = data if data is not None else Brew.BOTTLE

    def _open(self, url: str, accept: str | None = None) -> Any:  # type: ignore[override]
        if url.endswith(f"/blobs/sha256:{COWSAY_DIGEST}"):
            return Response(self.data)
        raise RegistryImageError(f"unexpected request: {url}")


class Stub:
    """A registry client that serves the bytes it is given and records what was asked of it."""

    def __init__(self, asked: list[tuple[str, str]]) -> None:
        self.asked = asked
        self.repository = ""

    def make(self, registry: str, repository: str) -> Any:
        self.asked.append((registry, repository))
        return SimpleNamespace(blob=lambda digest, pull: repository.encode())


class TestWhatIsAnInstall:
    @pytest.mark.parametrize(
        "args",
        [
            ["install", "jq"],
            ["reinstall", "jq"],
            ["upgrade"],
            ["upgrade", "jq"],
            ["install", "-q", "jq"],
        ],
    )
    def test_these_pour_bottles(self, args: list[str]) -> None:
        assert HomebrewPlanner.installs(args)

    @pytest.mark.parametrize(
        "args",
        [
            ["list"],
            ["info", "jq"],
            ["search", "jq"],
            ["install", "--dry-run", "jq"],
            ["install", "-n", "jq"],
            ["update"],
        ],
    )
    def test_these_do_not(self, args: list[str]) -> None:
        assert not HomebrewPlanner.installs(args)

    def test_an_option_before_the_command_is_refused_not_skipped(self) -> None:
        assert HomebrewPlanner.installs(["--debug", "install", "jq"])
        with pytest.raises(InstallRefused, match="before the command"):
            HomebrewPlanner.names(["--debug", "install", "jq"])


class TestWhatIsRefused:
    @pytest.mark.parametrize("flag", ["--cask", "-s", "--build-from-source", "--HEAD"])
    def test_an_install_that_would_run_unscanned_code_is_refused(self, flag: str) -> None:
        with pytest.raises(InstallRefused, match="refused"):
            HomebrewPlanner.names(["install", flag, "jq"])

    def test_an_option_it_does_not_know_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match="does not know the option --frobnicate"):
            HomebrewPlanner.names(["install", "--frobnicate", "jq"])

    @pytest.mark.parametrize(
        "name", ["user/tap/tool", "./tool.rb", "https://example.invalid/t.rb", "Tool"]
    )
    def test_a_tap_a_path_and_a_url_are_refused(self, name: str) -> None:
        with pytest.raises(InstallRefused, match="not a homebrew/core formula name"):
            HomebrewPlanner.names(["install", name])

    def test_a_cask_is_refused(self, tmp_path: Path) -> None:
        ask = Brew.answers(Brew.text("info-cask-rectangle.json"))
        with pytest.raises(InstallRefused, match="rectangle is a cask"):
            HomebrewPlanner.plan(["install", "rectangle"], tmp_path, ask, lambda r, p: FakeGhcr())

    def test_a_formula_with_no_bottle_is_refused(self, tmp_path: Path) -> None:
        info = json.loads(Brew.text("info-cowsay.json"))
        info["formulae"][0]["bottle"] = {}
        with pytest.raises(InstallRefused, match="has no bottle"):
            HomebrewPlanner.plan(
                ["install", "cowsay"],
                tmp_path,
                Brew.answers(json.dumps(info)),
                lambda r, p: FakeGhcr(),
            )

    def test_bottles_for_several_platforms_with_no_way_to_choose_are_refused(
        self, tmp_path: Path
    ) -> None:
        info = json.loads(Brew.text("info-cowsay.json"))
        files = info["formulae"][0]["bottle"]["stable"]["files"]
        files["arm64_sequoia"] = files.pop("all")
        files["sonoma"] = copy.deepcopy(files["arm64_sequoia"])
        with pytest.raises(InstallRefused, match="does not say which this machine takes"):
            HomebrewPlanner.plan(
                ["install", "cowsay"],
                tmp_path,
                Brew.answers(json.dumps(info)),
                lambda r, p: FakeGhcr(),
            )

    def test_a_bottle_from_anywhere_but_homebrew_core_is_refused(self, tmp_path: Path) -> None:
        info = json.loads(Brew.text("info-cowsay.json"))
        entry = info["formulae"][0]["bottle"]["stable"]["files"]["all"]
        entry["url"] = entry["url"].replace("ghcr.io/v2/homebrew/core", "evil.example/v2/acme")
        with pytest.raises(InstallRefused, match="does not come from homebrew/core"):
            HomebrewPlanner.plan(
                ["install", "cowsay"],
                tmp_path,
                Brew.answers(json.dumps(info)),
                lambda r, p: FakeGhcr(),
            )

    def test_a_digest_that_is_not_a_sha256_is_refused(self, tmp_path: Path) -> None:
        info = json.loads(Brew.text("info-cowsay.json"))
        info["formulae"][0]["bottle"]["stable"]["files"]["all"]["sha256"] = "zz"
        with pytest.raises(InstallRefused, match="does not come from homebrew/core"):
            HomebrewPlanner.plan(
                ["install", "cowsay"],
                tmp_path,
                Brew.answers(json.dumps(info)),
                lambda r, p: FakeGhcr(),
            )


class TestThePlan:
    def test_the_bottle_is_fetched_by_its_digest_and_written_for_the_scan(
        self, tmp_path: Path
    ) -> None:
        ask = Brew.answers(Brew.text("info-cowsay.json"))
        result = HomebrewPlanner.plan(
            ["install", "cowsay"], tmp_path / "bottles", ask, lambda r, p: FakeGhcr()
        )
        assert result.formulae == ("cowsay@3.8.4",)
        assert result.plan is not None and result.plan.ecosystem == "homebrew"
        written = (tmp_path / "bottles" / "cowsay-3.8.4.bottle.tar.gz").read_bytes()
        assert hashlib.sha256(written).hexdigest() == COWSAY_DIGEST

    def test_a_bottle_that_is_not_the_one_published_is_refused(self, tmp_path: Path) -> None:
        ask = Brew.answers(Brew.text("info-cowsay.json"))
        with pytest.raises(InstallRefused, match="do not match its digest"):
            HomebrewPlanner.plan(
                ["install", "cowsay"], tmp_path, ask, lambda r, p: FakeGhcr(Brew.BOTTLE + b"x")
            )

    def test_what_a_formula_needs_is_fetched_too_each_from_its_own_repository(
        self, tmp_path: Path
    ) -> None:
        asked: list[tuple[str, str]] = []
        ask = Brew.answers(Brew.text("info-jq.json"), Brew.text("deps-jq.txt"))
        result = HomebrewPlanner.plan(["install", "jq"], tmp_path, ask, Stub(asked).make)
        assert result.formulae == ("jq@1.8.2", "oniguruma@6.9.10")
        assert asked == [("ghcr.io", "homebrew/core/jq"), ("ghcr.io", "homebrew/core/oniguruma")]

    def test_a_bare_upgrade_scans_what_is_outdated(self, tmp_path: Path) -> None:
        asked: list[tuple[str, str]] = []
        ask = Brew.answers(Brew.text("info-cowsay.json"), outdated="cowsay\n")
        result = HomebrewPlanner.plan(["upgrade"], tmp_path, ask, Stub(asked).make)
        assert result.formulae == ("cowsay@3.8.4",)

    def test_a_bare_upgrade_with_nothing_outdated_has_nothing_to_scan(self, tmp_path: Path) -> None:
        result = HomebrewPlanner.plan(
            ["upgrade"], tmp_path, Brew.answers("{}", outdated=""), Stub([]).make
        )
        assert result.plan is None

    def test_a_bare_install_names_no_formula(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="names no formula"):
            HomebrewPlanner.plan(["install"], tmp_path, Brew.answers("{}"), Stub([]).make)

    def test_an_answer_that_is_not_json_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match="not JSON"):
            HomebrewPlanner.plan(
                ["install", "cowsay"], tmp_path, Brew.answers("oops"), Stub([]).make
            )

    def test_the_bottles_are_private(self, tmp_path: Path) -> None:
        ask = Brew.answers(Brew.text("info-cowsay.json"))
        HomebrewPlanner.plan(
            ["install", "cowsay"], tmp_path / "bottles", ask, lambda r, p: FakeGhcr()
        )
        assert (tmp_path / "bottles" / "cowsay-3.8.4.bottle.tar.gz").stat().st_mode & 0o077 == 0


class FakeContext:
    def __init__(self, *, ok: bool = True) -> None:
        self.ok = ok
        self.ran: list[tuple[list[str], dict[str, str] | None]] = []
        self.checked: list[list[str]] = []

    def check(self, plan: Any, scratch: Path) -> Any:
        self.checked.append(sorted(p.name for p in plan.local[0].iterdir()))
        return SimpleNamespace(ok=self.ok)

    def blocked(self, verdict: object) -> int:
        return 2

    def run(
        self, argv: list[str], cwd: Path | None = None, env: dict[str, str] | None = None
    ) -> int:
        self.ran.append((list(argv), env))
        return 0


class TestTheCommand:
    @pytest.fixture(autouse=True)
    def _brew(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cordon_scanner.sources.install.plan import Subprocesses

        def run(argv: Any, cwd: Path, env: dict[str, str]) -> Any:
            assert env["HOMEBREW_NO_AUTO_UPDATE"] == "1"
            verb = argv[1]
            out = {"info": Brew.text("info-cowsay.json"), "deps": ""}.get(verb, "")
            return SimpleNamespace(returncode=0, stdout=out, stderr="")

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
        monkeypatch.setattr(HomebrewPlanner, "registry", staticmethod(lambda r, p: FakeGhcr()))

    def test_brew_runs_from_the_same_formula_data_after_a_clean_scan(self) -> None:
        context = FakeContext()
        assert HomebrewTools.brew("/opt/homebrew/bin/brew", ["install", "cowsay"], context) == 0  # type: ignore[arg-type]
        assert context.checked == [["cowsay-3.8.4.bottle.tar.gz"]]
        ((argv, env),) = context.ran
        assert argv == ["/opt/homebrew/bin/brew", "install", "cowsay"]
        assert env is not None and env["HOMEBREW_NO_AUTO_UPDATE"] == "1"

    def test_a_block_runs_nothing(self) -> None:
        context = FakeContext(ok=False)
        assert HomebrewTools.brew("/opt/homebrew/bin/brew", ["install", "cowsay"], context) == 2  # type: ignore[arg-type]
        assert context.ran == []

    def test_a_refusal_runs_nothing(self) -> None:
        context = FakeContext()
        with pytest.raises(InstallRefused):
            HomebrewTools.brew("/opt/homebrew/bin/brew", ["install", "--cask", "x"], context)  # type: ignore[arg-type]
        assert context.ran == []


class TestTheScan:
    def test_the_scanner_reads_a_real_bottle_and_it_passes(self, tmp_path: Path) -> None:
        from cordon_scanner.cli.commands.install.context import InstallContext
        from cordon_scanner.foundation.config.settings import Config

        ask = Brew.answers(Brew.text("info-cowsay.json"))
        result = HomebrewPlanner.plan(
            ["install", "cowsay"], tmp_path / "bottles", ask, lambda r, p: FakeGhcr()
        )
        assert result.plan is not None
        assert InstallContext.scanner(Config.default())(result.plan.local[0]) == ()
        assert Pull().downloaded == 0
