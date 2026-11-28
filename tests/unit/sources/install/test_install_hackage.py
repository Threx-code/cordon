"""Haskell through Cordon: Hackage's signed metadata, its index kept by range, and cabal.project.freeze held to it.

`hackage_captures/` holds Hackage's real root.json, timestamp.json and snapshot.json of 2026-11-27 (the chain whose snapshot names the 1,058,028,032-byte
`01-index.tar` and its SHA-256, which the real index matched), the real `cabal.project` and `cabal.project.freeze` of hasura/graphql-engine, and a slice of the real
index: the real entries (header and data) of the 415 releases that freeze pins which the index holds."""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.hackage import HackagePlanner
from cordon_scanner.sources.install.managers.hackage_index import HackageIndex
from cordon_scanner.sources.install.managers.hackage_trust import HackageTrust, IndexFacts
from cordon_scanner.sources.install.plan import InstallRefused
from support import ROOT

CAPTURES = ROOT / "tests" / "unit" / "sources" / "install" / "hackage_captures"
NOW = datetime(2026, 11, 27, tzinfo=UTC)
AESON_SHA = "cfdc301326d363074cbed14b4e3a853a3b7e22e75b649d49992f37439b851cee"


class Helpers:
    @staticmethod
    def signed() -> tuple[bytes, bytes, bytes]:
        return tuple(
            (CAPTURES / f"{n}.json").read_bytes() for n in ("root", "timestamp", "snapshot")
        )  # type: ignore[return-value]


class TestTheSignedChain:
    def test_the_real_chain_states_the_index_it_describes(self) -> None:
        facts = HackageTrust.index(*Helpers.signed(), now=NOW)
        assert facts == IndexFacts(
            1058028032, "4da064b39a767e2681ff596d690b24ffd2b8509d57992860c35792abe02b6e33"
        )

    def test_a_snapshot_the_timestamp_does_not_describe_is_refused(self) -> None:
        root, stamp, shot = Helpers.signed()
        with pytest.raises(
            InstallRefused, match=r"not the file Hackage's timestamp\.json describes"
        ):
            HackageTrust.index(root, stamp, shot + b" ", now=NOW)

    def test_an_expired_timestamp_is_refused(self) -> None:
        with pytest.raises(InstallRefused, match=r"timestamp\.json expired"):
            HackageTrust.index(*Helpers.signed(), now=datetime(2026, 12, 5, tzinfo=UTC))

    def test_a_root_the_pinned_keys_did_not_sign_is_refused(self) -> None:
        root, stamp, shot = Helpers.signed()
        with pytest.raises(InstallRefused, match=r"not signed by 3 of the six root keys"):
            HackageTrust.index(
                root.replace(b"2027-07-31T23", b"2027-07-30T23"), stamp, shot, now=NOW
            )

    def test_a_timestamp_with_a_changed_signed_part_is_refused(self) -> None:
        root, stamp, shot = Helpers.signed()
        changed = stamp.replace(b'"version":112725', b'"version":112726')
        assert changed != stamp
        with pytest.raises(InstallRefused, match="not signed by the timestamp key"):
            HackageTrust.index(root, changed, shot, now=NOW)


class TestTheIndex:
    def slice(self) -> bytes:
        return (CAPTURES / "01-index-slice.tar").read_bytes()

    def facts(self, data: bytes) -> IndexFacts:
        return IndexFacts(len(data), hashlib.sha256(data).hexdigest())

    def test_a_missing_index_is_fetched_whole_and_held_to_the_signed_hash(
        self, tmp_path: Path
    ) -> None:
        data = self.slice()
        starts: list[int] = []

        def fetch(start: int):
            starts.append(start)
            yield data[start:]

        path = HackageIndex.current(tmp_path, self.facts(data), fetch)
        assert path.read_bytes() == data
        assert starts == [0]

    def test_a_cached_index_gets_only_its_tail(self, tmp_path: Path) -> None:
        data = self.slice()
        (tmp_path / HackageIndex.FILE).write_bytes(data[:200_000])
        starts: list[int] = []

        def fetch(start: int):
            starts.append(start)
            yield data[start:]

        path = HackageIndex.current(tmp_path, self.facts(data), fetch)
        assert path.read_bytes() == data
        assert starts == [200_000 - HackageIndex.CLOSING]

    def test_bytes_that_are_not_the_signed_index_are_refused_and_not_kept(
        self, tmp_path: Path
    ) -> None:
        data = self.slice()

        def fetch(start: int):
            yield (b"x" + data[1:])[start:]

        with pytest.raises(InstallRefused, match="not the file the signed snapshot describes"):
            HackageIndex.current(tmp_path, self.facts(data), fetch)
        assert not (tmp_path / HackageIndex.FILE).exists()

    def test_the_release_hashes_are_read_from_the_last_entry_of_the_index(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "index.tar"
        path.write_bytes(self.slice())
        found = HackageIndex.targets(path, {("aeson", "2.3.0.0"), ("aeson", "0.0")})
        assert set(found) == {("aeson", "2.3.0.0")}
        assert found[("aeson", "2.3.0.0")]["sha256"] == AESON_SHA


class TestTheFreeze:
    def hashes(self, tmp_path: Path):
        path = tmp_path / "index.tar"
        path.write_bytes((CAPTURES / "01-index-slice.tar").read_bytes())
        return lambda wanted: HackageIndex.targets(path, wanted)

    def test_the_real_freeze_pins_424_releases(self) -> None:
        pinned = HackagePlanner.pinned(
            (CAPTURES / "cabal.project.freeze").read_text(encoding="utf-8")
        )
        assert len(pinned) == 424
        assert ("aeson", "2.3.0.0") in pinned

    def test_a_release_the_signed_index_holds_no_hash_for_is_refused(self, tmp_path: Path) -> None:
        text = (CAPTURES / "cabal.project.freeze").read_text(encoding="utf-8")
        with pytest.raises(
            InstallRefused, match=r"kriti-lang-0\.3\.3: the signed Hackage index holds no SHA-256"
        ):
            HackagePlanner.files(text, self.hashes(tmp_path))

    def test_every_release_is_held_to_its_signed_sha256_and_the_compilers_own_are_skipped(
        self, tmp_path: Path
    ) -> None:
        lines = [
            line
            for line in (CAPTURES / "cabal.project.freeze").read_text(encoding="utf-8").splitlines()
            if not any(f"any.{n} ==" in line for n in ("kriti-lang", "libdeflate-hs", "odbc"))
        ]
        plan = HackagePlanner.files("\n".join(lines), self.hashes(tmp_path))
        assert len(plan.files) == 415
        aeson = next(f for f in plan.files if f.name == "aeson")
        assert (aeson.algorithm, aeson.digest.hex()) == ("sha256", AESON_SHA)
        assert aeson.url == "https://hackage.haskell.org/package/aeson-2.3.0.0/aeson-2.3.0.0.tar.gz"
        assert not any(f.name in ("ghc-prim", "rts", "ghci") for f in plan.files)

    def test_a_git_dependency_in_the_project_is_refused(self, tmp_path: Path) -> None:
        for name in ("cabal.project", "cabal.project.freeze"):
            shutil.copy(CAPTURES / name, tmp_path / name)
        with pytest.raises(InstallRefused, match="source-repository-package"):
            HackagePlanner.plan(["build"], tmp_path, self.hashes(tmp_path))

    def test_no_freeze_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(InstallRefused, match=r"no cabal\.project\.freeze"):
            HackagePlanner.plan(["build"], tmp_path, self.hashes(tmp_path))

    @pytest.mark.parametrize(
        ("args", "installs"),
        [
            (["build", "all"], True),
            (["v2-build"], True),
            (["--verbose", "install", "x"], True),
            (["update"], False),
            (["--version"], False),
            ([], False),
        ],
    )
    def test_which_commands_download_packages(self, args: list[str], installs: bool) -> None:
        assert HackagePlanner.installs(args) is installs


class TestTheRepositoryCabalBuildsFrom:
    """A repository of only the scanned tarballs, each with its latest .cabal revision beside it. The real proof ran cabal 3.14 in
    the `haskell` image (--network none): data-forced 0.3.0.0 built under GHC 9.6 with the revision beside it, was refused without it
    (`base ^>=4.16.4.0` against base-4.18), and an unscanned dependency was `unknown package` at the solve."""

    KEY = ("data-forced", "0.3.0.0")

    def test_the_latest_revision_of_the_cabal_file_comes_from_the_index(self) -> None:
        found = HackageIndex.entries(
            CAPTURES / "01-index-revisions-slice.tar", {self.KEY}, "<name>.cabal"
        )
        text = found[self.KEY].decode()
        assert "x-revision: 1" in text
        assert "base >=4.16.4.0 && <4.20.0" in text

    def test_each_scanned_tarball_is_copied_with_its_revision_beside_it(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.sources.install.managers.hackage_repository import HackageRepository
        from cordon_scanner.sources.install.plan import InstallPlan, PackageFile

        data = (CAPTURES / "data-forced-0.3.0.0.tar.gz").read_bytes()
        file = PackageFile(
            "hackage", "data-forced", "0.3.0.0", "https://hackage.haskell.org/x", "sha256",
            hashlib.sha256(data).digest(), separator="-",
        )  # fmt: skip
        scanned = tmp_path / "files"
        scanned.mkdir()
        (scanned / file.filename).write_bytes(data)
        revisions = HackageIndex.entries(
            CAPTURES / "01-index-revisions-slice.tar", {self.KEY}, "<name>.cabal"
        )
        repository = tmp_path / "repository"
        HackageRepository.build(InstallPlan("hackage", [file]), scanned, revisions, repository)
        assert sorted(p.name for p in repository.iterdir()) == [
            "data-forced-0.3.0.0.cabal",
            "data-forced-0.3.0.0.tar.gz",
        ]
        assert (repository / "data-forced-0.3.0.0.tar.gz").read_bytes() == data
        assert (repository / "data-forced-0.3.0.0.cabal").read_bytes() == revisions[self.KEY]
        assert HackageRepository.config(repository) == (
            f"repository cordon-scanned\n  url: file+noindex://{repository}\n"
        )
        assert HackageRepository.arguments(["build", "all"], tmp_path / "config") == [
            f"--config-file={tmp_path / 'config'}",
            "build",
            "all",
        ]

    @pytest.mark.parametrize(
        ("text", "word"),
        [
            ("repository mine\n  url: https://example.org/\n", "repository"),
            ("active-repositories: :rest\n", "active-repositories"),
        ],
    )
    def test_a_project_that_names_its_own_package_sources_is_refused(
        self, text: str, word: str
    ) -> None:
        from cordon_scanner.sources.install.managers.hackage_repository import HackageRepository

        with pytest.raises(InstallRefused, match=word):
            HackageRepository.refuse_own_sources({"cabal.project": text}, ["build"])

    def test_a_configuration_flag_is_refused(self) -> None:
        from cordon_scanner.sources.install.managers.hackage_repository import HackageRepository

        with pytest.raises(InstallRefused, match="--config-file"):
            HackageRepository.refuse_own_sources({}, ["--config-file=/x", "build"])
