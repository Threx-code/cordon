"""G17: the key ceremony produces keys a client accepts, and the published page matches the pins.

Each test that needs keys runs a full ceremony into a temporary directory. Nothing here touches the
real pinned files except to read them, and no private seed is ever printed.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cordon_scanner.intel import dbsync, feed
from cordon_scanner.intel.dbsync import AdvisoryBundle
from cordon_scanner.intel.feed import Feed, FeedError, FeedRoles

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_790_000_000.0


class CeremonyKit:
    @staticmethod
    def module(name: str, path: Path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @classmethod
    def ceremony(cls):
        return cls.module("key_ceremony", ROOT / "scripts/key_ceremony.py").KeyCeremony

    @classmethod
    def page(cls):
        return cls.module("signing_keys", ROOT / "tests/signing_keys.py").SigningKeysPage


@pytest.fixture
def ran(tmp_path):
    out = tmp_path / "keys"
    result = CeremonyKit.ceremony()(out, now=NOW).run()
    return out, result


class TestTheCeremony:
    def test_the_root_verifies_with_the_clients_own_code(self, ran) -> None:
        out, _ = ran
        document = json.loads((out / "public/feed-root.json").read_text())
        signed = FeedRoles.verify_role(document, "root", document["signed"], expected_type="root")
        assert signed["version"] == 1
        assert (
            signed["roles"]["root"]["threshold"] == 2
            and len(signed["roles"]["root"]["keyids"]) == 3
        )
        for role in ("timestamp", "snapshot", "targets"):
            assert signed["roles"][role]["threshold"] == 1
        assert FeedRoles._expires(signed) > NOW

    def test_a_feed_pinned_to_it_is_enabled(self, ran) -> None:
        out, _ = ran
        assert Feed(root=json.loads((out / "public/feed-root.json").read_text())).enabled

    def test_every_root_key_signed_and_the_threshold_is_real(self, ran) -> None:
        out, _ = ran
        document = json.loads((out / "public/feed-root.json").read_text())
        assert len(document["signatures"]) == 3
        # Two of three signatures are enough; one is not.
        two = {**document, "signatures": document["signatures"][:2]}
        FeedRoles.verify_role(two, "root", document["signed"], expected_type="root")
        one = {**document, "signatures": document["signatures"][:1]}
        with pytest.raises(FeedError, match="1 of the 2"):
            FeedRoles.verify_role(one, "root", document["signed"], expected_type="root")

    def test_a_tampered_root_is_refused(self, ran) -> None:
        out, _ = ran
        document = json.loads((out / "public/feed-root.json").read_text())
        document["signed"]["roles"]["root"]["threshold"] = 1
        with pytest.raises(FeedError):
            FeedRoles.verify_role(document, "root", document["signed"], expected_type="root")

    def test_the_advisory_key_verifies_a_bundle_it_signed(self, ran, monkeypatch) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        out, _ = ran
        seed = bytes.fromhex((out / "private/advisories.seed").read_text().strip())
        archive = b"bundle bytes"
        signature = Ed25519PrivateKey.from_private_bytes(seed).sign(archive)
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_FILE", out / "public/advisory-signing-key.json")
        assert AdvisoryBundle.verify_bundle(archive, signature)
        assert not AdvisoryBundle.verify_bundle(archive + b"!", signature)

    def test_private_seeds_are_owner_only_and_public_files_hold_no_seed(self, ran) -> None:
        out, _ = ran
        seeds = {p.name: p.read_text().strip() for p in (out / "private").iterdir()}
        assert set(seeds) == {
            "root-1.seed",
            "root-2.seed",
            "root-3.seed",
            "timestamp.seed",
            "snapshot.seed",
            "targets.seed",
            "advisories.seed",
        }
        for path in (out / "private").iterdir():
            assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert oct((out / "private").stat().st_mode & 0o777) == "0o700"
        published = "".join(p.read_text() for p in (out / "public").iterdir())
        assert not any(seed in published for seed in seeds.values())

    def test_fingerprints_name_every_key(self, ran) -> None:
        out, result = ran
        lines = (out / "public/fingerprints.txt").read_text().splitlines()
        assert len(lines) == 7 and lines == result["fingerprints"]
        document = json.loads((out / "public/feed-root.json").read_text())
        for keyid in document["signed"]["keys"]:
            assert any(keyid in line for line in lines)

    def test_it_refuses_a_directory_inside_a_git_working_tree(self, tmp_path) -> None:
        (tmp_path / "repo/.git").mkdir(parents=True)
        with pytest.raises(SystemExit, match="git working tree"):
            CeremonyKit.ceremony()(tmp_path / "repo/keys").run()
        assert not (tmp_path / "repo/keys").exists()

    def test_it_never_overwrites_keys(self, ran) -> None:
        out, _ = ran
        before = (out / "private/root-1.seed").read_text()
        with pytest.raises(SystemExit, match="not empty"):
            CeremonyKit.ceremony()(out).run()
        assert (out / "private/root-1.seed").read_text() == before

    @pytest.mark.parametrize("keys, threshold", [(3, 0), (2, 3)])
    def test_an_impossible_threshold_is_refused(self, tmp_path, keys, threshold) -> None:
        with pytest.raises(ValueError, match="threshold"):
            CeremonyKit.ceremony()(tmp_path / "k", root_keys=keys, threshold=threshold)

    def test_the_command_line_prints_fingerprints_and_never_a_seed(self, tmp_path) -> None:
        out = tmp_path / "cli"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/key_ceremony.py"), "--out", str(out)],
            capture_output=True,
            text=True,
            check=True,
        )
        seeds = [p.read_text().strip() for p in (out / "private").iterdir()]
        assert "feed root" in completed.stdout and "advisories" in completed.stdout
        assert not any(seed in completed.stdout + completed.stderr for seed in seeds)


class TestThePublishedPage:
    def test_the_page_matches_the_keys_this_build_pins(self) -> None:
        assert (ROOT / "docs/12-SIGNING-KEYS.md").read_text() == CeremonyKit.page().render(), (
            "docs/12-SIGNING-KEYS.md is out of date. Regenerate it:\n"
            "    python tests/signing_keys.py > docs/12-SIGNING-KEYS.md"
        )

    def test_with_nothing_pinned_the_page_says_so(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(feed, "ROOT_FILE", tmp_path / "absent.json")
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_FILE", tmp_path / "absent.json")
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_HEX", "")
        page = CeremonyKit.page().render()
        assert page.count("**Not pinned in this build.**") == 2

    def test_once_pinned_the_page_publishes_every_fingerprint(self, ran, monkeypatch) -> None:
        out, result = ran
        monkeypatch.setattr(feed, "ROOT_FILE", out / "public/feed-root.json")
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_FILE", out / "public/advisory-signing-key.json")
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_HEX", "")
        page = CeremonyKit.page().render()
        assert "Not pinned" not in page
        for line in result["fingerprints"]:
            assert line.split()[-1] in page

    def test_the_release_identity_is_this_repositorys_release_workflow(self) -> None:
        page = CeremonyKit.page().render()
        assert (
            "https://github.com/Threx-code/cordon/.github/workflows/release.yml@refs/tags/v" in page
        )
        assert (ROOT / ".github/workflows/release.yml").is_file()


class TestPinnedAdvisoryKey:
    def test_a_malformed_key_file_pins_nothing(self, tmp_path, monkeypatch) -> None:
        for body in (
            "{",
            "[]",
            json.dumps({"keytype": "rsa", "public": "ab"}),
            json.dumps({"keytype": "ed25519", "public": 5}),
        ):
            path = tmp_path / "k.json"
            path.write_text(body)
            monkeypatch.setattr(dbsync, "PUBLIC_KEY_FILE", path)
            monkeypatch.setattr(dbsync, "PUBLIC_KEY_HEX", "")
            assert AdvisoryBundle.pinned_key_hex() == ""

    def test_the_constant_wins_over_the_file(self, monkeypatch) -> None:
        monkeypatch.setattr(dbsync, "PUBLIC_KEY_HEX", "ab" * 32)
        assert AdvisoryBundle.pinned_key_hex() == "ab" * 32
