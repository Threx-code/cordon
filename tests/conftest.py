"""Shared fixtures.

The cache authentication key deliberately lives under the user's home directory
rather than beside the cache entries, so that redirecting the entries does not
also redirect the key. That is the right production behaviour and the wrong test
behaviour: a suite that writes into the real home directory has a side effect
outside the temporary directory pytest gave it, and worse, every test would
share one key and could only be run serially.

The redirect is therefore done here, once, by patching the method rather than by
setting a variable -- the whole point of `key_dir` is that no variable moves it.
"""

from __future__ import annotations

import pytest

from cordon_scanner.foundation.paths import StatePaths

AMBIENT = ("CI", "CORDON_POLICY", "CORDON_CACHE_DIR", "XDG_CACHE_HOME")
"""Variables the tool reads that a developer's shell may also set.

Every one of them changes behaviour: `CORDON_POLICY` installs an organisation
ceiling over the configuration, `CORDON_CACHE_DIR` and `XDG_CACHE_HOME` move
where results are cached, and `CI` decides whether progress is drawn. A test
that does not set one is asserting whatever the machine happens to say, and
three tests of progress did exactly that -- they passed locally and failed on
every runner, because runners set `CI` and the developer did not.

Cleared for every test rather than fixed one test at a time, because the next
test to read one of these will not know it is doing so. A test that wants a
value sets it with `monkeypatch.setenv`, which then means something.
"""


class SharedFixtures:
    """Fixtures for every test in the suite, registered as a plugin below."""

    @pytest.fixture(autouse=True)
    def _clean_environment(self, monkeypatch, tmp_path_factory: pytest.TempPathFactory) -> None:
        for name in AMBIENT:
            monkeypatch.delenv(name, raising=False)
        # The cache root holds what `advisories sync` wrote, and a scan prefers that database to
        # the bundled one: with ~/.cache/cordon as the root, a machine that had synced read
        # express 4.18.2 as vulnerable and failed a VEX test the bundled data passes. Each test
        # starts from an empty cache of its own; one that wants another sets it.
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path_factory.mktemp("cordon-cache")))

    @pytest.fixture(autouse=True)
    def _fresh_advisory_database(self) -> None:
        """Each test starts with no shared advisory database, as a new process does: one test
        patching or clearing the shipped records must not leave a database built from them for
        the next (`AdvisoryDatabase.bundled` keeps one per process)."""
        from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

        AdvisoryDatabase.shared = None

    @pytest.fixture(autouse=True)
    def _no_osv_refresh(self, monkeypatch) -> None:
        """A scan refreshes from OSV unless offline; a test must never reach the network. The
        variable reaches a scanner a test starts as a subprocess, which the attribute cannot."""
        monkeypatch.setattr("cordon_scanner.intel.advisories.osv_delta.ENABLED", False)
        monkeypatch.setenv("CORDON_NO_ADVISORY_REFRESH", "1")

    @pytest.fixture(autouse=True)
    def _intel_judged_when_it_was_built(self, monkeypatch) -> None:
        """Intel older than its limit makes a scan incomplete (7 days without a feed), so a test
        that read the wall clock passed the week after an intel refresh and failed the week after
        (`test_scanning_an_empty_directory_is_clean`, 4 Nov). A scan in a test judges its intel a
        minute after it was built, here and in every Python process the test starts (the MCP
        server's scans, 4 Nov); a test about staleness passes its own `now`, which wins."""
        import importlib.util
        import os as _os

        from cordon_scanner.intel.malware.feed import FeedClient
        from support import ROOT

        hooks = ROOT / "tests" / "sitehooks"
        spec = importlib.util.spec_from_file_location(
            "cordon_test_sitehooks", hooks / "sitecustomize.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setattr(FeedClient, "status", FeedClient.status)  # restored after the test
        module.IntelAtBuild.install()
        monkeypatch.setenv("CORDON_TEST_INTEL_AT_BUILD", "1")
        paths = [
            str(hooks),
            *[p for p in _os.environ.get("PYTHONPATH", "").split(_os.pathsep) if p],
        ]
        monkeypatch.setenv("PYTHONPATH", _os.pathsep.join(paths))

    @pytest.fixture(autouse=True)
    def _isolated_cache_key(self, tmp_path_factory: pytest.TempPathFactory, monkeypatch) -> None:
        directory = tmp_path_factory.mktemp("cordon-key")
        # The one place the key directory is decided: the scan cache, the evidence key and every
        # other key-holder ask StatePaths, so patching it isolates them all.
        monkeypatch.setattr(StatePaths, "key_dir", staticmethod(lambda: directory))


class UnixLines:
    """`Path.write_text` writes `\n` as `\n` on every platform while the suite runs.

    The suite's 1,310 `write_text` calls mean LF: they build sources, manifests and fixtures whose
    findings, digests and reference hashes the tests assert. On Windows the default newline wrote
    CRLF, so a recipe's digest, a format's reference hash and every rule anchored at a line end saw
    other bytes than on Linux and macOS (the first full Windows run, 4 Nov). CRLF itself is tested
    where it is the subject (tests/unit/foundation/text/test_line_endings.py). A caller that passes
    `newline` keeps it; on Linux and macOS nothing changes."""

    @staticmethod
    def install() -> None:
        from pathlib import Path

        real = Path.write_text
        if getattr(real, "_unix_lines", False):
            return

        def write_text(self, data, encoding=None, errors=None, newline="\n"):  # type: ignore[no-untyped-def]
            return real(self, data, encoding=encoding, errors=errors, newline=newline)

        write_text._unix_lines = True  # type: ignore[attr-defined]
        # Named as the method it replaces, so a test that pickles `Path.write_text` (a malicious
        # pickle's payload) still finds it by name.
        write_text.__module__, write_text.__qualname__ = real.__module__, real.__qualname__
        Path.write_text = write_text  # type: ignore[method-assign]


def pytest_configure(config: pytest.Config) -> None:
    """Register the shared fixtures. pytest finds hooks only as module-level functions
    in a conftest, so this one function stays one; everything else is a class."""
    UnixLines.install()
    config.pluginmanager.register(SharedFixtures(), "cordon-shared-fixtures")


@pytest.fixture
def hardening(monkeypatch: pytest.MonkeyPatch) -> None:
    """Report the hardening tier at full severity, as `--hardening` does.

    The CI, container and infrastructure rules' own tests check what each rule reports; by
    default the engine records those domains at LOW (`Policy.hardening`), which is the tier's
    behaviour and has its own tests (`test_hardening_tier.py`)."""
    from cordon_scanner.engine.pipeline.ceilings import Ceilings

    monkeypatch.setattr(Ceilings, "hardening_tier", staticmethod(lambda findings, policy: findings))


@pytest.fixture
def verdict_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scan with the shipped package verdict model off, so a test asserts what a RULE grades, not
    what the verdict then holds. The verdict (`decide/verdict.py`) lowers a minimal synthetic
    fixture whose combination is not what real malware looks like; a rule test that asserts HIGH on
    such a fixture turns the model off here and keeps testing the rule. The verdict's own
    held-as-a-warning behaviour is pinned separately (test_verdict_features.py)."""
    from cordon_scanner.decide.verdict import VerdictModel

    monkeypatch.setattr(VerdictModel, "load", staticmethod(lambda path=None: None))
