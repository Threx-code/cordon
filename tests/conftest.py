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

from cordon_scanner.core.cache import ScanCache

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


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch) -> None:
    for name in AMBIENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolated_cache_key(tmp_path_factory: pytest.TempPathFactory, monkeypatch) -> None:
    directory = tmp_path_factory.mktemp("cordon-key")
    monkeypatch.setattr(ScanCache, "key_dir", staticmethod(lambda: directory))
