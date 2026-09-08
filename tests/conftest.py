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


@pytest.fixture(autouse=True)
def _isolated_cache_key(tmp_path_factory: pytest.TempPathFactory, monkeypatch) -> None:
    directory = tmp_path_factory.mktemp("cordon-key")
    monkeypatch.setattr(ScanCache, "key_dir", staticmethod(lambda: directory))
