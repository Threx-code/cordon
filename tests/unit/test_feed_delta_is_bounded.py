"""A feed delta's decompression has a ceiling (`package.md` PK-09)."""

from __future__ import annotations

import gzip
import json

import pytest

from cordon_scanner.intel.feed import FeedError, FeedStore


class TestADeltaCannotExpandWithoutLimit:
    def test_a_delta_past_the_ceiling_is_refused(self, monkeypatch) -> None:
        monkeypatch.setattr(FeedStore, "MAX_DELTA_BYTES", 1024)
        body = gzip.compress(json.dumps({"serial": 7, "pad": "x" * 4096}).encode())
        with pytest.raises(FeedError, match="expands past"):
            FeedStore._read_delta(body, 7)

    def test_an_ordinary_delta_is_read(self) -> None:
        body = gzip.compress(json.dumps({"serial": 7, "advisories": []}).encode())
        assert FeedStore._read_delta(body, 7)["serial"] == 7
