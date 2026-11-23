"""Pack text, delivered-set archives and the cache isolation the tests of delivered rule packs share."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.intel.advisories import shipped

GOOD = "LEARNED.EDGE.1"
PACK = """
pack:
  id: edge.{pid}
  version: 1.0.0
  license: Apache-2.0
  expires: 2099-12-31

rules:
  - id: {rid}
    category: suspicious
    severity: high
    confidence: medium
    title: A delivered rule
    message: Something happened.
    remediation: Fix it.
    match:
      kind: regex
      pattern: '{pattern}'
    tests:
      positive:
        - "{sample}"
      negative:
        - "safe_call(x)"
"""


class Sets:
    @staticmethod
    def pack(
        pid: str, rid: str, pattern: str = "dangerous_call", sample: str = "dangerous_call(x)"
    ) -> str:
        return PACK.format(pid=pid, rid=rid, pattern=pattern, sample=sample)

    @staticmethod
    def archive(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @classmethod
    def rules(cls, entries: list[Any], files: dict[str, str], **index: Any) -> bytes:
        members = {name: text.encode() for name, text in files.items()}
        members["rulepacks.json"] = json.dumps({"packs": entries, **index}).encode()
        return cls.archive(members)

    @staticmethod
    def entry(name: str, enforcement: str = "block", **extra: Any) -> dict[str, Any]:
        return {"file": name, "enforcement": enforcement, **extra}

    @staticmethod
    def ids(packs: Any) -> list[str]:
        return [c.rule.id for p in packs for c in p.rules]


class Isolated:
    @pytest.fixture(autouse=True)
    def isolated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("CORDON_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.delenv("CORDON_OFFLINE", raising=False)
        shipped.ShippedAdvisories.reset_caches()
        yield
        shipped.ShippedAdvisories.reset_caches()
