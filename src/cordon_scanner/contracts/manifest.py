"""The contracts as data for other languages, and the manifest that pins them (design spec M0).

The console is TypeScript and the backend reads the contracts without importing this package. They
take them from the JSON files shipped as package data:

```
  data/subject-kinds.json   the ten subject kinds, their id prefixes and parts      (generated here)
  data/reason-codes.json    every reason code: code, title, severity, explanation, state (generated here)
  schemas/*.json            the predicate schemas                                    (written by hand)
  manifest.json             the contracts version and the sha256 of every file above
```

A consumer generates its typed code from these files and keeps a test that fails when a file's hash
differs from the manifest, so its copy cannot drift. `ContractData.problems` is the same test on this
side: the generated files and the manifest equal what the Python registries say now. A change to any
file takes a new `CONTRACTS_VERSION`, and the manifest records it.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar, Final

from cordon_scanner.contracts.catalogue import SubjectCatalogue
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.contracts.schemas import ContractSchemas

#: Bump on any change to any contract file: a new schema, a new reason code, a changed part list.
CONTRACTS_VERSION: Final = "1.0.0"


class ContractData:
    """Build, write and check the JSON data files and the manifest."""

    GENERATED: ClassVar[tuple[str, ...]] = ("data/subject-kinds.json", "data/reason-codes.json")
    MANIFEST: ClassVar[str] = "manifest.json"

    @classmethod
    def reason_codes(cls) -> dict[str, Any]:
        return {
            "contracts_version": CONTRACTS_VERSION,
            "groups": dict(ReasonCodes.GROUPS),
            "codes": [
                {
                    "code": entry.code,
                    "name": entry.name,
                    "group": entry.group,
                    "title": entry.title,
                    "severity": entry.severity,
                    "explanation": entry.meaning,
                    "overridable": entry.overridable,
                    "state": "active",
                }
                for entry in ReasonCodes.ALL
            ],
            "retired": sorted(ReasonCodes.RETIRED),
        }

    @classmethod
    def subject_kinds(cls) -> dict[str, Any]:
        return {"contracts_version": CONTRACTS_VERSION, **SubjectCatalogue.as_json()}

    @staticmethod
    def text(document: dict[str, Any]) -> str:
        """A document as the file holds it: two-space indent, keys in the order written, one newline."""
        return json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def generated(cls) -> dict[str, str]:
        """Each generated file's path (inside `contracts/`) and the text it must hold."""
        return {
            "data/subject-kinds.json": cls.text(cls.subject_kinds()),
            "data/reason-codes.json": cls.text(cls.reason_codes()),
        }

    @classmethod
    def schema_files(cls) -> dict[str, str]:
        """Each schema file's path and its text as shipped."""
        return {
            f"schemas/{name}.json": cls._shipped(f"schemas/{name}.json")
            for name in ContractSchemas.NAMES
        }

    @classmethod
    def manifest(cls, files: dict[str, str]) -> str:
        """The manifest text for these files (path -> text)."""
        listed = {
            path: "sha256:" + hashlib.sha256(files[path].encode("utf-8")).hexdigest()
            for path in sorted(files)
        }
        return cls.text({"contracts_version": CONTRACTS_VERSION, "files": listed})

    @classmethod
    def expected(cls) -> dict[str, str]:
        """Every file the package ships under `contracts/` for other languages, as it must read."""
        files = {**cls.generated(), **cls.schema_files()}
        return {**files, cls.MANIFEST: cls.manifest(files)}

    @classmethod
    def write(cls, directory: Path) -> list[str]:
        """Write the generated files and the manifest into `directory` (the `contracts` folder)."""
        written = []
        for path, text in cls.expected().items():
            if path.startswith("schemas/"):
                continue
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            written.append(path)
        return written

    @classmethod
    def problems(cls) -> list[str]:
        """How the shipped files differ from what the registries say now; empty when none does."""
        found = []
        for path, text in cls.expected().items():
            if cls._shipped(path) != text:
                found.append(f"{path}: differs from what the registries generate")
        return found

    @staticmethod
    def _shipped(path: str) -> str:
        entry = resources.files("cordon_scanner.contracts").joinpath(path)
        return entry.read_text("utf-8") if entry.is_file() else ""


__all__ = ["CONTRACTS_VERSION", "ContractData"]
