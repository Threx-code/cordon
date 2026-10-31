"""The macho and dex readers held to the reference engine's own module dumps: `yara -D` (YARA 4.5.8 built
from source) over the YARA test fixtures (tests/unit/data/rule_reference/yara_tests), recorded once by
scripts/reference/record_module_dumps.py and replayed here leaf by leaf, every leaf the reference gives
and no leaf it does not, as test_elf holds the ELF reader to modules/expected.json. The crafted dex of
100 classes sharing one class data is held to the same dump but for the one named divergence: the
reference drops each class's last three methods (it wants 12 bytes before an entry), this reader keeps
them, so number_of_methods is 10,000 against its 9,700 and those 300 methods are ours alone."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.formats.dex import Dex
from cordon_scanner.detect.binary.modules.formats.macho import Macho
from cordon_scanner.detect.binary.modules.values import Call, Dual, Record, Scalar, Seq
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "yara_tests"
RECORDED: dict[str, Any] = json.loads((DIR / "reference-4.5.8.json").read_text(encoding="utf-8"))
READERS = {"macho": (Macho.SCHEMA, Macho.data), "dex": (Dex.SCHEMA, Dex.data)}
EXACT = sorted(n for n in RECORDED if not n.startswith("shared-"))


class Tree:
    MACHO_X = (
        "dylibs", "rpaths", "linker_options", "dynamic_linker", "source_version", "uuid",
        "build_version", "min_version", "symtab", "dysymtab", "dyld_info", "code_signature_data",
        "entitlements", "certificates", "exports", "imports",
    )  # fmt: skip
    """Our data rendered the way the recorded dump is: integers as signed 64-bit, strings as hex under
    `b`, arrays keyed by index as text, functions and the second shape of a dual field left out."""

    @staticmethod
    def recode(declared: Any, data: Any) -> Any:
        if data is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Dual):
            return Tree.recode(declared.first, data[0])
        if isinstance(declared, Scalar):
            if declared is Scalar.TEXT:
                return {"b": data.hex()}
            if declared is Scalar.INT:
                v = data & ((1 << 64) - 1)
                return v - (1 << 64) if v >> 63 else v
            return None  # the reference's dump has no booleans; those names are the other engine's
        if isinstance(declared, Record):
            out = {}
            for k, kind in declared.fields.items():
                if k in data and data[k] is not None:
                    r = Tree.recode(kind, data[k])
                    if r is not None:
                        out[k] = r
            return out
        if isinstance(declared, Seq):
            return {str(k): Tree.recode(declared.item, v) for k, v in sorted(data.items())}
        return data

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            if not v:
                out[prefix + "#empty"] = True
            for k, x in v.items():
                Tree.leaves(x, f"{prefix}.{k}", out)
        else:
            out[prefix] = v
        return out

    @staticmethod
    def ours(module: str, data: bytes) -> dict[str, Any]:
        schema, read = READERS[module]
        tree = Tree.recode(schema, read(data))
        if module == "macho":  # the names the other engine declares are not in the reference's dump
            for obj in [tree, *tree.get("file", {}).values()]:
                for k in Tree.MACHO_X:
                    obj.pop(k, None)
                for seg in obj.get("segments", {}).values():
                    seg.pop("filesize", None)
            for arch in tree.get("fat_arch", {}).values():
                arch.pop("reserved", None)
        if module == "dex":  # the names the other engine declares are not in the reference's dump
            for k in ("strings", "types", "protos", "fields", "methods"):
                tree.pop(k, None)
            tree["map_list"].pop("items", None)
            for k in ("version", "link_off", "data_off", "container_size", "header_offset"):
                tree["header"].pop(k, None)
            for c in tree["class_defs"].values():
                for k in ("class", "superclass", "source_file"):
                    c.pop(k, None)
        return Tree.leaves(tree, "", {})


class TestTheReferenceDumps:
    @pytest.mark.parametrize("name", EXACT)
    def test_every_leaf_is_the_one_the_reference_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == RECORDED[name]["sha256"]
        for module, recorded in RECORDED[name]["modules"].items():
            want = Tree.leaves(recorded, "", {})
            got = Tree.ours(module, data)
            assert {
                k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]
            } == {}
            assert sorted(set(got) - set(want)) == []

    def test_the_crafted_dex_differs_only_by_the_named_divergence(self) -> None:
        """The reference's dump is recorded as a digest of its leaves: ours, with the 300 methods it
        drops removed and its method count put in, must hash to the same."""
        name = "shared-100x100.dex"
        data = (DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == RECORDED[name]["sha256"]
        recorded = RECORDED[name]["modules"]["dex"]
        got = Tree.ours("dex", data)
        assert got[".number_of_methods"] == 10000 and recorded["number_of_methods"] == 9700
        extra = {k for k in got if k.startswith(".method.") and int(k.split(".")[2]) >= 9700}
        assert len(extra) == 300 * 9
        theirs = {k: v for k, v in got.items() if k not in extra}
        theirs[".number_of_methods"] = 9700
        assert len(theirs) == recorded["leaf_count"]
        text = json.dumps(sorted(theirs.items()), sort_keys=True, separators=(",", ":"))
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == recorded["leaf_digest"]
