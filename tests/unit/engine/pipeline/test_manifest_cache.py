"""engine.pipeline.graph.Graph.manifest_of: an in-tree manifest parsed once a scan, kept by a small
view id (`view_of`), not by the view itself. Kept answers equal fresh parses, and the cache holds
one view however many manifests share it: holding the view in every entry kept 18,543 paths and
contents for each of 10,475 Terraform manifests and ended a scan at 8 GB (2026-10-31)."""

from __future__ import annotations

import tracemalloc

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.content import FileContent


class Tree:
    @staticmethod
    def units(directories: int) -> list[FileUnit]:
        out = []
        for i in range(directories):
            raw = (
                f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "x{i}"\n}}\n'
                f'module "m{i}" {{\n  source = "terraform-aws-modules/vpc/aws"\n  version = "5.{i % 9}.0"\n}}\n'
            ).encode()
            out.append(
                FileUnit(content=FileContent(path=f"envs/e{i}/main.tf", raw=raw, size=len(raw)))
            )
        return out


class TestTheManifestCache:
    def test_kept_answers_are_the_fresh_ones(self) -> None:
        ScanCaches.after_scan()
        terraform = EcosystemRegistry.get("terraform")
        units = Tree.units(30)
        files = {u.path: u.content for u in units}
        fresh = [terraform.parse_in_tree(u.content, files) for u in units]
        kept = [Graph.manifest_of(terraform, u, dict(files)) for u in units]
        again = [Graph.manifest_of(terraform, u, dict(files)) for u in units]
        assert kept == fresh and again == fresh
        assert len(Graph._signatures) == 1  # two mapping objects, one view
        ScanCaches.after_scan()
        assert not Graph._parsed and not Graph._views and not Graph._signatures

    def test_a_changed_mapping_is_never_answered_from_its_old_view(self) -> None:
        ScanCaches.after_scan()
        terraform = EcosystemRegistry.get("terraform")
        units = Tree.units(4)
        files = {u.path: u.content for u in units[:3]}
        first = Graph.view_of(files)
        files[units[3].path] = units[3].content  # a caller that broke the rule
        assert Graph.view_of(files) != first
        assert Graph.manifest_of(terraform, units[0], files) == terraform.parse_in_tree(
            units[0].content, files
        )
        ScanCaches.after_scan()

    def test_the_cache_holds_one_view_not_one_per_manifest(self) -> None:
        ScanCaches.after_scan()
        terraform = EcosystemRegistry.get("terraform")
        units = Tree.units(2000)
        files = {u.path: u.content for u in units}
        tracemalloc.start()
        try:
            base, _ = tracemalloc.get_traced_memory()
            for _ in range(3):  # three steps asking, each with its own mapping
                view = dict(files)
                for u in units:
                    Graph.manifest_of(terraform, u, view)
            grown, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # one view of 2,000 paths, 2,000 small entries and the manifests; a view per entry was
        # 2,000 x 2,000 references (about 32 MB in tuples alone). Asserted first, so the old
        # cache fails here, on memory, not on a table it lacked.
        assert grown - base < 12 << 20, f"the cache grew {(grown - base) >> 20} MB"
        assert len(Graph._parsed) == len(units) and len(Graph._signatures) == 1
        ScanCaches.after_scan()
