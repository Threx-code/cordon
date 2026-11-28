# sbom_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| cdxgen-terraform-nix.json | components as CycloneDX/cdxgen's own tests assert them: lib/ecosystems/parsers-terraform.poku.js (proposed types at parsers-terraform.js:253, :1197), lib/ecosystems/parsers-misc.js:1448-1458, lib/inventory/purl.js `nixGenericPurl` | Apache-2.0 (CycloneDX/cdxgen) | written by hand from those assertions; not a tool run (the sources and their sha256 are in ~/cordon-work-backup/captures-20261127/formats/CAPTURES.md) | f06a52c52f850cce67e70aca8fd37fd6007a493304c3016ff4aa63d4dfa44839 |
