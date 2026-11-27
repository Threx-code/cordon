# hackage_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| 01-index-slice.tar | the real https://hackage.haskell.org/01-index.tar (1,058,028,032 bytes, sha256 4da064b3...6e33, equal to the signed snapshot's) | BSD-3-Clause (package.json metadata only, no package content) | the header and data blocks of the last package.json entry of each of the 415 releases cabal.project.freeze pins that the index holds, copied unchanged in index order, then two zero blocks | 887c8a31ce903e62552ce6d40e27856fe2a6841d131a9ae1d155b8cd264cfe51 |
| cabal.project | https://raw.githubusercontent.com/hasura/graphql-engine/master/cabal.project | Apache-2.0 (hasura/graphql-engine) | curl with a generic User-Agent, kept as served, 2026-11-27 | 673ab86b21a06470742a0539a136c3e0c25208b476343e527a72664ba04b1572 |
| cabal.project.freeze | https://raw.githubusercontent.com/hasura/graphql-engine/master/cabal.project.freeze | Apache-2.0 (hasura/graphql-engine) | curl with a generic User-Agent, kept as served, 2026-11-27 | d28faca29b8691b76c5807d54b1138d3d46bec04f411d77234d48533292def75 |
| root.json | https://hackage.haskell.org/root.json | BSD-3-Clause (Hackage metadata) | curl with a generic User-Agent, kept as served, 2026-11-27 | f62e46cb51d4a499a8336894d7a46071b7e528135ad71614c7102c1de0aeeabc |
| snapshot.json | https://hackage.haskell.org/snapshot.json | BSD-3-Clause (Hackage metadata) | curl with a generic User-Agent, kept as served, 2026-11-27 | adde08d36f6bc5e917106dd764f6bfaea65a7ee17c5d2422a0f0e917fd67eb10 |
| timestamp.json | https://hackage.haskell.org/timestamp.json | BSD-3-Clause (Hackage metadata) | curl with a generic User-Agent, kept as served, 2026-11-27 | 146407d119b5ba45bf77ff1fcfb23c5e42add9c22ade9c2c7f632a5761a28a6a |
