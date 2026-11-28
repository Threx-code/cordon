# swift_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| CollectionConcurrencyKit-b4f23e24.tar.gz | https://codeload.github.com/JohnSundell/CollectionConcurrencyKit/tar.gz/b4f23e24b5a1bff301efc5e70871083ca029ff95 | MIT (JohnSundell/CollectionConcurrencyKit) | curl with a generic User-Agent, kept as served | 6d6ea0da0c04d3b63ce0687b3c8402243bd6b9067e073550b88ee20505525118 |
| Package.resolved | the Package.resolved of github.com/realm/SwiftLint | MIT (realm/SwiftLint) | curl with a generic User-Agent, kept as served | 524ccd9c6b987b460da4b1f22dd28b30991f1b9ea1462ed24a638d59a636aa86 |
