# action_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| actions-checkout-v4.2.2.tar.gz | https://codeload.github.com/actions/checkout/tar.gz/refs/tags/v4.2.2 (what a workflow's `uses: actions/checkout@v4.2.2` downloads) | MIT (actions/checkout) | curl with a generic User-Agent, kept as served, 2026-11-28 | da55487936ad3c29dafe8ffa5bea7dc5cbea38775f8bb1026ebaf9461e684ab1 |
