# cran_captures

Real files these tests read; each row says where the file came from and how, and the sha256 of the file as committed
(`tests/unit/repository/release/test_fixture_provenance.py` checks the table).

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| bioconductor.lock | https://raw.githubusercontent.com/rstudio/renv/main/tests/testthat/resources/bioconductor.lock | MIT (rstudio/renv) | curl with a generic User-Agent, kept as served | 33696651885523f63444cc9e7c3d12192343cff4a3c20dcb9d8e9cae381c2483 |
| cran-R6_2.5.1.tar.gz | https://cran.r-project.org/src/contrib/Archive/R6/R6_2.5.1.tar.gz | MIT (R6) | curl with a generic User-Agent, kept as served | 8d92bd29c2ed7bf15f2778618ffe4a95556193d21d8431a7f75e7e5fc102bf48 |
| crandb-R6-all.json | https://crandb.r-pkg.org/R6/all | MIT (R6 metadata) | curl with a generic User-Agent, kept as served | 6ffc120e2252f462f38855f429c08a3bd2c2e4bafadc0d0681c4e01a745aac72 |
| renv.lock | written by renv 1.3.1 in rocker/r-ver@sha256:78cb94ce2db23aaaf7b546450fcf70b5a3f2ace5a9b5fa1f87217da329211312 with no network: R6 2.5.1 installed from CRAN's tarball, `renv::snapshot(type = "all")` | GPL-3 (renv); output of the tool | docker run --network none, read-only mounts of renv_1.3.1.tar.gz and R6_2.5.1.tar.gz (sha256 in ~/cordon-work-backup/captures-20261127/formats/CAPTURES.md) | 0f0fb2e22d2b077d54610cfc1d196d11646d2cae43ff4f728ee942eaf9d3e04c |
