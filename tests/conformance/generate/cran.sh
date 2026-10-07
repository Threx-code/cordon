#!/bin/sh
# Regenerates the real-world CRAN conformance case: renv installs a project's dependencies (CRAN,
# Bioconductor and a GitHub remote) into its own library and snapshots it to renv.lock. The
# DESCRIPTION uses Depends (with R), Imports, Suggests, LinkingTo, Enhances, Remotes,
# biocViews and SystemRequirements. R's own installed.packages() over the project library --
# independent of the lockfile -- is the authoritative inventory. Only the declared packages' code
# is installed; the project's own code is never run. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" rocker/r-ver:4.4 sh /conformance/generate/cran.sh
set -eu
OUT=/conformance/cases/cran/real-renv
rm -rf /tmp/r && mkdir -p /tmp/r/R && cd /tmp/r

cat > DESCRIPTION <<'EOF'
Package: conformance
Title: A Conformance Fixture
Version: 0.1.0
Authors@R: person("Conformance", "Fixture", role = c("aut", "cre"), email = "fixture@example.invalid")
Description: Exercises every DESCRIPTION dependency field.
License: MIT
Depends:
    R (>= 4.1.0)
Imports:
    jsonlite (>= 1.8.0),
    R6,
    digest,
    BiocGenerics,
    glue
Suggests:
    knitr
LinkingTo:
    Rcpp
Enhances:
    data.table
Remotes:
    github::tidyverse/glue@v1.8.0
biocViews:
SystemRequirements: libxml2, GNU make
Encoding: UTF-8
EOF

Rscript -e '
options(repos = c(CRAN = "https://packagemanager.posit.co/cran/latest"), renv.consent = TRUE)
install.packages("renv")
renv::init(bare = TRUE, restart = FALSE)
renv::install(c("jsonlite", "R6", "digest", "knitr", "Rcpp", "bioc::BiocGenerics", "tidyverse/glue@v1.8.0"), prompt = FALSE)
renv::snapshot(type = "explicit", prompt = FALSE)
' >/tmp/r.log 2>&1 || { tail -30 /tmp/r.log; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT/renv"
cp DESCRIPTION renv.lock "$OUT/"
cp renv/settings.json "$OUT/renv/" 2>/dev/null || printf '{\n  "snapshot.type": "explicit"\n}\n' > "$OUT/renv/settings.json"

Rscript -e '
lib <- renv::paths$library()
ip <- installed.packages(lib.loc = lib, priority = NA_character_)
ip <- ip[!(ip[, "Package"] %in% c("renv")), , drop = FALSE]
pkgs <- sort(paste0(ip[, "Package"], "@", ip[, "Version"]))
suggests <- "installed for Suggests (development only): renv snapshot.dev is false, so the lock records only what Imports, Depends and LinkingTo reach"
locked <- names(jsonlite::read_json("renv.lock")$Packages)
ignore <- list(renv = "renv itself, the tool")
for (p in setdiff(ip[, "Package"], c(locked, "renv"))) ignore[[p]] <- suggests
# installed.packages() lists the Bioconductor installer renv keeps (BiocManager, BiocVersion) too.
writeLines(jsonlite::toJSON(list(tool = "installed.packages() over the renv project library", packages = pkgs, ignore = ignore, lists_tools = TRUE), auto_unbox = TRUE, pretty = TRUE), file.path(commandArgs(TRUE)[1], "authoritative.json"))
cat("installed", length(pkgs), "\n")
' "$OUT"
head -60 renv.lock
echo done
