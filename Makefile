# Everything a contributor runs, and everything the release needs checked first.
#
# **There is no upload target, and its absence is the point.** Publishing goes
# through `.github/workflows/release.yml` on a `v*` tag, using PyPI trusted
# publishing: the identity is minted from the workflow run itself and no API
# token exists anywhere -- not in the repository, not in CI, not on a laptop.
# A `twine upload dist/*` here would need one, which is precisely the
# long-lived credential that design removes, and it would skip the SBOM, the
# SLSA provenance, the Sigstore signatures and the post-publish digest
# confirmation that the workflow performs. The artefact would reach PyPI with
# no provenance at all -- which this project's own
# `POLICY.RELEASE.NO_PROVENANCE.001` rule reports as a finding.
#
# So `make release` verifies, tags and pushes. GitHub publishes.

PY := .venv/bin/python
PKG := cordon_scanner
VERSION := $(shell $(PY) -c "from $(PKG).version import __version__; print(__version__)" 2>/dev/null)

.DEFAULT_GOAL := help
.PHONY: help setup fmt lint types test test-all scan check live matrix demo \
        build verify preflight guards release clean

help:  ## List the targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# -- Develop ---------------------------------------------------------------

setup:  ## Create .venv and install the package with its dev extra
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

fmt:  ## Format
	$(PY) -m ruff format src/ tests/ scripts/
	$(PY) -m ruff check --fix src/ tests/ scripts/

# -- Verify ----------------------------------------------------------------
#
# Each target mirrors a CI job, so a green `make check` means the same thing
# locally that it means on a runner. Where they differ, CI is authoritative --
# it runs on three operating systems and this runs on one.

lint:  ## ruff check and format --check
	$(PY) -m ruff check src/ tests/
	$(PY) -m ruff format --check src/ tests/

types:  ## mypy, strict
	$(PY) -m mypy src/$(PKG)

test:  ## The suite, across every core
	@# `-n auto` is not a convenience. Serial, coverage-instrumented, this suite is
	@# seventeen thousand tests and takes hours; distributed across the cores of an
	@# ordinary laptop it is under six minutes, and the coverage total is identical
	@# because pytest-cov combines the workers' data before it reports. `pytest-xdist`
	@# has been in the dev extra from the start, described there as being for exactly
	@# this, and nothing used it -- so the documented way to run the suite was the one
	@# nobody could afford to run, which is the same as having no suite locally.
	$(PY) -m pytest -q -n auto --cov=$(PKG) --cov-report=term-missing

test-fast:  ## The suite with no coverage, for the edit-run loop
	@# Seventy seconds rather than six minutes. Coverage instrumentation is most of
	@# what is left once the work is parallel, and the gate it feeds belongs in
	@# `check` and CI rather than in the loop somebody runs on every save.
	$(PY) -m pytest -q -n auto

test-all: test  ## The suite plus the perf and fuzz markers, which CI deselects
	$(PY) -m pytest -q -m perf -s tests/perf/
	$(PY) -m pytest -q -m fuzz tests/fuzz/

scan:  ## Cordon scans Cordon
	@# A security tool that cannot pass its own checks has no standing to
	@# enforce them. The corpus is excluded because it holds deliberate
	@# payloads whose whole purpose is to be detected.
	@# build/ and dist/ hold a copy of src/ left by a previous `make build`.
	@# Scanning them reports every finding a second time, against a path that
	@# is not in the repository.
	@# `--tracked`, so this scans the REPOSITORY rather than the working directory.
	@# Without it the scan walks gitignored paths too: `.iac-schema/` holds third-party
	@# Terraform and CloudFormation fixtures pulled down for schema work, and scanning
	@# those reported 69 critical and 726 high findings against code this project did
	@# not write and does not ship. CI never saw it because a fresh checkout has no
	@# such directory -- so the target passed in CI and failed for anyone who had done
	@# the schema work, which is the worst way round.
	$(PY) -m $(PKG) scan . --tracked --exclude 'corpus/**' --exclude 'build/**' \
		--exclude 'dist/**' --exclude '**/intel/data/**' \
		--exclude '**/detect/data/**' --fail-on medium --no-color

check: lint types test scan  ## Everything CI checks, in CI's order

# -- Generated artefacts ---------------------------------------------------

matrix:  ## Regenerate the generated docs (coverage matrix, ecosystem table)
	$(PY) tests/matrix.py > docs/05-COVERAGE-MATRIX.md
	PYTHONPATH=tests $(PY) tests/ecosystems.py > docs/07-ECOSYSTEMS.md

demo: DEMO := corpus/malicious/compromised-npm-package
demo:  ## Regenerate the README image from a real scan
	@# Real output, captured rather than drawn.
	@#
	@# The target is a committed corpus sample, not a fixture written here.
	@# It was written here, and Cordon reported this file: a Makefile is a
	@# build hook, and a recipe holding `curl ... | sh` beside a read of
	@# `~/.npmrc` is a dropper and a credential theft by every rule this
	@# project ships. It was right, and the sample belongs in the corpus
	@# anyway -- where it is guarded by an `expected.yaml` like every other
	@# one, and excluded from both the self-scan and the sdist.
	@#
	@# FORCE_COLOR because the colour the image exists to show is gated on a
	@# terminal, and this is a pipe.
	cd $(DEMO) && COLUMNS=118 FORCE_COLOR=1 $(CURDIR)/$(PY) -m $(PKG) scan . --no-cache \
		| $(CURDIR)/$(PY) $(CURDIR)/scripts/render_demo.py \
			--command "cordon-scanner scan ." --out $(CURDIR)/docs/assets/demo.svg

# -- Release ---------------------------------------------------------------

build:  ## Build the wheel and sdist with the hash-pinned toolchain
	rm -rf dist build
	$(PY) -m pip install --quiet --require-hashes -r requirements-build.txt
	$(PY) -m build --no-isolation

# The commit SHA the workflow pins is published as an image *tag*, not as a
# digest, so this is `:` and not `@sha256:`. Read out of the workflow rather
# than repeated here, so the cross-check can never drift from the pin it is
# supposed to be checking.
PUBLISHER := ghcr.io/pypa/gh-action-pypi-publish:$(shell \
	sed -n 's/.*gh-action-pypi-publish@\([0-9a-f]\{40\}\).*/\1/p' \
	.github/workflows/release.yml)

verify: build  ## Check the built artefacts the way the release does
	$(PY) -m pip install --quiet twine
	$(PY) -m twine check dist/*
	@# ...and then the way the release *actually* does, which is not the same
	@# thing. This checked only with local twine, which is current, while the
	@# publisher runs a pinned image whose twine is whatever it shipped with.
	@# v1.12.2 carried twine 5.1.1 and pkginfo 1.10, which support
	@# Metadata-Version up to 2.3; setuptools 80 writes 2.4. Local `twine
	@# check` passed, the release failed on "Metadata is missing required
	@# fields: Name, Version" for a wheel whose first three lines are the
	@# metadata version, the name and the version -- and the first anyone knew
	@# was a failed publish.
	@#
	@# Two pins that are each correct can still disagree, so the check has to
	@# use the publisher's own image. Skipped without Docker rather than
	@# failing: it is a cross-check, and the local one above still ran.
	@command -v docker >/dev/null 2>&1 || { echo "no docker; skipped the publisher cross-check"; exit 0; }
	@echo "cross-checking with $(PUBLISHER)"
	@docker run --rm --entrypoint sh -v "$(CURDIR)/dist:/dist" $(PUBLISHER) \
		-c 'twine check /dist/*' 2>&1 | grep -v "^WARNING" \
		|| { echo "the publisher's twine rejects these artefacts"; exit 1; }
	@# The wheel must install into a clean environment with no runtime
	@# dependencies, and both entry points must behave: the scanner scans,
	@# and the sandbox refuses without its flag.
	@rm -rf .verify && python3 -m venv .verify
	.verify/bin/pip install --quiet dist/*.whl
	@# The metadata's own `Requires:`, not the environment's contents. A fresh
	@# venv holds pip whatever we install into it, so `pip list` can never be
	@# empty and a check written against it fails on every machine.
	@test -z "$$(.verify/bin/pip show cordon-scanner | sed -n 's/^Requires: *//p')" \
		|| (echo "the wheel declares a runtime dependency" && exit 1)
	@echo "no runtime dependencies"
	.verify/bin/cordon-scanner --version
	@.verify/bin/cordon-sandbox pypi six > /dev/null 2>&1 \
		&& (echo "the sandbox ran without --sandbox" && exit 1) \
		|| echo "cordon-sandbox refuses without --sandbox"
	@rm -rf .verify
	@echo "wheel and sdist verified"

live:  ## The checks that need a live registry (network; not part of `check`)
	@# Deliberately NOT a prerequisite of `check`. Everything in `check` runs
	@# offline so the suite passes in an air-gap and never goes red because a
	@# registry is slow. These need egress, so they are their own target and
	@# their own workflow -- and `preflight` requires them, because the defects
	@# they catch are the ones that reach users.
	$(PY) scripts/live_checks.py

preflight: check live verify  ## Everything the release will do, before tagging

guards:  ## The cheap checks a release must pass, on their own
	@# Ordered before `preflight`, not after. Make runs prerequisites left to
	@# right, and finding out that the tree is dirty or the changelog has no
	@# entry belongs at the start of a release rather than four minutes into
	@# one.
	@test -n "$(VERSION)" || (echo "could not read the version; run make setup" && exit 1)
	@test -z "$$(git status --porcelain)" \
		|| (echo "the working tree is dirty; commit or stash first" && exit 1)
	@test "$$(git rev-parse --abbrev-ref HEAD)" = "main" \
		|| (echo "releases are cut from main" && exit 1)
	@git fetch --quiet origin main
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" \
		|| (echo "HEAD and origin/main differ; push or pull first" && exit 1)
	@# `cmd && (exit 1) || true` prints the refusal and then succeeds: the
	@# `|| true` that stops rev-parse's own non-zero exit from failing the
	@# recipe also swallows the exit meant to stop the release. The guard said
	@# "v0.1.0 already exists" and passed. An `if` says one thing at a time.
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "v$(VERSION) already exists; bump the version first"; exit 1; \
	fi
	@grep -q "^## \[$(VERSION)\]" CHANGELOG.md \
		|| (echo "CHANGELOG.md has no entry for $(VERSION)" && exit 1)
	@echo "guards passed for v$(VERSION)"

release: guards preflight  ## Tag v$(VERSION) and push, which is what publishes
	@# The tag is the trigger, and a tag pushed to a public repository is not
	@# something that can be quietly taken back.
	@echo
	@echo "About to tag v$(VERSION) and push it to origin."
	@echo "That starts .github/workflows/release.yml, which publishes to PyPI."
	@echo
	git tag -a "v$(VERSION)" -m "cordon-scanner $(VERSION)"
	git push origin "v$(VERSION)"
	@echo
	@echo "Pushed. Watch it with: gh run watch"

clean:  ## Remove build output and caches
	rm -rf dist build .verify .demo .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
