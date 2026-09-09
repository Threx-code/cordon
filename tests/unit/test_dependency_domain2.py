"""Dependency confusion, combosquatting, and manifests without lockfiles.

Three attacks on a dependency's *name* rather than on its contents, which is
what makes them cheap: none requires compromising anything, and two require no
mistake by the victim at all.

The negative cases carry most of the weight here. Wrapping a popular name is
how a very large number of legitimate packages are named -- `eslint-plugin-
react` and `pytest-django` exist because that is the convention -- so a rule
that treats the shape as suspicious reports on most repositories and is
switched off in a day.
"""

from __future__ import annotations

from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.dependency import DependencyDetector
from cordon_scanner.rules.loader import RuleLoader, RuleSet


def dependency(name: str, *, ecosystem: str = "npm", resolved: str | None = None) -> Dependency:
    return Dependency(
        purl=f"pkg:{ecosystem}/{name}",
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        direct=True,
        scope=Scope.RUNTIME,
        resolved_from=resolved,
        declared_in="package-lock.json",
    )


def findings_for(*deps: Dependency, namespaces: tuple[str, ...] = ()) -> list[str]:
    ctx = ScanContext(
        config=Config.default() if not namespaces else _config_with(namespaces),
        rules=RuleSet(RuleLoader.load_builtin()),
        dependencies=deps,
    )
    return [f.rule_id for f in DependencyDetector().inspect(GraphUnit(dependencies=deps), ctx)]


def _config_with(namespaces: tuple[str, ...]) -> Config:
    from dataclasses import replace

    return replace(Config.default(), internal_namespaces=namespaces)


PUBLIC_NPM = "https://registry.npmjs.org/@acme/utils/-/utils-9.0.0.tgz"
PRIVATE = "https://npm.acme-internal.example/@acme/utils/-/utils-1.2.3.tgz"


class TestDependencyConfusion:
    def test_an_internal_name_from_the_public_registry(self) -> None:
        """The attack needs no typo and no mistake. A resolver asked for a name
        takes the highest version any configured registry offers, so publishing
        the internal name publicly at a higher version simply wins."""
        found = findings_for(dependency("@acme/utils", resolved=PUBLIC_NPM), namespaces=("@acme/",))
        assert "SUSPECT.DEPENDENCY.CONFUSION.001" in found

    def test_an_internal_name_with_no_recorded_source(self) -> None:
        """Unpinned is the same exposure. Nothing says the internal registry
        will be the one that answers."""
        found = findings_for(dependency("@acme/utils", resolved=None), namespaces=("@acme/",))
        assert "SUSPECT.DEPENDENCY.CONFUSION.001" in found

    def test_an_internal_name_from_the_internal_registry_is_correct(self) -> None:
        found = findings_for(dependency("@acme/utils", resolved=PRIVATE), namespaces=("@acme/",))
        assert "SUSPECT.DEPENDENCY.CONFUSION.001" not in found

    def test_a_public_scoped_name_is_not_confusion(self) -> None:
        """Most scoped packages are public and ordinary. Only a namespace the
        project declares internal carries the claim."""
        found = findings_for(
            dependency("@babel/core", resolved="https://registry.npmjs.org/@babel/core.tgz"),
            namespaces=("@acme/",),
        )
        assert "SUSPECT.DEPENDENCY.CONFUSION.001" not in found

    def test_the_check_is_off_without_configuration(self) -> None:
        """Whether a name is supposed to come from somewhere private is a fact
        about the organisation, not about the code. With no answer supplied the
        honest behaviour is silence, not a guess."""
        found = findings_for(dependency("@acme/utils", resolved=PUBLIC_NPM))
        assert "SUSPECT.DEPENDENCY.CONFUSION.001" not in found


class TestCombosquattingWasRemoved:
    """Recorded rather than deleted quietly.

    A name that wraps a popular one -- `python-requests-oauth` -- is a real
    attack, and detecting it by name alone is not viable offline. Scanning
    twenty-one widely used repositories produced a hundred and ninety-three
    findings against Vue's lockfile, every one of them legitimate:
    `fast-glob`, `is-glob`, `neo-async`, `typescript-eslint`, `click-plugins`.
    Each is structurally identical to a squat.

    Separating them needs to know who publishes each package and how widely it
    is installed. That is registry data a scan does not have and must not fetch
    by default, so the rule is gone rather than shipped at a severity chosen to
    make its noise tolerable.
    """

    def test_the_rule_is_not_declared(self) -> None:
        declared = {r.id for r in DependencyDetector.declared_rules()}
        assert "SUSPECT.DEPENDENCY.COMBOSQUAT.001" not in declared

    def test_the_detector_has_no_resolver_left_behind(self) -> None:
        assert not hasattr(DependencyDetector, "_combosquat_target")

    def test_typosquatting_still_works(self) -> None:
        """The rule that *is* viable offline, and the reason removing the other
        one costs less than keeping it: edit distance plus a plausible-slip
        test plus a known-package check is precise enough to survive contact
        with real lockfiles."""
        assert DependencyDetector()._typosquat_target("npm", "lodahs") == "lodash"
        assert DependencyDetector()._typosquat_target("npm", "fast-glob") is None


class TestManifestsWithoutLockfiles:
    """A repository without a lockfile is not one without dependencies.

    The graph was built from lockfiles alone, so a typosquat in a
    `package.json` with no `package-lock.json` beside it produced nothing,
    while the identical typo next to a lockfile was reported at high. The check
    that matters most for an unpinned project was the one that did not run.
    """

    def scan(self, tmp_path, files: dict[str, str]) -> list[str]:
        from cordon_scanner import Scanner

        for name, body in files.items():
            (tmp_path / name).write_text(body, encoding="utf-8")
        return [f.rule_id for f in Scanner().scan(tmp_path).findings]

    MANIFEST = (
        '{"name": "app", "version": "1.0.0", '
        '"dependencies": {"lodahs": "^4.17.21", "express": "^4.18.2"}}'
    )

    def test_a_typosquat_declared_without_a_lockfile_is_found(self, tmp_path) -> None:
        found = self.scan(tmp_path, {"package.json": self.MANIFEST})
        assert "SUSPECT.DEPENDENCY.TYPOSQUAT.001" in found

    def test_declared_dependencies_claim_no_version(self, tmp_path) -> None:
        """They are declared, not resolved: the spec is a range and nothing
        records where the package would come from. Rules that need a resolved
        version must skip them rather than guess, so no integrity finding is
        raised for something that has no lockfile to carry a hash."""
        found = self.scan(tmp_path, {"package.json": self.MANIFEST})
        assert "POLICY.DEPENDENCY.INTEGRITY.001" not in found

    def test_a_clean_manifest_stays_clean(self, tmp_path) -> None:
        manifest = (
            '{"name": "app", "version": "1.0.0", '
            '"dependencies": {"react": "^18.2.0", "express": "^4.18.2"}}'
        )
        assert self.scan(tmp_path, {"package.json": manifest}) == []
