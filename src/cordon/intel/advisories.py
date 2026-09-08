"""Known-bad packages, and the advisories that name them.

`Category.VULNERABLE` was defined, documented ("A known weakness in something
depended upon. CVE, GHSA, OSV"), threaded through severity floors, policy,
filtering and every reporter -- and emitted by nothing. `Confidence.CONFIRMED`
was documented as reserved for "an exact package-and-version match against the
threat-intelligence database", and there was no such database. So the highest
confidence level the model defines was unreachable, and a whole finding category
existed only as a type.

This module is that database. Two kinds of record, and the distinction matters
more than it looks:

**Malicious.** The package version *is* the attack: a compromised release of an
otherwise legitimate package, or a package published solely to attack. Matching
one is not a judgement call, so it is reported as `MALICIOUS` at `CONFIRMED`
confidence -- the one place that level is warranted, because the finding is an
exact identity match against a recorded incident rather than an inference from
behaviour.

**Vulnerable.** The package version contains a known weakness. Reported as
`VULNERABLE`, which is a different claim: the dependency is not hostile, it is
exposed.

Bundled rather than fetched, and versioned with the release, because a scan must
work offline. The bundled set is deliberately small and covers documented
supply-chain incidents; `AdvisoryDatabase.from_file` loads an organisation's own
export, which is how an air-gapped deployment stays current without this file
growing without bound.

The data below is drawn from public incident reporting. Every entry names a
reference so a reader can check it rather than trust it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Advisory:
    """One record about one package."""

    ecosystem: str
    name: str
    versions: tuple[str, ...]
    """Exact affected versions.

    Exact rather than a range expression. A range needs an ecosystem-specific
    version comparator -- npm semver, PEP 440, Maven, Go -- and getting one
    subtly wrong produces either a missed match or an accusation against a
    version that was never affected. Compromised releases are a short, known
    list, so enumerating them is both simpler and exactly right. Ranges belong
    with the OSV import path, where the exporter has already resolved them.
    """

    malicious: bool
    summary: str
    reference: str
    identifier: str = ""

    def affects(self, version: str | None) -> bool:
        """Whether this record covers a resolved version.

        A dependency with no resolved version does not match. Reporting one
        would mean flagging a package by name alone, and the name is shared with
        every version that was never compromised.
        """
        return bool(version) and version in self.versions


class AdvisoryDatabase:
    """The advisories this installation knows about."""

    def __init__(self, advisories: tuple[Advisory, ...] = ()) -> None:
        self._by_key: dict[tuple[str, str], list[Advisory]] = {}
        for advisory in advisories:
            key = (advisory.ecosystem, advisory.name.lower())
            self._by_key.setdefault(key, []).append(advisory)

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_key.values())

    @classmethod
    def bundled(cls) -> AdvisoryDatabase:
        """The set that ships with this release."""
        return cls(BUNDLED)

    @classmethod
    def from_file(cls, path: str | Path) -> AdvisoryDatabase:
        """Load an export, for an organisation that maintains its own.

        The format is a JSON list of objects with the fields of :class:`Advisory`.
        Deliberately plain: an air-gapped site has to be able to produce this
        from an OSV dump with a short script and no network access at scan time.
        """
        from cordon.core.errors import ConfigError

        file = Path(path)
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"{file}: advisory file is not readable JSON: {exc}") from exc
        if not isinstance(data, list):
            raise ConfigError(f"{file}: advisory file must be a JSON list")

        records: list[Advisory] = []
        for index, raw in enumerate(data):
            if not isinstance(raw, dict):
                raise ConfigError(f"{file}: entry {index} is not an object")
            try:
                records.append(
                    Advisory(
                        ecosystem=str(raw["ecosystem"]),
                        name=str(raw["name"]),
                        versions=tuple(str(v) for v in raw["versions"]),
                        malicious=bool(raw.get("malicious", False)),
                        summary=str(raw.get("summary", "")),
                        reference=str(raw.get("reference", "")),
                        identifier=str(raw.get("id", "")),
                    )
                )
            except (KeyError, TypeError) as exc:
                raise ConfigError(f"{file}: entry {index} is missing {exc}") from exc
        return cls(tuple(records))

    def matching(self, ecosystem: str, name: str, version: str | None) -> tuple[Advisory, ...]:
        """Every record covering this exact package and version."""
        candidates = self._by_key.get((ecosystem, name.lower()), ())
        return tuple(a for a in candidates if a.affects(version))


BUNDLED: tuple[Advisory, ...] = (
    Advisory(
        ecosystem="npm",
        name="event-stream",
        versions=("3.3.6",),
        malicious=True,
        summary=(
            "Handed to a new maintainer who added a dependency containing an "
            "encrypted payload targeting a specific cryptocurrency wallet."
        ),
        reference="https://github.com/advisories/GHSA-mh6f-8j2x-4483",
        identifier="GHSA-mh6f-8j2x-4483",
    ),
    Advisory(
        ecosystem="npm",
        name="flatmap-stream",
        versions=("0.1.1",),
        malicious=True,
        summary="Published solely to carry the event-stream payload.",
        reference="https://github.com/advisories/GHSA-9x64-5r7x-2q53",
        identifier="GHSA-9x64-5r7x-2q53",
    ),
    Advisory(
        ecosystem="npm",
        name="ua-parser-js",
        versions=("0.7.29", "0.8.0", "1.0.0"),
        malicious=True,
        summary=(
            "Maintainer account compromised; the released versions installed a "
            "cryptocurrency miner and a credential stealer."
        ),
        reference="https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
        identifier="GHSA-pjwm-rvh2-c87w",
    ),
    Advisory(
        ecosystem="npm",
        name="coa",
        versions=("2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"),
        malicious=True,
        summary="Maintainer account compromised; released versions ran a credential stealer.",
        reference="https://github.com/advisories/GHSA-73qr-pfmq-6rp8",
        identifier="GHSA-73qr-pfmq-6rp8",
    ),
    Advisory(
        ecosystem="npm",
        name="rc",
        versions=("1.2.9", "1.3.9", "2.3.9"),
        malicious=True,
        summary="Maintainer account compromised; same payload as the coa incident.",
        reference="https://github.com/advisories/GHSA-g2q5-5433-rhrf",
        identifier="GHSA-g2q5-5433-rhrf",
    ),
    Advisory(
        ecosystem="npm",
        name="node-ipc",
        versions=("10.1.1", "10.1.2"),
        malicious=True,
        summary=(
            "The maintainer added code that overwrote files on machines "
            "geolocated to Russia or Belarus."
        ),
        reference="https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
        identifier="GHSA-97m3-w2cp-4xx6",
    ),
    Advisory(
        ecosystem="npm",
        name="node-ipc",
        # A separate incident from the file-overwriting releases above, and a
        # separate advisory. Folding the two into one record made the
        # identifier wrong for whichever version matched.
        versions=("9.2.2",),
        malicious=True,
        summary=(
            "Imports a dependency that writes a file into user directories on "
            "install, added without a version bump signalling it."
        ),
        reference="https://github.com/advisories/GHSA-8gr3-2gjw-jj7g",
        identifier="GHSA-8gr3-2gjw-jj7g",
    ),
    Advisory(
        ecosystem="pypi",
        name="ctx",
        versions=(
            "0.1.2-1",
            "0.1.2-2",
            "0.1.4",
            "0.2",
            "0.2.1",
            "0.2.2",
            "0.2.2.1",
            "0.2.3",
            "0.2.4",
            "0.2.5",
            "0.2.6",
        ),
        malicious=True,
        summary="Abandoned package taken over; released versions exfiltrated environment variables.",
        reference="https://osv.dev/vulnerability/PYSEC-2022-199",
        identifier="PYSEC-2022-199",
    ),
    Advisory(
        ecosystem="pypi",
        name="torchtriton",
        versions=("2.0.0",),
        malicious=True,
        summary=(
            "Dependency-confusion package on PyPI shadowing an internal PyTorch "
            "dependency; uploaded system and credential data on install."
        ),
        reference="https://pytorch.org/blog/compromised-nightly-dependency/",
        # No advisory database carries this incident, so there is no identifier
        # to give. Empty rather than invented: an identifier is a claim that a
        # reader can look up, and one that resolves to nothing -- or worse, to
        # an unrelated advisory -- is more damaging than none at all.
        identifier="",
    ),
)
"""Documented supply-chain incidents, with the versions actually affected.

Small on purpose. This is not a substitute for an advisory feed; it is the set
whose absence made `Category.VULNERABLE` and `Confidence.CONFIRMED` unreachable,
and it is the set most likely to matter to somebody who installs this tool and
scans a lockfile they inherited. Organisations with a feed load their own with
`--advisories`.

Every identifier and version list here was checked against the OSV API rather
than written from memory. That check is the reason for several corrections: an
identifier belonging to an unrelated advisory, two incidents in one record, and
one entry whose identifier did not exist at all. A wrong identifier in a
security tool is worse than a missing one, because it survives review -- it has
the right shape, and the reader who follows it lands on a real page about a
different problem.
"""

__all__ = ["BUNDLED", "Advisory", "AdvisoryDatabase"]
