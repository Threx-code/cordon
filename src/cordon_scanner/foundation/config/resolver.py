"""Which configuration a scan runs under, and where each setting came from: the built-in defaults, the
organisation's signed policy, the user's file, the repository's file and the command line, layered
in that order, with what an untrusted layer may not loosen held back.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from cordon_scanner.foundation.config.parser import ConfigParser
from cordon_scanner.foundation.config.policy import MAX_SUPPRESSION_DAYS, OrgConstraints
from cordon_scanner.foundation.config.provenance import Layer, Provenance
from cordon_scanner.foundation.config.settings import CONFIG_VERSION, TOP_LEVEL_KEYS, Config
from cordon_scanner.foundation.distribution import PolicyDistribution
from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Severity,
)
from cordon_scanner.foundation.paths import StatePaths


class ConfigResolver:
    """Assembles the effective configuration from all four layers.

    Order is defaults, organisation policy, repository file, command line, and
    it is not adjustable. The organisation layer is a ceiling rather than
    another set of values: later layers may make a setting stricter and may not
    relax one, so a repository cannot lower a threshold its organisation set.

    The repository layer is the one that needs care, because it comes from
    inside the scan target and the scan target is untrusted. Powers that a
    configuration file could turn against the machine running the scan -- rule
    packs, resource limits -- are withheld from that layer and reported as
    withheld.
    """

    # ---------------------------------------------------------------------------
    # Organisation policy loading
    # ---------------------------------------------------------------------------

    _ORG_TOP_KEYS = frozenset(
        {
            "version",
            "name",
            "issued",
            "issuer",
            "enforce",
            "suppressions",
            "scoring",
            "fail_on",
            "scan",
            "evidence",
            "rules",
            "policy",
        }
    )
    _ENFORCE_KEYS = frozenset(
        {
            "detectors_required",
            "min_severity_threshold",
            "min_confidence_threshold",
            "allow_network",
            "allow_plugins",
            "allow_extra_rule_packs",
            "allow_limit_increase",
            "max_total_timeout",
        }
    )
    _ORG_SUPPRESSION_KEYS = frozenset(
        {
            "max_duration_days",
            "require_justification",
            "require_approver",
            "forbid_categories",
            "forbid_path_only",
        }
    )

    @classmethod
    def load_org_policy(
        cls,
        path: str | Path,
        *,
        allow_network: bool = False,
        cache_dir: Path | None = None,
    ) -> tuple[Config, OrgConstraints]:
        """Load an organisation policy: its settings and its constraints.

        Returns the policy's own configuration (used as the upper layer in the merge)
        and the constraints it imposes on repository configurations.

        A URL is accepted and resolved to a verified local file first. It must
        carry a `#sha256=` digest, because this document is the ceiling -- the
        thing that says a repository may not disable a detector or suppress a
        category -- and fetching it over an unauthenticated channel would let
        whoever controls the network switch the control off across every
        repository at once.
        """
        source = str(path)
        if not PolicyDistribution.is_remote(source) and "#sha256=" in source:
            path = PolicyDistribution.verify_local(source)
        elif PolicyDistribution.is_remote(source):
            path = PolicyDistribution.resolve(
                source,
                allow_network=allow_network,
                cache_dir=cache_dir or StatePaths.default_cache_dir(),
            )

        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"organisation policy not found: {p}")
        data = RestrictedYamlParser._load_yaml_subset(Config.read_bounded(p), source=str(p))
        ConfigParser._reject_unknown(data, cls._ORG_TOP_KEYS, str(p))

        enforce, sup, forbid = cls._enforced_sections(data, p)

        constraints = ConfigResolver._constraints(enforce, p, sup, forbid)

        # The policy's own scan settings form the upper configuration layer.
        body = {k: v for k, v in data.items() if k in TOP_LEVEL_KEYS and k != "suppressions"}
        body.setdefault("version", CONFIG_VERSION)
        org_config = ConfigParser._parse_config(body, source=str(p), layer=Layer.ORG, into=Config)

        if constraints.max_total_timeout is not None:
            org_config = replace(
                org_config,
                limits=org_config.limits.merged(total_timeout=constraints.max_total_timeout),
            )

        return org_config, constraints

    @classmethod
    def _enforced_sections(
        cls, data: dict[str, Any], p: Path
    ) -> tuple[dict[Any, Any], dict[Any, Any], frozenset[Category]]:
        """The enforce and suppression sections of an organisation policy, every key checked."""
        enforce = data.get("enforce") or {}
        if not isinstance(enforce, dict):
            raise ConfigError(f"{p}: `enforce` must be a mapping")
        ConfigParser._reject_unknown(enforce, cls._ENFORCE_KEYS, f"{p}: enforce")

        sup = data.get("suppressions") or {}
        if not isinstance(sup, dict):
            raise ConfigError(
                f"{p}: in an organisation policy, `suppressions` is a mapping of constraints, "
                "not a list of suppressions"
            )
        ConfigParser._reject_unknown(sup, cls._ORG_SUPPRESSION_KEYS, f"{p}: suppressions")

        forbid_raw = sup.get("forbid_categories", ["malicious"])
        try:
            forbid = frozenset(Category(c) for c in forbid_raw)
        except ValueError as exc:
            raise ConfigError(f"{p}: suppressions.forbid_categories: {exc}") from exc
        return enforce, sup, forbid

    @staticmethod
    def _constraints(
        enforce: dict[Any, Any], p: Path, sup: dict[Any, Any], forbid: frozenset[Category]
    ) -> OrgConstraints:
        """The organisation's constraints, from its enforce and suppression sections."""
        return OrgConstraints(
            detectors_required=frozenset(
                ConfigParser._as_str_tuple(
                    enforce.get("detectors_required"), f"{p}: enforce.detectors_required"
                )
            ),
            min_severity_threshold=(
                Severity.parse(enforce["min_severity_threshold"])
                if "min_severity_threshold" in enforce
                else None
            ),
            min_confidence_threshold=(
                Confidence.parse(enforce["min_confidence_threshold"])
                if "min_confidence_threshold" in enforce
                else None
            ),
            allow_network=bool(enforce.get("allow_network", True)),
            allow_plugins=bool(enforce.get("allow_plugins", False)),
            allow_extra_rule_packs=bool(enforce.get("allow_extra_rule_packs", True)),
            allow_limit_increase=bool(enforce.get("allow_limit_increase", False)),
            # Read, at last. `max_total_timeout` was in `_ENFORCE_KEYS`, so the
            # strict key validator accepted it, and `OrgConstraints` was built
            # without it -- leaving the field `None`, so the block that would
            # apply it never ran. An organisation believed a ceiling was in
            # force and the 900s default applied. The module's own docstring
            # names this failure: "the same failure in a different costume".
            max_total_timeout=(
                float(enforce["max_total_timeout"])
                if enforce.get("max_total_timeout") is not None
                else None
            ),
            max_suppression_days=int(sup.get("max_duration_days", MAX_SUPPRESSION_DAYS)),
            require_justification=bool(sup.get("require_justification", True)),
            require_approver=bool(sup.get("require_approver", False)),
            forbid_path_only_suppressions=bool(sup.get("forbid_path_only", True)),
            forbid_suppressing=forbid,
        )

    @staticmethod
    def resolve(
        *,
        root: str | Path = ".",
        config_path: str | Path | None = None,
        policy_path: str | Path | None = None,
        allow_network: bool = False,
        **cli_overrides: Any,
    ) -> Config:
        """Build the effective configuration from all four layers.

        This is the only supported way to assemble a Config for a scan. Constructing
        one directly skips the ceiling enforcement, which is why the CLI and the SDK
        both route through here.
        """
        # An explicitly passed --config is operator input and is trusted. A config
        # discovered inside the scan target is not: it is part of the untrusted
        # input, and two of its powers are withheld accordingly.
        if config_path:
            repo = Config.from_file(config_path)
        else:
            repo = Config.discover(root)
            if repo != Config.default():
                repo = repo._withhold_untrusted_powers()

        # An explicit --policy wins over the environment. An attacker who can
        # set variables in a build -- a `.env` sourced by a Makefile, an `env:`
        # block in a workflow, a compromised shell profile -- could otherwise
        # point CORDON_POLICY at a crafted file and break every build, or aim it
        # at an unrelated file to have its parse error name that file's keys.
        from_environment = policy_path is None
        policy_source = policy_path or os.environ.get("CORDON_POLICY")
        if policy_source:
            org_config, constraints = ConfigResolver.load_org_policy(
                policy_source,
                # A policy URL is fetched only when network access was asked
                # for. A tool that reaches out because an argument happened to
                # begin with `https://` has network behaviour nobody can audit.
                allow_network=allow_network,
            )
            repo = repo.clamped_by(org_config, constraints)
            if from_environment:
                # Recorded so the report says where the policy came from. A
                # ceiling nobody can see the origin of is one nobody can audit.
                repo = replace(
                    repo,
                    provenance=(
                        *repo.provenance,
                        Provenance(
                            key="policy",
                            value=str(policy_source),
                            source="$CORDON_POLICY",
                            layer=Layer.ORG,
                        ),
                    ),
                )
        elif repo.from_untrusted_source:
            # The default ceiling still applies. `_suppression_violation` was
            # reachable only through `clamped_by`, which runs only when a policy
            # file is configured -- so with no policy, and that is almost every
            # repository, `OrgConstraints.permissive()` sat on the config and
            # was never consulted. A repository could write `expires:
            # 9999-12-31` with a forty-character justification and suppress a
            # finding about itself forever, and MAX_SUPPRESSION_DAYS had no
            # effect at all.
            #
            # Only the suppression rules are enforced here, and only for a
            # configuration that came from inside the scan target. The other
            # constraints (required detectors, minimum thresholds) express an
            # organisation's intent and have no meaning without an organisation.
            repo._check_suppressions(OrgConstraints.permissive())

        return repo.with_overrides(**cli_overrides)


__all__ = ["ConfigResolver"]
