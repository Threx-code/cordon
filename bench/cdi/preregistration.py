"""Every threshold and operating line is written down here, in code, before any sealed or fresh number is seen.

A threshold chosen after a number is a threshold chosen to fit the number. So the gate does not read a policy it has not
been told about: each policy id is listed below with the digest of its values, and a policy whose values differ from the
registered ones, or whose id is not listed, is refused. To change a threshold, register a new policy id with its digest in
a change that is reviewed on its own, before the numbers it will judge exist; the old id keeps its old digest, so the
numbers already recorded under it still mean what they meant.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

REGISTERED: Final[dict[str, str]] = {
    "gate-policy/1": "dea013b4995c55885cf268a587a96bdbc327e9e3f83afe6bb60b88a2f992211c",
}
"""Policy id -> sha256 of the policy's canonical JSON (sorted keys, no whitespace)."""


class ThresholdChanged(ValueError):
    """A policy was offered whose thresholds are not the ones registered for its id."""


class Preregistration:
    @staticmethod
    def digest(policy: dict[str, Any]) -> str:
        body = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        return hashlib.sha256(body).hexdigest()

    @classmethod
    def check(cls, policy: dict[str, Any]) -> str:
        """The policy's digest when it is exactly a registered one, else `ThresholdChanged`."""
        policy_id = policy.get("policy_id")
        registered = REGISTERED.get(policy_id) if isinstance(policy_id, str) else None
        if registered is None:
            raise ThresholdChanged(
                f"the policy {policy_id!r} is not pre-registered: register it before using it"
            )
        digest = cls.digest(policy)
        if digest != registered:
            changed = ", ".join(sorted(cls.differences(policy)))
            raise ThresholdChanged(
                f"the policy {policy_id} no longer has the thresholds it was registered with ({changed or 'values'}): "
                "a threshold changed after numbers were recorded under it is refused; register a new policy id"
            )
        return digest

    @staticmethod
    def differences(policy: dict[str, Any]) -> list[str]:
        """The keys of `policy` that are not what the default registered under the same id holds (best effort, for the
        message)."""
        from bench.cdi.gate import DEFAULT_POLICY

        keys = set(policy) | set(DEFAULT_POLICY)
        return [key for key in keys if policy.get(key) != DEFAULT_POLICY.get(key)]
