"""The device's decision runtime, assembled from the device store: what an agent hook asks.

`policy pull` keeps in the store the tenant's pinned root key, the delegation the root signed, the tenant and the verified policy
bundle. This opens them: a `LocalRuntime` that decides from the held bundle (checked against the pinned root again), under a
`CordonRuntime` whose resolvers say what an offline device can say of a name. A name is not looked up in a registry here, so a
package, an MCP server or a skill is an unresolved subject (its stand-in is the hash of what was written) and the policy's own
level for incomplete evidence decides it; a local command is the agent's own action. A store with no pinned root has no runtime
and the caller says so.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.cloud.local_runtime import LocalRuntime
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.cloud.runtime import CordonRuntime, Sources
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.resolve.resolution import Resolution

if TYPE_CHECKING:
    from collections.abc import Callable

PINS: Final = "pin"
RULES_VERSION: Final = "device-offline-1"


class DeviceRuntime:
    """Opens the runtime a store was pulled for."""

    @staticmethod
    def baseline(tenant: str) -> Any:
        """What is asked before any bundle is held: block everything, naming the bundle as the missing evidence."""
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "cordon/strict-baseline",
                    "version": 1,
                    "scope": [tenant],
                    "rules": [],
                    "defaults": {"default": "block", "on_incomplete": {"*": "block"}},
                }
            )
        )

    @classmethod
    def pins(cls, store: LocalStore) -> tuple[bytes, Any, str] | None:
        """The pinned root, the delegation and the tenant, or None when the store was never pulled for."""
        root, delegation, tenant = (
            store.blob(PINS, name) for name in ("root", "delegation", "tenant")
        )
        if root is None or delegation is None or tenant is None:
            return None
        try:
            return root.data, json.loads(delegation.data), tenant.data.decode("utf-8")
        except ValueError:
            return None  # S2: a delegation that is not JSON leaves the device with no runtime, which denies

    @classmethod
    def open(cls, directory: Path, now: datetime) -> tuple[CordonRuntime, LocalStore] | None:
        store = LocalStore(directory)
        pinned = cls.pins(store)
        if pinned is None:
            return None
        root, delegation, tenant = pinned
        local = LocalRuntime(
            root_public=root,
            delegation=delegation,
            tenant=tenant,
            baseline=cls.baseline(tenant),
            store=store,
        )
        local.resume(now)
        return CordonRuntime(
            local, resolvers=cls.resolvers(), sources=Sources(rules_version=RULES_VERSION)
        ), store

    @staticmethod
    def unresolved(kind: str, prefix: str, reason: str) -> Callable[[str], Resolution]:
        def resolve(reference: str) -> Resolution:
            return Resolution.failed(kind, Resolution.stand_in(prefix, reference), reason)

        return resolve

    @classmethod
    def resolvers(cls) -> dict[str, Callable[[str], Resolution]]:
        return {
            "package": cls.unresolved("package", "package", "source_unreachable"),
            "mcp_server": cls.unresolved("mcp_server", "mcp", "source_unreachable"),
            "skill": cls.unresolved("agent_skill", "skill", "source_unreachable"),
            "command": cls.unresolved("agent", "agent", "local_command"),
        }
