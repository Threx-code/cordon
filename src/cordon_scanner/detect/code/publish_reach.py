"""Whether a published package's publishing script can run on the machine that installs it.

`SUSPECT.REGISTRY.SELF_PUBLISH.001` reads one act, a publishing command handed to something that
runs it. In a published npm package that act is a worm only where something runs it for a consumer:
an install hook, a library entry point (`main`, `exports`), or a file one loads. A `bin` is a command
a person runs, as a release script is: a publishing CLI publishes when its user asks it to. A release
task in `tasks/` or a spam publisher's `auto.js` that nothing requires, no hook runs and no entry
names publishes only when its owner runs it (review 98 G6: 35 benign units blocked on it alone; its
six labelled spam siblings adjudicated clause (c), no consumer payload). Outside a published
package -- a source tree, an installed `node_modules` -- nothing is lowered: entry points are not
known there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext


class PublishReach:
    RULE: ClassVar[str] = "SUSPECT.REGISTRY.SELF_PUBLISH.001"
    REASON: ClassVar[str] = "a publishing script nothing installs or loads"

    @staticmethod
    def unreached(rule_id: str, path: str, ctx: ScanContext) -> bool:
        """Whether this is the publishing rule, in a published npm package's file that no install
        hook, entry point or entry's import runs."""
        if (
            rule_id != PublishReach.RULE
            or not ctx.package_distribution
            or ctx.distribution != "npm"
        ):
            return False
        return not (
            ctx.in_install_hook(path)
            or path in ctx.library_entry_paths
            or path in ctx.library_closure_paths
        )
