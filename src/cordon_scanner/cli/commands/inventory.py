"""`inventory`: what the repository is -- its files, languages and install hooks -- and the evidence
for each."""

from __future__ import annotations

import argparse

from cordon_scanner.foundation.errors import ExitCode


class InventoryCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        inventory = sub.add_parser(
            "inventory", help="print what the repository is, and the evidence for it"
        )
        inventory.add_argument("target", nargs="?", default=".")
        inventory.add_argument("--format", "-f", default="text", choices=["text", "json"])

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        import json

        from cordon_scanner import Scanner

        inventory = Scanner().inventory(args.target)

        if args.format == "json":
            print(json.dumps(inventory.to_dict(), indent=2, sort_keys=True))
            return int(ExitCode.CLEAN)

        print(f"{inventory.root}")
        print(f"{inventory.file_count} files, {inventory.total_bytes:,} bytes\n")

        if inventory.languages:
            print("languages")
            for stat in inventory.languages:
                evidence = ", ".join(stat.evidence[:4])
                print(
                    f"  {stat.language:<14}{stat.share * 100:5.1f}%  {stat.files:>5} files   {evidence}"
                )
            print()

        if inventory.hooks:
            # Listed prominently because execution context is the largest multiplier
            # in the risk model: these are the paths where ordinary capabilities
            # become mechanisms.
            print("install and build hooks (code that runs before any other control)")
            for hook in inventory.hooks:
                print(f"  {hook.kind:<10}{hook.path}")
            print()

        return int(ExitCode.CLEAN)


__all__ = ["InventoryCommand"]
