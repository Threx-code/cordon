"""What a finished scan writes and sends: its reports in each format asked for, whether they carry
colour, the gate-failure notifications, and the upload to Cordon Cloud."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.foundation.errors import ConfigError
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.results import ScanResult


class ScanOutput:
    @staticmethod
    def upload(args: argparse.Namespace, result: ScanResult, verdict: Any, target: Path) -> None:
        """Send the results. Reported on stderr, never allowed to change the exit code."""
        from cordon_scanner.cloud import CloudError, auth, results

        try:
            credentials = auth.CloudAuth.current(args.cloud_url)
            ambient = auth.CloudAuth.ambient_identity_token()
            # A token for Sigstore's own audience, when the pipeline minted one (GitLab, CircleCI,
            # Buildkite); otherwise sigstore asks the CI for one itself (GitHub Actions).
            signer = (
                results.SignedResults.sigstore_signer(os.environ.get("SIGSTORE_ID_TOKEN") or None)
                if ambient is not None
                else None
            )
            receipt = results.SignedResults.upload(
                result,
                credentials,
                exit_code=int(verdict.exit_code),
                reason=str(verdict.reason),
                signer=signer,
                ai_document=results.SignedResults.ai_inventory(target, result),
            )
        except CloudError as exc:
            print(f"{PROGRAM}: upload failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"{PROGRAM}: upload failed while signing: {type(exc).__name__}", file=sys.stderr)
            return
        if not args.quiet:
            trust = (
                "signed with the CI identity"
                if receipt.signing == "sigstore"
                else "unsigned, vouched for by the sign-in"
            )
            where = f" {receipt.url}" if receipt.url else ""
            print(f"{PROGRAM}: uploaded scan {receipt.scan_id} ({trust}){where}", file=sys.stderr)

    @staticmethod
    def notify(
        channels: tuple[str, ...], result: ScanResult, verdict: Any, *, verbose: bool
    ) -> None:
        """Post the gate failure. Reported on stderr, never allowed to change the exit code."""
        from cordon_scanner.notify.notifier import Notifier

        deliveries = Notifier().send(
            channels, result, reason=str(verdict.reason), exit_code=int(verdict.exit_code)
        )
        for delivery in deliveries:
            if not delivery.ok:
                print(
                    f"{PROGRAM}: notify {delivery.channel} failed: {delivery.error}",
                    file=sys.stderr,
                )
            elif verbose:
                print(f"{PROGRAM}: notified {delivery.channel}", file=sys.stderr)

    @staticmethod
    def use_color(disabled: bool) -> bool:
        """Whether to emit colour, by the conventions people already have.

        `--no-color` wins, then `NO_COLOR` (no-color.org: set to anything at
        all means no colour), then `FORCE_COLOR` for the case a terminal test
        cannot answer -- a CI log viewer that renders escapes, or a capture
        being piped into something that wants them. Without `FORCE_COLOR`
        there is no way to get coloured output that is not a terminal, which
        is what rendering this project's own README image needs.
        """
        if disabled or os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        return sys.stdout.isatty()

    @staticmethod
    def emit(
        result: ScanResult,
        formats: Sequence[str],
        single_output: str | None,
        opts: object,
        *,
        quiet: bool,
    ) -> None:
        """Render each requested format to its destination.

        A destination is attached to its format with a colon:
        ``--format sarif:cordon.sarif``. Positional pairing between two repeatable
        flags was tried first and is genuinely error-prone: with
        ``-f text -f sarif -o cordon.sarif`` the natural reading is that SARIF goes
        to the file, while positional pairing sends the *text* report there. That
        produced an unparseable SARIF file, and it did so silently, because writing
        a report to a path always succeeds.

        ``--output`` remains as a shorthand for the single-format case, and is
        refused when it would be ambiguous.
        """
        from cordon_scanner.engine.registry import Registry

        registry = Registry()
        targets: list[tuple[str, str | None]] = []

        for entry in formats:
            name, sep, path = entry.partition(":")
            targets.append((name, path if sep and path else None))

        if single_output is not None:
            named = [name for name, path in targets if path is None]
            if len(named) != 1:
                raise ConfigError(
                    "--output is ambiguous with more than one --format",
                    hint=(
                        "Attach the destination to its format instead, for example:\n"
                        "  --format text --format sarif:cordon.sarif"
                    ),
                )
            targets = [(name, single_output if path is None else path) for name, path in targets]

        for name, destination in targets:
            reporter = registry.reporter(name)

            if destination:
                out_path = Path(destination)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with out_path.open("wb") as handle:
                    for chunk in reporter.render(result, opts):
                        handle.write(chunk)
                if not quiet:
                    print(f"wrote {name} report to {destination}", file=sys.stderr)
            else:
                buffer = sys.stdout.buffer
                for chunk in reporter.render(result, opts):
                    buffer.write(chunk)
                buffer.flush()


__all__ = ["ScanOutput"]
