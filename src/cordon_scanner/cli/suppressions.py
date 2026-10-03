"""`cordon-scanner suppress list|add|prune`: the suppression lifecycle, on the repository's own config.

A suppression is the one sanctioned way to make a finding stop failing a build, so the command that
writes one holds it to exactly the rules the scanner applies when it reads one -- the same parser,
the same organisation ceiling, the same refusal to silence malware. A suppression this command
accepts is one the next scan honours, and one it refuses is one the scan would have refused.

The file is edited as text, never re-serialised. A repository's `cordon.yaml` carries comments that
explain why each exception exists, and rewriting it through a YAML dumper would drop them -- the
record of the decision is worth more than the convenience. Every write is verified by parsing the
result before the original is replaced, and the replacement is atomic: the file on disk is always
either the old configuration or a new one that loads.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from cordon_scanner.core.config import (
    CONFIG_FILENAMES,
    CONFIG_VERSION,
    MIN_JUSTIFICATION_CHARS,
    Config,
    ConfigParser,
    ConfigResolver,
    OrgConstraints,
    RestrictedYamlParser,
)
from cordon_scanner.core.errors import ConfigError, ExitCode
from cordon_scanner.core.models import Category, Suppression


@dataclass(frozen=True, slots=True)
class SuppressionState:
    """Whether one suppression is in force today, and if not, why."""

    suppression: Suppression
    state: str
    """`active`, `expired` or `refused`."""
    detail: str

    def as_dict(self, index: int) -> dict[str, object]:
        return {
            "index": index,
            "rule": self.suppression.rule,
            "path": self.suppression.path,
            "expires": self.suppression.expires,
            "approved_by": self.suppression.approved_by,
            "state": self.state,
            "detail": self.detail,
        }


class SuppressionRules:
    """The checks a suppression must pass: the scanner's own, plus the two this command adds."""

    def __init__(self, constraints: OrgConstraints, categories: dict[str, Category]) -> None:
        self.constraints = constraints
        self.categories = categories

    @classmethod
    def load(cls, policy: str | None) -> SuppressionRules:
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.rules.loader import RuleLoader

        constraints = OrgConstraints.permissive()
        if policy:
            _, constraints = ConfigResolver.load_org_policy(policy)
        categories: dict[str, Category] = {}
        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                categories[compiled.rule.id] = compiled.rule.category
        for declared in RuleCatalogue.from_detectors(Registry().detectors()):
            categories.setdefault(declared.id, declared.category)
        return cls(constraints, categories)

    def state(self, suppression: Suppression, today: date) -> SuppressionState:
        expires = date.fromisoformat(suppression.expires)
        if expires < today:
            return SuppressionState(
                suppression,
                "expired",
                f"expired {suppression.expires}; it no longer suppresses anything",
            )
        refusal = self.refusal(suppression, today)
        if refusal:
            return SuppressionState(suppression, "refused", refusal)
        left = (expires - today).days
        return SuppressionState(suppression, "active", f"expires in {left} day(s)")

    def refusal(self, suppression: Suppression, today: date) -> str | None:
        category = self.categories.get(suppression.rule)
        if category is None:
            # A suppression naming a rule that does not exist suppresses nothing, and reads as if
            # it did: the usual cause is a typo, and the finding it was meant for still fails.
            return f"no rule {suppression.rule!r} exists, so this suppresses nothing"
        if category in self.constraints.forbid_suppressing:
            return f"{suppression.rule} is a {category.value} rule, and organisation policy forbids suppressing those"
        violation = ConfigParser._suppression_violation(suppression, self.constraints)
        if violation:
            return violation
        if date.fromisoformat(suppression.expires) <= today:
            return "the expiry date must be in the future"
        return None


class SuppressionFile:
    """A repository config file and the suppressions in it, edited as text."""

    _HEADER = re.compile(r"^suppressions:[ \t]*(?:\[\s*\])?[ \t]*(?:#.*)?$")
    _ITEM = re.compile(r"^([ \t]*)-[ \t]")

    def __init__(self, path: Path) -> None:
        self.path = path
        self.text = Config.read_bounded(path) if path.exists() else ""

    @classmethod
    def locate(cls, root: Path, explicit: str | None) -> SuppressionFile:
        if explicit:
            return cls(Path(explicit))
        for name in CONFIG_FILENAMES:
            if (root / name).is_file():
                return cls(root / name)
        return cls(root / CONFIG_FILENAMES[0])

    def suppressions(self, text: str | None = None) -> tuple[Suppression, ...]:
        body = self.text if text is None else text
        if not body.strip():
            return ()
        data = RestrictedYamlParser._load_yaml_subset(body, source=str(self.path))
        raw = data.get("suppressions")
        if raw is None:
            return ()
        return ConfigParser._parse_suppressions(raw, source=str(self.path))

    def _block(self, lines: list[str]) -> tuple[int, int, list[int]] | None:
        """The header line, the line after the block's last item, and where each item starts."""
        header = next((i for i, line in enumerate(lines) if self._HEADER.match(line)), None)
        if header is None:
            return None
        starts: list[int] = []
        indent: str | None = None
        end = header + 1
        for index in range(header + 1, len(lines)):
            line = lines[index]
            stripped = line.strip()
            if stripped and not line[:1].isspace() and not stripped.startswith("#"):
                break
            item = self._ITEM.match(line)
            if item and (indent is None or item.group(1) == indent):
                indent = item.group(1)
                starts.append(index)
            if stripped and not stripped.startswith("#"):
                end = index + 1
        return header, end, starts

    def with_added(self, suppression: Suppression) -> str:
        lines = self.text.splitlines()
        entry = self.render(suppression)
        block = self._block(lines)
        if block is None:
            prefix = lines if lines else [f"version: {CONFIG_VERSION}"]
            return "\n".join([*prefix, "", "suppressions:", *entry]) + "\n"
        header, end, starts = block
        indent = self._ITEM.match(lines[starts[0]]).group(1) if starts else "  "  # type: ignore[union-attr]
        lines[header] = "suppressions:"
        rendered = [f"{indent}{line[2:]}" if line.startswith("  ") else line for line in entry]
        return "\n".join([*lines[:end], *rendered, *lines[end:]]) + "\n"

    def without(self, drop: set[int]) -> str:
        lines = self.text.splitlines()
        block = self._block(lines)
        if block is None or not drop:
            return self.text
        header, end, starts = block
        # A comment directly above an entry is about that entry, and goes with it: left behind, it
        # would sit above whichever entry came next and describe the wrong exception.
        owned = []
        for start in starts:
            first = start
            while first - 1 > header and lines[first - 1].strip().startswith("#"):
                first -= 1
            owned.append(first)
        spans = [
            (first, owned[i + 1] if i + 1 < len(owned) else end) for i, first in enumerate(owned)
        ]
        removed = {line for i, (a, b) in enumerate(spans) if i in drop for line in range(a, b)}
        kept = [line for i, line in enumerate(lines) if i not in removed]
        if len(drop) == len(starts):
            kept[header] = "suppressions: []"
        return "\n".join(kept) + "\n"

    @staticmethod
    def render(suppression: Suppression) -> list[str]:
        def quoted(value: str) -> str:
            return json.dumps(value, ensure_ascii=False)

        lines = [
            f"  - rule: {quoted(suppression.rule)}",
            f"    path: {quoted(suppression.path)}",
            f"    justification: {quoted(suppression.justification)}",
            f"    expires: {quoted(suppression.expires)}",
        ]
        if suppression.approved_by:
            lines.append(f"    approved_by: {quoted(suppression.approved_by)}")
        return lines

    def replace(self, text: str, expected: tuple[Suppression, ...]) -> None:
        """Write `text` only if it parses to exactly `expected`, atomically, keeping the file's mode."""
        if self.suppressions(text) != expected:
            raise ConfigError(
                f"refusing to write {self.path}: the edited file does not read back as intended",
                hint="Edit the suppressions block by hand; its layout is one this command does not recognise.",
            )
        directory = self.path.parent if str(self.path.parent) else Path()
        mode = self.path.stat().st_mode & 0o777 if self.path.exists() else 0o644
        descriptor, temporary = tempfile.mkstemp(prefix=".cordon-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
            Path(temporary).chmod(mode)
            Path(temporary).replace(self.path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        self.text = text


class SuppressCommand:
    """The three actions, as the CLI calls them."""

    MAX_DAYS_DEFAULT = 30

    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        suppress = sub.add_parser(
            "suppress", help="list, add and prune suppressions in the repository config"
        )
        actions = suppress.add_subparsers(
            dest="suppress_command", metavar="<action>", required=True
        )
        common = argparse.ArgumentParser(add_help=False)
        common.add_argument("--root", default=".", help="repository root (default: .)")
        common.add_argument(
            "--config", help="config file to edit (default: the repository's cordon.yaml)"
        )
        common.add_argument(
            "--policy", help="organisation policy whose ceiling suppressions must respect"
        )
        listing = actions.add_parser(
            "list", parents=[common], help="show every suppression and whether it is in force"
        )
        listing.add_argument("--format", choices=("text", "json"), default="text")
        add = actions.add_parser(
            "add", parents=[common], help="add a suppression, checked as the scanner checks it"
        )
        add.add_argument("rule", help="the rule id, e.g. SUSPECT.SPAWN.001")
        add.add_argument("path", help="the path it applies to (no `**`)")
        add.add_argument(
            "--justification",
            required=True,
            help=f"why this is safe here (at least {MIN_JUSTIFICATION_CHARS} characters)",
        )
        when = add.add_mutually_exclusive_group()
        when.add_argument("--expires", help="expiry date, YYYY-MM-DD")
        when.add_argument(
            "--days",
            type=int,
            help=f"expire this many days from today (default {cls.MAX_DAYS_DEFAULT})",
        )
        add.add_argument(
            "--approved-by", help="who approved it (required when policy demands an approver)"
        )
        prune = actions.add_parser(
            "prune", parents=[common], help="remove expired suppressions and report them"
        )
        prune.add_argument(
            "--dry-run", action="store_true", help="report what would be removed, change nothing"
        )

    @classmethod
    def run(cls, args: argparse.Namespace, today: date | None = None) -> int:
        today = today or date.today()
        target = SuppressionFile.locate(Path(args.root), args.config)
        action = args.suppress_command
        if action == "list":
            return cls.list(target, SuppressionRules.load(args.policy), today, args.format)
        if action == "add":
            return cls.add(target, SuppressionRules.load(args.policy), today, args)
        return cls.prune(target, today, dry_run=args.dry_run)

    @staticmethod
    def list(target: SuppressionFile, rules: SuppressionRules, today: date, fmt: str) -> int:
        states = [rules.state(s, today) for s in target.suppressions()]
        if fmt == "json":
            print(
                json.dumps(
                    {
                        "file": str(target.path),
                        "suppressions": [s.as_dict(i) for i, s in enumerate(states)],
                    },
                    indent=2,
                )
            )
            return int(ExitCode.CLEAN)
        if not states:
            print(f"no suppressions in {target.path}")
            return int(ExitCode.CLEAN)
        print(f"{len(states)} suppression(s) in {target.path}\n")
        for index, entry in enumerate(states):
            s = entry.suppression
            print(f"  [{index}] {entry.state.upper():<8} {s.rule}  {s.path}")
            print(
                f"       {entry.detail}{f'; approved by {s.approved_by}' if s.approved_by else ''}"
            )
        return int(ExitCode.CLEAN)

    @classmethod
    def add(
        cls, target: SuppressionFile, rules: SuppressionRules, today: date, args: argparse.Namespace
    ) -> int:
        if args.expires:
            expires = args.expires
        else:
            days = cls.MAX_DAYS_DEFAULT if args.days is None else args.days
            if days < 1:
                raise ConfigError("--days must be at least 1")
            expires = (today + timedelta(days=days)).isoformat()
        justification = " ".join(str(args.justification).split())
        candidate = {
            "rule": args.rule.strip(),
            "path": args.path.strip(),
            "justification": justification,
            "expires": expires,
        }
        if args.approved_by:
            candidate["approved_by"] = args.approved_by.strip()
        if any(ord(c) < 32 or c == "\x7f" for v in candidate.values() for c in v):
            raise ConfigError("suppression fields may not contain control characters")
        (suppression,) = ConfigParser._parse_suppressions([candidate], source="suppress add")
        refusal = rules.refusal(suppression, today)
        if refusal:
            raise ConfigError(f"refused: {refusal}")
        existing = target.suppressions()
        if any(s.rule == suppression.rule and s.path == suppression.path for s in existing):
            raise ConfigError(
                f"{target.path} already suppresses {suppression.rule} for {suppression.path}",
                hint="Prune or edit the existing entry rather than stacking a second one.",
            )
        target.replace(target.with_added(suppression), (*existing, suppression))
        print(
            f"added to {target.path}: {suppression.rule} for {suppression.path}, expires {suppression.expires}"
        )
        return int(ExitCode.CLEAN)

    @staticmethod
    def prune(target: SuppressionFile, today: date, *, dry_run: bool) -> int:
        existing = target.suppressions()
        expired = {i for i, s in enumerate(existing) if date.fromisoformat(s.expires) < today}
        if not expired:
            print(f"nothing to prune in {target.path}")
            return int(ExitCode.CLEAN)
        for index in sorted(expired):
            s = existing[index]
            print(
                f"{'would remove' if dry_run else 'removed'}: {s.rule} for {s.path} (expired {s.expires})"
            )
        if not dry_run:
            kept = tuple(s for i, s in enumerate(existing) if i not in expired)
            target.replace(target.without(expired), kept)
        return int(ExitCode.CLEAN)
