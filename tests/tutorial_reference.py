"""Generates tutorials 25 and 26 from what ships: every ecosystem, and every command.

The other tutorials are written by hand, one use case each. These two are the reference beside
them, and a reference kept by hand drifts: an ecosystem is added and its section never written, a
flag is renamed and the tutorial keeps the old one. So both are rendered from the registry and the
argument parser, and `tests/unit/test_tutorial_reference.py` fails when the files disagree.

    python tests/tutorial_reference.py ecosystems > tutorials/25-every-ecosystem.md
    python tests/tutorial_reference.py commands > tutorials/26-every-command.md
    python tests/tutorial_reference.py agents > tutorials/27-every-agent-location.md
    python tests/tutorial_reference.py rules > tutorials/28-every-rule.md
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import textwrap
from typing import ClassVar

from cordon_scanner.detect.provenance import SUPPORTED_ECOSYSTEMS as PROVENANCE_ECOSYSTEMS
from cordon_scanner.detect.registry import REGISTRY_ECOSYSTEMS
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories import AdvisoryDatabase
from cordon_scanner.intel.popular import PackageIntel
from cordon_scanner.sources.package import PackageTarget
from cordon_scanner.version import __version__

BANNER = (
    f"> **For Cordon {__version__}.** Using another version? Open the tutorials at its tag: "
    "`https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` "
    "prints the link for the version you have installed."
)

WIDTH = 74
"""The inside of a box: the frame is two characters wider, the 76 columns the other tutorials use."""

#: How each ecosystem is written when it stands for itself, and what it is.
NAMES: dict[str, tuple[str, str]] = {
    "actions": ("GitHub Actions", "workflows and the actions they use, pinned or not"),
    "ansible": ("Ansible Galaxy", "roles and collections a playbook installs"),
    "bazel": ("Bazel", "modules from the Bazel Central Registry"),
    "cargo": ("Cargo", "Rust crates from crates.io"),
    "cocoapods": ("CocoaPods", "iOS and macOS pods"),
    "composer": ("Composer", "PHP packages from Packagist"),
    "conan": ("Conan", "C and C++ packages"),
    "conda": ("Conda", "conda-forge and Anaconda packages"),
    "cran": ("CRAN", "R packages, through renv"),
    "gomod": ("Go modules", "Go modules from the module proxy"),
    "gradle": ("Gradle", "JVM dependencies, Gradle's way"),
    "hackage": ("Hackage", "Haskell packages, through cabal and stack"),
    "helm": ("Helm", "charts a chart depends on"),
    "hex": ("Hex", "Elixir and Erlang packages"),
    "homebrew": ("Homebrew", "formulae and casks in a Brewfile"),
    "image": ("Container images", "the images a Dockerfile, compose file or workload runs"),
    "julia": ("Julia", "packages from the General registry"),
    "maven": ("Maven", "JVM dependencies from Maven Central"),
    "nix": ("Nix", "flake inputs"),
    "npm": ("npm", "JavaScript and TypeScript packages, with npm, pnpm, Yarn or Bun"),
    "nuget": ("NuGet", ".NET packages"),
    "opam": ("opam", "OCaml packages"),
    "pub": ("Pub", "Dart and Flutter packages"),
    "pypi": ("PyPI", "Python packages, with pip, Poetry, Pipenv, PDM or uv"),
    "rubygems": ("RubyGems", "Ruby gems, through Bundler"),
    "swift": ("Swift", "Swift Package Manager dependencies"),
    "terraform": ("Terraform", "providers and their pinned hashes"),
    "vcpkg": ("vcpkg", "C and C++ ports"),
}


class Box:
    """A framed block in the house diagram style."""

    @staticmethod
    def render(lines: list[str]) -> str:
        top = "┌" + "─" * (WIDTH + 2) + "┐"
        bottom = "└" + "─" * (WIDTH + 2) + "┘"
        body = [f"│ {line:<{WIDTH}} │" for line in lines]
        return "\n".join(["```", top, *body, bottom, "```"])

    @staticmethod
    def wrap(label: str, text: str, indent: int = 16) -> list[str]:
        """`label` in a column, `text` wrapped beside it."""
        lines = textwrap.wrap(text, WIDTH - indent) or [""]
        return [f"{label:<{indent}}{lines[0]}", *[" " * indent + rest for rest in lines[1:]]]


class EcosystemTutorial:
    @staticmethod
    def purl_type(ecosystem_id: str) -> str | None:
        for purl, ecosystem in PackageTarget.TYPES.items():
            if ecosystem == ecosystem_id:
                return purl
        return None

    @staticmethod
    def files(globs: tuple[str, ...] | list[str]) -> str:
        return ", ".join(g.removeprefix("**/") for g in globs) or "none"

    @staticmethod
    def section(ecosystem_id: str, database: AdvisoryDatabase) -> str:
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        assert ecosystem is not None
        name, what = NAMES.get(ecosystem_id, (ecosystem_id, ""))
        checks = ["the dependency graph, lockfile integrity, licences, install hooks"]
        if database.covers(ecosystem_id):
            checks.append("known-malicious and known-vulnerable releases, offline")
        else:
            checks.append("no advisory feed: said so, as OPERATIONAL.ADVISORY.NO_FEED.001")
        if PackageIntel.POPULAR_PACKAGES.get(ecosystem_id):
            checks.append("typosquats and dependency confusion against its popular names")
        online = []
        if ecosystem_id in REGISTRY_ECOSYSTEMS:
            online.append("registry: withdrawn releases, version distance, hash agreement")
        if ecosystem_id in PROVENANCE_ECOSYSTEMS:
            online.append("provenance: whether a build attestation exists, and verifies")
        purl = EcosystemTutorial.purl_type(ecosystem_id)
        if purl:
            online.append(
                "a published package fetched by digest and compared with the last release"
            )
        lines = [
            *Box.wrap("MANIFESTS", EcosystemTutorial.files(ecosystem.manifest_globs)),
            *Box.wrap("LOCKFILES", EcosystemTutorial.files(ecosystem.lockfile_globs)),
            "",
        ]
        for i, check in enumerate(checks):
            lines += Box.wrap("OFFLINE" if i == 0 else "", check)
        for i, check in enumerate(online):
            lines += Box.wrap("WITH --online" if i == 0 else "", check)
        commands = ["cordon-scanner scan .                      # every file above, in the project"]
        if purl:
            commands.append(f"cordon-scanner scan pkg:{purl}/<name>@<version> --online")
        commands.append(
            "cordon-scanner deps .                      # every package found, with its findings"
        )
        return "\n".join(
            [
                f"## {name}",
                "",
                f"{what[:1].upper()}{what[1:]}. Ecosystem id `{ecosystem_id}`.",
                "",
                Box.render(lines),
                "",
                "```",
                *commands,
                "```",
                "",
            ]
        )

    @staticmethod
    def render() -> str:
        database = AdvisoryDatabase.bundled()
        ids = sorted(EcosystemRegistry.BY_ID, key=lambda i: NAMES.get(i, (i,))[0].lower())
        missing = [i for i in ids if i not in NAMES]
        if missing:
            raise SystemExit(f"name these ecosystems in tests/tutorial_reference.py: {missing}")
        head = f"""# 25 · Every ecosystem

{BANNER}

Every package ecosystem Cordon reads, {len(ids)} of them, and how to scan each one. The files,
the checks and the commands below are rendered from the shipped code, so this page names
exactly what a scan reads. The same facts as one table:
[docs/07-ECOSYSTEMS.md](../docs/07-ECOSYSTEMS.md).

```
   One command reads all of them at once. A repository with a package.json, a
   go.mod, a Dockerfile and a workflow is four ecosystems in one scan:

   cordon-scanner scan .

   Offline by default. --online adds the registry and provenance checks, and
   names each package to its own registry; nothing else leaves the machine.
```

"""
        body = "\n".join(EcosystemTutorial.section(i, database) for i in ids)
        tail = "Next: **[26 · Every command](26-every-command.md)**.\n"
        return head + body + tail


class CommandTutorial:
    @staticmethod
    def subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                return dict(action.choices)
        return {}

    @staticmethod
    def helps(parser: argparse.ArgumentParser) -> dict[str, str]:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                return {a.dest: a.help or "" for a in action._choices_actions}
        return {}

    @staticmethod
    def option_lines(parser: argparse.ArgumentParser) -> list[str]:
        lines: list[str] = []
        for action in parser._actions:
            if isinstance(action, (argparse._HelpAction, argparse._SubParsersAction)):
                continue
            if action.help == argparse.SUPPRESS:
                continue
            if action.option_strings:
                name = ", ".join(action.option_strings)
                if action.nargs != 0:
                    metavar = action.metavar or (
                        action.dest.upper()
                        if not action.choices
                        else "{" + ",".join(map(str, action.choices)) + "}"
                    )
                    name = f"{name} {metavar}"
            else:
                name = str(action.metavar or action.dest)
            text = action.help or ""
            with contextlib.suppress(KeyError, TypeError, ValueError):
                text = text % {"default": action.default, "prog": parser.prog}
            text = " ".join(text.split())
            if len(name) >= 26:
                lines.append(name)
                lines += Box.wrap("", text, indent=26) if text else []
            else:
                lines += Box.wrap(name, text, indent=26)
        return lines

    @staticmethod
    def section(name: str, parser: argparse.ArgumentParser, summary: str) -> str:
        actions = CommandTutorial.subparsers(parser)
        helps = CommandTutorial.helps(parser)
        parts = [f"## {name}", "", f"{summary[:1].upper()}{summary[1:]}." if summary else "", ""]
        if parser.description:
            parts += [" ".join(parser.description.split()), ""]
        if actions:
            visible = {
                k: v
                for k, v in actions.items()
                if k in helps
                and helps[k] is not None
                and helps[k] != argparse.SUPPRESS
                and helps[k] != ""
            }
            rows = []
            for action in visible:
                rows += Box.wrap(f"{name} {action}", helps.get(action, ""), indent=30)
            if rows:
                parts += [Box.render(rows), ""]
            for action, sub in visible.items():
                options = CommandTutorial.option_lines(sub)
                if options:
                    parts += [f"### {name} {action}", "", Box.render(options), ""]
        options = CommandTutorial.option_lines(parser)
        if options:
            parts += [Box.render(options), ""]
        return "\n".join(parts)

    @staticmethod
    def render() -> str:
        from cordon_scanner.cli.help import HelpScreen
        from cordon_scanner.cli.main import CommandLine

        os.environ["COLUMNS"] = "100"
        parser = CommandLine.build_parser()
        commands = CommandTutorial.subparsers(parser)
        helps = CommandTutorial.helps(parser)
        head = f"""# 26 · Every command

{BANNER}

Every command and every option, rendered from the scanner's own argument parser, so nothing
here can name a flag that does not exist. `cordon-scanner help <command>` prints the same for
one command at a terminal.

```
   0  clean            nothing met the failure policy
   1  findings         something did: the build should stop
   2  scanner error    a bug in Cordon; please report it
   3  config error     the invocation or configuration is wrong
   4  incomplete       the scan could not read everything (with --fail-on-incomplete)
```

"""
        sections = []
        for group, names in HelpScreen.GROUPS:
            listed = [n for n in names if n in commands]
            if not listed:
                continue
            sections.append(
                f"## {group[:1]}{group[1:].lower()}\n\n"
                + "\n".join(f"- `{n}`: {HelpScreen.SHORT.get(n, helps.get(n, ''))}" for n in listed)
                + "\n"
            )
            for n in listed:
                sections.append(CommandTutorial.section(n, commands[n], helps.get(n, "")))
        tail = "Next: **[27 · Every AI agent and MCP location](27-every-agent-location.md)**.\n"
        return head + "\n".join(sections) + tail


#: Which agent reads a path, by the directory or file name that marks it.
AGENT_MARKS: tuple[tuple[str, str], ...] = (
    ("claude", "Claude Code"),
    ("CLAUDE", "Claude Code"),
    ("SKILL.md", "Claude Code and other skill readers"),
    ("managed-settings", "Claude Code (managed)"),
    ("hooks/hooks.json", "Claude Code plugins"),
    ("AGENT", "Codex, Amp and AGENTS.md readers"),
    ("codex", "Codex"),
    ("GEMINI", "Gemini CLI"),
    ("gemini", "Gemini CLI"),
    ("cursor", "Cursor"),
    ("windsurf", "Windsurf"),
    ("clinerules", "Cline"),
    ("cline", "Cline"),
    ("copilot", "GitHub Copilot"),
    (".github/", "GitHub Copilot"),
    ("opencode", "opencode"),
    ("kiro", "Kiro"),
    ("amazonq", "Amazon Q"),
    ("junie", "JetBrains Junie"),
    ("augment", "Augment"),
    ("trae", "Trae"),
    ("roo", "Roo Code"),
    ("continue", "Continue"),
    ("zed", "Zed"),
    (".rules", "Zed"),
    ("goosehints", "goose"),
    ("gitpod", "Gitpod"),
    ("Brewfile", "Homebrew, into VS Code"),
    ("vscode", "VS Code"),
    ("devcontainer", "Dev Containers"),
    ("code-workspace", "VS Code"),
    ("claude_desktop", "Claude Desktop"),
    (".mcp.json", "every MCP client that reads a project file"),
    ("mcp.json", "MCP clients"),
)


class AgentTutorial:
    @staticmethod
    def who(path: str) -> str:
        for mark, agent in AGENT_MARKS:
            if mark in path:
                return agent
        return "several agents"

    @staticmethod
    def table(paths: tuple[str, ...] | list[str], why: str) -> str:
        rows = [f"| `{p.removeprefix('**/')}` | {AgentTutorial.who(p)} |" for p in paths]
        return "\n".join([why, "", "| Path | Read by |", "|---|---|", *rows, ""])

    @staticmethod
    def render() -> str:
        from pathlib import Path

        from cordon_scanner.cloud.device import DeviceInventory
        from cordon_scanner.detect import agents

        rules = sorted(agents.RULES.values(), key=lambda r: r.rule_id)
        rule_rows = [
            f"| `{r.rule_id}` | {r.severity} | {r.title.replace('|', '/')} |" for r in rules
        ]
        laptop = [
            f"| `{str(src.path).replace('/home/you', '~')}` | {src.tool} | {src.kind} |"
            for src in DeviceInventory.sources(Path("/home/you"))
        ]
        actions = [
            f"| `{name}` | {agent} |" for name, agent in sorted(agents.AGENT_ACTIONS.items())
        ]
        categories = (
            ", ".join(sorted(agents.ATR_CATEGORIES))
            if isinstance(agents.ATR_CATEGORIES, dict)
            else ""
        )
        sections = [
            f"""# 27 · Every AI agent and MCP location

{BANNER}

Everything a repository can hand a coding agent, the exact paths Cordon reads for each,
and every rule that judges them. Rendered from the detector itself, so a location added to
the code appears here, and one that is not read never does. The walkthrough is tutorial 18.

```
   instruction files ──┐
   skills, commands ───┤
   settings and hooks ─┼──►  read, never run  ──►  Cordon's agent rules
   MCP configurations ─┤                           Agent Threat Rules
   files run on open ──┤                           intent, offline
   CI agent actions ───┘                           the judge, if asked
```
""",
            "## Instruction files, skills and commands\n",
            AgentTutorial.table(
                agents.INSTRUCTION_PATHS,
                "Text an agent reads as its instructions. Checked for hidden characters, injection wording, remote instructions, what the text asks for, and the Agent Threat Rules.",
            ),
            "## Settings and hooks\n",
            AgentTutorial.table(
                agents.AGENT_SETTINGS_PATHS + agents.CODEX_CONFIG_PATHS,
                "Configuration that decides what an agent may do, and hooks it runs on its own: permissions granted, commands run on events, approval switched off.",
            ),
            "## MCP servers\n",
            AgentTutorial.table(
                agents.MCP_PATHS,
                "Every MCP configuration dialect. Each local server is resolved to the exact package it launches and read from the registry tarball; each remote one, with `--online`, is asked what it serves now (tutorial 18).",
            ),
            "## Files that run when a folder opens\n",
            AgentTutorial.table(
                agents.AUTORUN_PATHS,
                "Commands an editor or agent runs without anyone typing them: tasks set to run on open, dev-container lifecycle commands, background-agent setup.",
            ),
            "## Editor extensions\n",
            AgentTutorial.table(
                agents.EXTENSION_PATHS
                + agents.GITPOD_PATHS
                + agents.BREWFILE_PATHS
                + agents.MARKETPLACE_PATHS,
                "Extensions and plugins a repository asks to have installed, checked against the marketplaces' own malware and impersonation verdicts.",
            ),
            "## Agents in CI\n",
            "\n".join(
                [
                    "Workflow steps that run a coding agent, checked for untrusted triggers, write permissions and broad tools.",
                    "",
                    "| Action | Agent |",
                    "|---|---|",
                    *actions,
                    "",
                ]
            ),
            "## On a developer's laptop\n",
            "\n".join(
                [
                    "`cordon-scanner agent inventory` reads these, and only these; `agent report` sends the list, never a file's contents. Paths shown for Linux; on macOS and Windows the application-support folder is used.",
                    "",
                    "| Path | Tool | Kind |",
                    "|---|---|---|",
                    *laptop,
                    "",
                ]
            ),
            "## Every agent rule\n",
            "\n".join(
                [
                    f"{len(rules)} rules of Cordon's own, beside the Agent Threat Rules (tutorial 28 lists those too).",
                    "",
                    "| Rule | Severity | What it catches |",
                    "|---|---|---|",
                    *rule_rows,
                    "",
                ]
            ),
        ]
        if categories:
            sections.append(
                f"Agent Threat Rules findings are reported in these categories: {categories}.\n"
            )
        sections.append("Next: **[28 · Every rule](28-every-rule.md)**.\n")
        return "\n".join(sections)


class RuleTutorial:
    FAMILIES: ClassVar[dict[str, str]] = {
        "AGENT": "AI agents",
        "MCP": "MCP servers",
        "CI": "CI/CD pipelines",
        "CONTAINER": "Containers",
        "K8S": "Kubernetes",
        "HELM": "Helm",
        "IAC": "Infrastructure as code",
        "DEPENDENCY": "Dependencies",
        "LOCKFILE": "Lockfiles",
        "SECRET": "Secrets",
        "EXFIL": "Exfiltration",
        "OBFUSCATION": "Obfuscation",
        "INSTALL": "Install-time code",
        "PERSIST": "Persistence",
        "NETWORK": "Network",
        "AWS": "AWS",
        "GCP": "Google Cloud",
        "GOOGLE": "Google Cloud",
        "AZURE": "Azure",
        "CFN": "CloudFormation",
        "TF": "Terraform",
        "TERRAFORM": "Terraform",
        "GITHUB": "GitHub",
        "GITLAB": "GitLab",
        "NPM": "npm",
        "PYPI": "PyPI",
        "MCP_SERVER": "MCP servers",
        "VCS": "Source and history",
        "SBOM": "SBOMs",
        "VEX": "VEX",
        "YARA": "YARA",
        "CLAMAV": "ClamAV",
        "DOCKERFILE": "Dockerfiles",
        "COMPOSE": "Compose files",
    }

    @staticmethod
    def declared() -> list[tuple[str, str, str, str]]:
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.rules.loader import RuleLoader

        found: dict[str, tuple[str, str, str, str]] = {}
        for r in RuleCatalogue.from_detectors(Registry().detectors()):
            found.setdefault(r.id, (r.id, str(r.severity), str(r.category), r.title))
        for pack in RuleLoader.load_builtin():
            for compiled in pack.rules:
                r = compiled.rule
                found.setdefault(r.id, (r.id, str(r.severity), str(r.category), r.title))
        return [v for k, v in sorted(found.items()) if not k.startswith(("CAP.", "AST.", "INTEL."))]

    @staticmethod
    def family(rule_id: str) -> str:
        if rule_id.upper().startswith("ATR"):
            return "Agent Threat Rules"
        if rule_id.startswith("SECRET."):
            return "Secrets"
        parts = rule_id.split(".")
        key = parts[1] if len(parts) > 2 else parts[0]
        return RuleTutorial.FAMILIES.get(key, key.replace("_", " ").title())

    @staticmethod
    def render() -> str:
        rules = RuleTutorial.declared()
        families: dict[str, list[tuple[str, str, str, str]]] = {}
        for rule in rules:
            families.setdefault(RuleTutorial.family(rule[0]), []).append(rule)
        order = sorted(families, key=lambda f: (f == "Agent Threat Rules", f.lower()))
        head = f"""# 28 · Every rule

{BANNER}

All {len(rules):,} detection rules Cordon defines itself, grouped by what they watch, with the
severity each reports at, and after them every Agent Threat Rule it carries. Rendered from the detectors and rule packs themselves. `cordon-scanner rules
show <id>` prints one in full, with its remediation and references; `rules test` runs every
rule's own samples.

```
   MALWARE.*       evidence of intent to harm: fails the build by default
   SUSPECT.*       a behaviour or shape attackers use: worth a look
   VULNERABLE.*    a known vulnerability in what you ship
   SECRET.*        a credential in the code or its history
   POLICY.*        a choice the project made about itself
   OPERATIONAL.*   what the scan could not do, said out loud
```

"""
        parts = [head]
        for family in order:
            rows = families[family]
            parts.append(f"## {family}\n")
            parts.append(f"{len(rows)} rules.\n")
            parts.append("| Rule | Severity | What it catches |\n|---|---|---|")
            parts.extend(
                f"| `{rid}` | {sev} | {title.replace('|', '/')} |" for rid, sev, _cat, title in rows
            )
            parts.append("")
        parts.extend(RuleTutorial.atr())
        parts.append("Back to the start: **[the tutorial map](README.md)**.\n")
        return "\n".join(parts)

    @staticmethod
    def atr() -> list[str]:
        """The Agent Threat Rules Cordon carries, by the catalogue's own categories."""
        from cordon_scanner.intel.atr import AtrEngine, RuleLinks

        catalogue = AtrEngine.catalogue()
        by_category: dict[str, list] = {}
        for rule in catalogue.rules:
            by_category.setdefault(rule.category, []).append(rule)
        parts = [
            "## Agent Threat Rules\n",
            f"{sum(r.rule_id.startswith('ATR-') for r in catalogue.rules)} rules from the open "
            "[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) "
            f"catalogue (MIT), at commit `{catalogue.commit[:12]}`, and "
            f"{sum(not r.rule_id.startswith('ATR-') for r in catalogue.rules)} of Cordon's own written "
            "in its format (`CORDON-ATR-*`): translated, screened for runaway "
            "patterns, and graded by how often each matched benign text. A `production` rule counts "
            "on its own; `warn` and `observe` need a second signal (tutorial 18).\n",
        ]
        for category in sorted(by_category):
            rules = sorted(by_category[category], key=lambda r: r.rule_id)
            parts.append(f"### {category.replace('-', ' ').capitalize()}\n")
            parts.append("| Rule | Severity | Grade | What it catches |\n|---|---|---|---|")
            parts.extend(
                f"| [`{r.rule_id}`]({RuleLinks.url(r.rule_id)}) | {r.severity} | "
                f"{r.instruction_grade} | {r.title.replace('|', '/')} |"
                for r in rules
            )
            parts.append("")
        return parts


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    if which == "ecosystems":
        print(EcosystemTutorial.render(), end="")
    elif which == "commands":
        print(CommandTutorial.render(), end="")
    elif which == "agents":
        print(AgentTutorial.render(), end="")
    elif which == "rules":
        print(RuleTutorial.render(), end="")
    else:
        raise SystemExit("usage: tutorial_reference.py ecosystems|commands|agents|rules")
