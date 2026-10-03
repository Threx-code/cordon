"""`cordon-scanner completion bash|zsh|fish`: shell completion generated from the parser itself.

Read from the same argparse tree the CLI runs, so a command or flag added there is completed the
moment it exists, and a completion can never offer a flag the program would reject.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field


@dataclass
class CommandTree:
    """Every command path (`suppress add`) with the options and subcommands available at it."""

    options: dict[str, list[str]] = field(default_factory=dict)
    subcommands: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_parser(cls, parser: argparse.ArgumentParser) -> CommandTree:
        tree = cls()
        tree._walk(parser, "")
        return tree

    def _walk(self, parser: argparse.ArgumentParser, path: str) -> None:
        options: list[str] = []
        children: list[str] = []
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    children.append(name)
                    self._walk(child, f"{path} {name}".strip())
            else:
                options.extend(s for s in action.option_strings if s.startswith("--"))
        self.options[path] = sorted(set(options))
        self.subcommands[path] = sorted(children)


class CompletionScript:
    SHELLS = ("bash", "zsh", "fish")

    def __init__(self, parser: argparse.ArgumentParser, program: str) -> None:
        self.tree = CommandTree.from_parser(parser)
        self.program = program
        self.function = "_" + "".join(c if c.isalnum() else "_" for c in program)

    def render(self, shell: str) -> str:
        if shell == "bash":
            return self.bash()
        if shell == "zsh":
            return "autoload -U +X bashcompinit && bashcompinit\n" + self.bash()
        if shell == "fish":
            return self.fish()
        raise ValueError(f"unsupported shell {shell!r}; choose one of {', '.join(self.SHELLS)}")

    def bash(self) -> str:
        cases = []
        for path in sorted(self.tree.options):
            words = " ".join([*self.tree.subcommands[path], *self.tree.options[path]])
            cases.append(f'        "{path}") words="{words}" ;;')
        return (
            f'# {self.program} completion. Install: eval "$({self.program} completion bash)"\n'
            f"{self.function}() {{\n"
            '    local cur="${COMP_WORDS[COMP_CWORD]}" path="" i word words=""\n'
            "    for ((i = 1; i < COMP_CWORD; i++)); do\n"
            '        word="${COMP_WORDS[i]}"\n'
            '        [[ "$word" == -* ]] && continue\n'
            '        case " $(' + f"{self.function}_children" + ' "$path") " in\n'
            '            *" $word "*) path="${path:+$path }$word" ;;\n'
            "        esac\n"
            "    done\n"
            '    case "$path" in\n' + "\n".join(cases) + "\n    esac\n"
            '    COMPREPLY=($(compgen -W "$words" -- "$cur"))\n'
            '    [[ ${#COMPREPLY[@]} -eq 0 ]] && COMPREPLY=($(compgen -f -- "$cur"))\n'
            "}\n"
            f"{self.function}_children() {{\n"
            '    case "$1" in\n'
            + "\n".join(
                f'        "{p}") echo "{" ".join(c)}" ;;'
                for p, c in sorted(self.tree.subcommands.items())
            )
            + "\n    esac\n}\n"
            f"complete -F {self.function} {self.program}\n"
        )

    def fish(self) -> str:
        lines = [f"# {self.program} completion. Install: {self.program} completion fish | source"]
        lines.append(f"complete -c {self.program} -f")
        for path, children in sorted(self.tree.subcommands.items()):
            condition = self._fish_condition(path)
            for child in children:
                lines.append(f"complete -c {self.program} -n '{condition}' -a {child}")
        for path, options in sorted(self.tree.options.items()):
            condition = self._fish_condition(path)
            for option in options:
                lines.append(f"complete -c {self.program} -n '{condition}' -l {option[2:]}")
        return "\n".join(lines) + "\n"

    def _fish_condition(self, path: str) -> str:
        if not path:
            return "__fish_use_subcommand"
        parts = path.split()
        seen = " ".join(f"__fish_seen_subcommand_from {p};" for p in parts)
        deeper = " ".join(self.tree.subcommands.get(path, []))
        guard = f" and not __fish_seen_subcommand_from {deeper}" if deeper else ""
        return f"{seen.rstrip(';').replace('; ', '; and ')}{guard}"


class CompletionCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        completion = sub.add_parser("completion", help="print a shell completion script")
        completion.add_argument("shell", choices=CompletionScript.SHELLS)

    @staticmethod
    def run(args: argparse.Namespace, parser: argparse.ArgumentParser, program: str) -> int:
        print(CompletionScript(parser, program).render(args.shell), end="")
        return 0
