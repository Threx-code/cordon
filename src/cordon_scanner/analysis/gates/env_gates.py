"""The environment gate around sensitive code: a branch on a CI or environment variable whose body does something sensitive.

A release that behaves only where a CI variable is set (or only where one is not) shows nothing to a reader on a
workstation. The shape is static, so it is read without running anything: the variable the condition tests and the kind
of sensitive call the guarded branch makes. It is a measured fact beside the feature vector, not a vector input.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class EnvGate:
    """One gated branch: the variable its condition tests, the sensitive capability its body reaches, and where."""

    variable: str
    capability: str
    line: int


class EnvGates:
    """Reads the environment gates of a Python or JavaScript source text."""

    VARIABLES = frozenset(
        {
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "TRAVIS",
            "CIRCLECI",
            "BUILDKITE",
            "TF_BUILD",
        }
    )
    """The variables a runner sets, which a gate tests to tell a build machine from a workstation."""

    PYTHON_CAPABILITIES: ClassVar[dict[str, re.Pattern[str]]] = {
        "process": re.compile(r"^(subprocess\.\w+|os\.(system|popen|exec\w*|spawn\w*)|exec|eval)$"),
        "network": re.compile(
            r"^(requests\.\w+|urllib\.request\.\w+|urlopen|socket\.\w+|http\.client\.\w+)$"
        ),
    }
    JS_CAPABILITIES: ClassVar[dict[str, re.Pattern[str]]] = {
        "process": re.compile(r"\b(child_process|execSync|spawnSync|exec|spawn|eval)\s*\("),
        "network": re.compile(r"\b(fetch|https?\.request|https?\.get|XMLHttpRequest)\b"),
    }
    JS_CONDITION = re.compile(r"\bif\s*\(([^)]*)\)\s*\{")
    JS_VARIABLE = re.compile(r"\bprocess\.env(?:\.(\w+)|\[\s*[\"'](\w+)[\"']\s*\])")

    @staticmethod
    def of_python(text: str) -> tuple[EnvGate, ...]:
        """Every `if` of the text that tests a runner variable and calls something sensitive in its body."""
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return ()  # S2: text that does not parse has no syntax to read a gate from
        found: list[EnvGate] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            variable = EnvGates._python_variable(node.test)
            capability = EnvGates._python_capability(node.body)
            if variable and capability:
                found.append(EnvGate(variable, capability, node.lineno))
        return tuple(found)

    @staticmethod
    def _python_variable(test: ast.expr) -> str:
        """The runner variable a condition reads from the environment, or ""."""
        for node in ast.walk(test):
            if isinstance(node, ast.Constant) and node.value in EnvGates.VARIABLES:
                text = ast.unparse(test)
                if "environ" in text or "getenv" in text:
                    return str(node.value)
        return ""

    @staticmethod
    def _python_capability(body: list[ast.stmt]) -> str:
        """The first sensitive kind of call in a branch body, or ""."""
        for statement in body:
            for node in ast.walk(statement):
                if isinstance(node, ast.Call):
                    name = ast.unparse(node.func)
                    for capability, pattern in EnvGates.PYTHON_CAPABILITIES.items():
                        if pattern.match(name):
                            return capability
        return ""

    @staticmethod
    def of_javascript(text: str) -> tuple[EnvGate, ...]:
        """Every `if (...)` of the text that tests `process.env.<runner variable>` and has a sensitive call in its braces."""
        found: list[EnvGate] = []
        for match in EnvGates.JS_CONDITION.finditer(text):
            read = EnvGates.JS_VARIABLE.search(match.group(1))
            variable = (read.group(1) or read.group(2) or "") if read else ""
            if variable not in EnvGates.VARIABLES:
                continue
            body = EnvGates._block(text, match.end())
            for capability, pattern in EnvGates.JS_CAPABILITIES.items():
                if pattern.search(body):
                    found.append(
                        EnvGate(variable, capability, text.count("\n", 0, match.start()) + 1)
                    )
                    break
        return tuple(found)

    @staticmethod
    def _block(text: str, start: int) -> str:
        """The text from just after an opening brace to its matching close, or to the end."""
        depth = 1
        for index in range(start, len(text)):
            depth += (text[index] == "{") - (text[index] == "}")
            if depth == 0:
                return text[start:index]
        return text[start:]
