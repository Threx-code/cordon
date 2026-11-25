"""The environment gate is read from the syntax, in Python and JavaScript, and only where a branch on a runner variable reaches a sensitive call."""

from __future__ import annotations

from cordon_scanner.analysis.gates.env_gates import EnvGate, EnvGates

PYTHON_GATED = """
import os
import subprocess

if os.environ.get("CI"):
    subprocess.run(["sh", "-c", "true"])
"""

PYTHON_PLAIN = """
import os
import subprocess

if os.environ.get("MODE") == "fast":
    subprocess.run(["sh", "-c", "true"])
if os.environ.get("CI"):
    print("running on a build machine")
"""

JS_GATED = """
const cp = require("child_process");
if (process.env.GITHUB_ACTIONS) {
  cp.execSync("true");
}
"""

JS_PLAIN = """
if (process.env.NODE_ENV === "test") {
  fetch("https://example.invalid");
}
"""


class TestPython:
    def test_a_runner_variable_guarding_a_process_call_is_a_gate(self) -> None:
        assert EnvGates.of_python(PYTHON_GATED) == (EnvGate("CI", "process", 5),)

    def test_other_variables_and_harmless_bodies_are_not(self) -> None:
        assert EnvGates.of_python(PYTHON_PLAIN) == ()

    def test_text_that_does_not_parse_has_no_gate(self) -> None:
        assert EnvGates.of_python("if os.environ.get('CI'):\n  (") == ()


class TestJavaScript:
    def test_a_runner_variable_guarding_a_process_call_is_a_gate(self) -> None:
        assert EnvGates.of_javascript(JS_GATED) == (EnvGate("GITHUB_ACTIONS", "process", 3),)

    def test_other_variables_are_not(self) -> None:
        assert EnvGates.of_javascript(JS_PLAIN) == ()
