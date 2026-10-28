"""What a path in a scanned tree is: a test, documentation, build tooling, generated output, vendored
code, bulk data, an editor extension, a content-hashed asset.

A fact about where a file sits, read by the detectors that discount what tests and documentation
contain and by the engine when it decides which files are a package's own code. Nothing here reads
a file: only its path.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from typing import Protocol

from cordon_scanner.analysis.shared.test_material import SCANNER_CONFIG_PATHS, TEST_MATERIAL_PATHS
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.models import (
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths


class EntryPaths(Protocol):
    """What `is_test_material_here` reads of a scan: the files that run at install, and the ones
    importing the package runs. A detector's `ScanContext` is one."""

    @property
    def install_hook_paths(self) -> Collection[str]: ...

    @property
    def import_entry_paths(self) -> Collection[str]: ...


#: Paths whose content is written to be read by a person, not executed.
#:
#: Documentation gets the same treatment as test material and for a closely related
#: reason: a credential-shaped string in a document is an EXAMPLE far more often
#: than it is a live key, because showing the shape of a connection string is how
#: you document a connection string.
#:
#: Celery's SQS page carries `sqs://ABCDEFGHIJKLMNOPQRST:ZYXK7Niyn...@` and, two
#: lines below, `sqs://aws_access_key_id:aws_secret_access_key@` as the format. The
#: first was reported at HIGH. Its access key is the alphabet in order.
#:
#: Ceilinged rather than suppressed, and the distinction matters: a real key pasted
#: into a README leaks exactly as far as one in a settings file, and plenty have
#: been. It stays in the report, below the severity that fails a build, with the
#: caveat saying why.
DOCUMENTATION_PATHS = (
    "**/docs/**",
    "**/doc/**",
    "**/documentation/**",
    "**/*.md",
    "**/*.rst",
    "**/*.adoc",
    "**/*.asciidoc",
    "**/*.asc",
    "**/*.org",
    "**/*.textile",
    "**/*.txt",
    "**/*.mdx",
    "**/*.ipynb",
    # A man page, in the nine sections roff uses. `rclone/rclone.1` is its whole
    # command reference as one generated troff file, and the examples in it are
    # examples -- `rclone lsf :ftp: --ftp-pass=...` is a line somebody is meant to
    # read and adapt.
    "**/*.[1-9]",
    "**/README*",
    "**/CHANGELOG*",
    "**/CONTRIBUTING*",
    # A Python distribution's metadata: its headers, then its README as the long description.
    # `curl -LsSf https://astral.sh/uv/install.sh | sh` there is an install instruction in the
    # README, and nothing runs the file (review 98).
    "**/PKG-INFO",
    "**/*.dist-info/METADATA",
    "**/*.example",
    "**/*.example.*",
    "**/*.sample",
    "**/*.sample.*",
    "**/*.template",
    "**/*.dist",
    # Localisation catalogues. The value beside a key called `password` is the WORD
    # "password" in another language: a Danish translation file was reported for
    # `password = "Adgangskode"`. Every project with a translated login form has one
    # of these for every language it supports, so the count scales with how
    # international the project is.
    "**/locales/**",
    # The rest of the names a translation catalogue goes under. The note above names
    # the case exactly -- "the value beside a key called `password` is the WORD
    # 'password' in another language" -- and then the list had one glob for it.
    # Keycloak keeps its under `theme/keycloak.v2/admin/messages/messages_de.properties`
    # and ships dozens of languages: `resetPasswordConfirmation=Passwortbestätigung` was
    # reported as a credential, and 40 of its 61 remaining findings were that shape.
    "**/locale/**",
    "**/messages/**",
    "**/messages_*.*",
    "**/i18n/**",
    "**/translations/**",
    "**/translation/**",
    "**/lang/**",
    "**/langs/**",
    "**/locale/**",
    "**/translations/**",
    "**/i18n/**",
    "**/lang/**",
    "**/*.po",
    "**/*.pot",
    "**/*.xliff",
    "**/*.arb",
    "**/*.resx",
)
"""Where a credential is usually one somebody generated for the suite.

Four hundred and eighty-eight of the five hundred and seventy-six private keys
found across thirty-eight production repositories were here, and every one of
them was a key made so a TLS test would have something to serve. A tool that
reports those at critical is a tool people stop reading, and the reason is not
that the keys are not keys -- they are, and the pattern is right about them.

So this changes what is claimed, not whether it is claimed. The finding is
still emitted, still says a private key is committed, and still says why that
matters; what it stops doing is failing a build over `tests/fixtures/key.pem`.
A production key committed under `tests/` is genuinely under-reported by this,
which is the trade being made, and the message says so where the finding is
read rather than here."""


FIXTURE_CEILING = Severity.MEDIUM
"""The most a secret in test material may be reported at."""


class SourcePaths:
    """What a path is: tests, documentation, build tooling, generated output, vendored code, data."""

    @staticmethod
    def _names(path: str, globs: tuple[str, ...]) -> bool:
        """Whether a path matches any of these globs, ignoring case.

        Every one of these lists is a list of CONVENTIONS, and the conventions are
        spelled differently by ecosystem: Swift and .NET capitalise `Tests/`, Apple
        capitalises `Documentation/`, Maven lowercases `src/test/java`. Matching
        case-sensitively meant the lists were Unix- and Python-shaped and silently
        missed whole ecosystems -- `manaflow-ai/cmux` had fifty-nine credential
        findings in `cmuxTests/` and `Packages/.../Tests/`, none of which any glob
        here matched.

        The globs are lowered too, so `**/javaRestTest/**` keeps working.
        """
        lowered = path.lower()
        return any(PathGlob.matches(lowered, glob.lower()) for glob in globs)

    @staticmethod
    def names_test_file(path: str) -> bool:
        """Whether the FILENAME says it is test infrastructure.

        `huggingface/transformers` keeps its committed Hub token in
        `src/transformers/testing_utils.py`, which no `test_*` or `*_test.*` glob matches and
        which is not in a test directory either -- the helpers live beside the library.

        Split on the separators a filename uses, so `testing_utils` counts and `latest`
        does not, which is the same distinction `names_test_directory` draws one level up.
        `conftest` and `runtests` are named because each is spelled as one word.

        The extension is a separator too. `*.test.*` and `*.spec.*` are already globs in
        `TEST_MATERIAL_PATHS`, but the plural `utils.tests.js` is not and is just as clear,
        and reading the whole name rather than the stem costs nothing: `latest.py` and
        `manifest.py` are single parts either way.
        """
        name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        parts = re.split(r"[._\-]+", name)
        if parts[0] in ONE_WORD_TEST_FILES or any(part in TEST_FILE_WORDS for part in parts):
            return True
        # And a non-production marker, but only where the extension says the file holds key
        # material or configuration. See `NON_PRODUCTION_MARKERS`.
        extension = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        return extension in MARKED_EXTENSIONS and any(
            part in NON_PRODUCTION_MARKERS for part in parts
        )

    @staticmethod
    def names_test_directory(path: str) -> bool:
        """Whether any DIRECTORY in this path says it holds test material.

        Beyond what a glob can say. A project spells its own test tree with its own name in
        front -- Caddy keeps two TLS keys in `caddytest/`, Radarr keeps an HTML file named
        `.jpg` under `src/NzbDrone.Core.Test/Files/`, and okio keeps a deliberately corrupt
        zip under `okio-testing-support/` -- and `**/test/**` sees none of them.

        A segment counts if it ENDS in one of the suffixes, or if any dot-, dash- or
        underscore-separated part of it IS one. The deny-list above is what keeps `latest`
        out; see `NOT_A_TEST_WORD`.
        """
        for segment in path.lower().replace("\\", "/").split("/")[:-1]:
            if not segment or segment in NOT_A_TEST_WORD:
                continue
            # A dunder-wrapped directory is a tooling convention, not product source:
            # `__tests__`, `__mocks__`, `__snapshots__`, `__fixtures__`, `__pycache__`, and
            # the variants every project invents -- Storybook keeps a text file named
            # `Primary.png` under `__mockdata__/src/__screenshots__/`, which no `__mocks__`
            # or `__snapshots__` glob can see.
            if len(segment) > 4 and segment.startswith("__") and segment.endswith("__"):
                return True
            if segment.endswith(TEST_DIRECTORY_SUFFIXES):
                return True
            # A SPACE separates words too. Meson keeps its entire suite under
            # `test cases/`, with a subdirectory per case -- `test cases/rust/25 cargo
            # lock/subprojects/packagecache/bar-0.1.tar.gz` -- and two deliberately
            # malformed archives in there were reported as files contradicting their own
            # names. The segment is not `test`, does not end in `test`, and contains no
            # dot, dash or underscore to split on, so nothing saw the word.
            #
            # Whole words, which is what keeps this safe: `latest builds` splits to
            # `latest` and `builds` and matches neither, the same way `latest` alone
            # does not. See `NOT_A_TEST_WORD`.
            parts = re.split(r"[.\-_\s]+", segment)
            if any(part in TEST_DIRECTORY_COMPOUNDS for part in parts):
                return True
        return False

    @staticmethod
    def test_material_glob(path: str) -> bool:
        """Whether a path matches one of `TEST_MATERIAL_PATHS`."""
        return SourcePaths._names(path, TEST_MATERIAL_PATHS)

    @staticmethod
    def is_test_material(path: str) -> bool:
        """Whether a path is where a project keeps things its tests need."""
        path = SourcePaths.inside_release(path)
        return (
            SourcePaths._names(path, TEST_MATERIAL_PATHS + SCANNER_CONFIG_PATHS)
            or SourcePaths.names_test_directory(path)
            or SourcePaths.names_test_file(path)
        )

    _ARCHIVE_SUFFIX = re.compile(
        r"(?i)\.(?:tar\.gz|tgz|tar\.bz2|tar\.xz|tar|zip|whl|gem|crate|nupkg|jar|vsix)$"
    )

    @staticmethod
    def inside_release(path: str) -> str:
        """The path within the release a scanned archive holds, without the release's own name.

        `chai-await-test.tgz!package/lib/caller.js` is `package/lib/caller.js`: a package's name is
        what its publisher called it, not where it keeps its tests, and the word `test` in it had
        made every file of `chai-await-test` -- its fetch-and-run loader included -- test material
        (review 98). The root folder an sdist or gem names after its release goes too. A `test/`
        directory a nested archive sits in still counts.
        """
        head, bang, rest = path.partition("!")
        if not bang:
            return path
        directory, _, archive = head.rpartition("/")
        stem = SourcePaths._ARCHIVE_SUFFIX.sub("", archive).lower()
        first, slash, remainder = rest.partition("/")
        if slash and stem and first.lower() == stem:
            rest = remainder
        return f"{directory}/{rest}" if directory else rest

    @staticmethod
    def is_test_material_here(path: str, ctx: EntryPaths) -> bool:
        """`is_test_material`, except for a file that runs at install.

        The fuzzy half of the test -- a directory with `test` or `samples` as one word of its name --
        is a guess about what a file is for, and a lifecycle script naming the file is evidence of what
        it does. `"preinstall": "bun run index.js"` in `@antv-data-samples/package/` runs `index.js`
        on every install of the package; the word `samples` in the directory had ceilinged the
        obfuscated payload and the hook declaring it below the failure gate. Such a file is test
        material only under a directory whose whole name says so, the test `setup.py` already gets.

        A published package's import entry is the same evidence: whatever imports the package runs
        its top level. `api-demo-sample-lib1` reports the importer's host, user and DNS servers from
        `index.js`, and the word `sample` in its own name had held that below the gate (review 98).
        """
        if path in ctx.install_hook_paths or path in ctx.import_entry_paths:
            return ContainerPaths.under_fixture_directory(path)
        return SourcePaths.is_test_material(path)

    @staticmethod
    def is_documentation(path: str) -> bool:
        """Whether a path holds prose written to be read rather than executed."""
        return SourcePaths._names(path, DOCUMENTATION_PATHS)

    @staticmethod
    def is_build_tooling(path: str) -> bool:
        """Whether a path is the project's own build, test or release tooling."""
        return SourcePaths._names(path, BUILD_TOOLING_PATHS)

    _EDITOR_EXTENSION = re.compile(
        r"\.vsix!|(?:^|/)\.(?:vscode|vscode-insiders|vscode-oss|vscode-server|cursor|windsurf)"
        r"/extensions/[^/\n]{1,200}/"
    )

    @staticmethod
    def is_editor_extension(path: str) -> bool:
        """Whether a path is inside an editor extension: a `.vsix` member, or an installed
        extension's folder. The editor starts its code on its own and never runs npm in it."""
        return SourcePaths._EDITOR_EXTENSION.search(path) is not None

    @staticmethod
    def is_generated_artefact(path: str) -> bool:
        """Whether a path is build output rather than source somebody wrote.

        Including a bundle named by its content hash -- webpack's `[name].[contenthash].js`, which is
        how jupyterlab, notebook and streamlit ship their front ends inside a Python package
        (`jupyterlab/static/2874.ea9bd8ad31b1acb0.js`). Nobody writes a file with a hash in its
        name; a bundler does.
        """
        return (
            SourcePaths._names(path, GENERATED_ARTEFACT_PATHS)
            or CONTENT_HASHED_ASSET.search(path) is not None
            or SourcePaths._base64url_hashed(path)
        )

    @staticmethod
    def _base64url_hashed(path: str) -> bool:
        found = BASE64URL_HASHED_ASSET.search(path)
        if found is None:
            return False
        token = found.group(1)
        return bool(sum(c.isdigit() for c in token) >= 2 and sum(c.isupper() for c in token) >= 2)

    @staticmethod
    def is_bulk_data(path: str, rows: int) -> bool:
        """Whether this file is a dataset rather than something a person wrote line by line.

        `Asabeneh/30-Days-Of-Python` ships a twenty-thousand-row Hacker News export for its
        exercises, and one row's link is a Vimeo CDN URL with a signed `token=` in the query
        string. The row was scraped from a web page in 2016; nobody chose to put it there,
        and the signature expired the same day.

        A grade and not a dismissal, for the reason every ceiling in this file is: a
        dataset of ten thousand real API keys is a leak, and the collapse rules are what
        keep it from being ten thousand findings. What the grade says is that a credential
        here arrived with the data.
        """
        extension = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
        return extension in BULK_DATA_EXTENSIONS and rows >= BULK_DATA_ROWS

    @staticmethod
    def is_vendored(path: str) -> bool:
        """Whether this path is inside a vendored dependency -- including a member of a Java
        archive another package bundles, which is that library's compiled code (pyspark ships
        Hadoop's jars, and their classes are Hadoop's)."""
        if ".jar!" in path or ".war!" in path:
            return True
        return any(segment.lower() in VENDORED_SEGMENTS for segment in path.split("/"))


#: Words that end in "test" and are not about testing.
#:
#: `**/*test/**` was added to `TEST_MATERIAL_PATHS` for `caddytest/` and two existing
#: tests refused it within one run: `docs/latest/guide.md` and `src/latest/config.py`
#: are not test trees, and they were right. A glob cannot tell a compound from a word
#: that happens to end the same way, so the exceptions are named.
NOT_A_TEST_WORD = frozenset(
    {
        # The one that was measured: `docs/latest/` and `src/latest/` are release
        # directories and two existing tests said so.
        "latest",
        "contest",
        "protest",
        "attest",
        "detest",
        # English forms the superlative of an adjective ending in `t` by adding `est`,
        # so every one of them ends in the four letters this predicate looks for. None
        # of these has been seen naming a directory; they are here because the class is
        # real and a reader should not have to rediscover it.
        "fastest",
        "greatest",
        "lightest",
        "brightest",
        "shortest",
        "softest",
        "quietest",
        "smartest",
        "neatest",
        "sweetest",
    }
)


TEST_DIRECTORY_SUFFIXES = ("test", "tests", "testing")


TEST_DIRECTORY_COMPOUNDS = (
    *TEST_DIRECTORY_SUFFIXES,
    # Words that make a directory test material when they are PART of its name. A
    # directory called `examples/` or `demo/` outright is already a glob in
    # `TEST_MATERIAL_PATHS`; this is the compound spelling, which a glob cannot see.
    #
    # `mbedtls` keeps two RSA keys in `yotta/data/example-benchmark/main.cpp`.
    # `docker-mailserver` ships a TLS key under `demo-setups/`. `coolify` seeds four
    # of them from `database/seeders/`, and `postal` keeps a signing key in
    # `docker/ci-config/`.
    "example",
    "examples",
    "demo",
    "demos",
    "sample",
    "samples",
    "seeder",
    "seeders",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "dummy",
    # `ut` for unit test, which is the convention across Yandex's C++ projects and the
    # ones that took their layout: `catboost` keeps a TLS key at
    # `library/cpp/neh/ut/server.pem`. An exact part, like `ci` below.
    "ut",
    # A continuous-integration directory holds what the pipeline needs rather than what
    # the product ships. `postal` keeps a signing key in `docker/ci-config/` and
    # `dragonflydb` a TLS key in `contrib/charts/dragonfly/ci/`. An exact part, so
    # `pci-config` and `uci/` are untouched.
    "ci",
)
"""Words that make a compound directory name test material. See `names_test_directory`."""


TEST_FILE_WORDS = (
    *TEST_DIRECTORY_SUFFIXES,
    # The other names a project gives the same thing, in a FILENAME only. A directory
    # called `examples/` or `samples/` is already a glob in `TEST_MATERIAL_PATHS`; these
    # are the one-file spellings. `photoprism` keeps three session tokens in
    # `internal/entity/auth_session_fixtures.go`, beside the entity it builds them for,
    # which is where Go convention puts them.
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "stub",
    "stubs",
    "dummy",
    "sample",
    "samples",
    "example",
    "examples",
)
"""Words in a filename that say the file holds material written for a test.

Not used for directories. `seed` and `example` as directory names reach too far -- a
`seed/` directory in a data pipeline is production input and `example/` is where a
library keeps code somebody is meant to run -- and the directory question is answered
by `TEST_MATERIAL_PATHS` and `names_test_directory` already.

Twelve words were here and are not: `seed`, `seeds`, `seeder`, `seeders`, `demo`,
`demos`, `local`, `localhost`, `localdev`, `dev`, `default` and `defaults`. They were
added for key and manifest files -- `local.key`, `key.default.pem`,
`pacman-stateful-demo.yaml` -- and a cumulative measurement over a real repository
showed what they cost everywhere else. See `NON_PRODUCTION_MARKERS`.
"""


NON_PRODUCTION_MARKERS = frozenset(
    {
        "local",
        "localhost",
        "localdev",
        "dev",
        "default",
        "defaults",
        "demo",
        "demos",
        "seed",
        "seeds",
        "seeder",
        "seeders",
    }
)
"""Markers that a file is not the production one, read only on a key or config file.

These were in `TEST_FILE_WORDS`, where they applied to any filename at all, and a
cumulative measurement over the 4,104 tracked files of a real Django repository showed
the cost: 39 files claimed by `seed` were data migrations and management commands --
`migrations/0032_seed_opinion_types.py`, `management/commands/seed_opinion_types.py` --
and `default` and `defaults` claimed five more migrations plus
`services/intake_defaults_service.py`, while `local` claimed
`providers/local_embedding_provider.py`. A data migration runs against the production
database. A credential in one is a real leak, and it was being graded to MEDIUM.

What the words were added for was key material and configuration: `local.key`,
`key.default.pem`, `localhost.pem`, `autograph_localdev_config.yaml`,
`pacman-stateful-demo.yaml`. So the marker now means something only where the extension
says the file holds key material or configuration, and on a source file it is just a
word in a name. See `MARKED_EXTENSIONS`.
"""


MARKED_EXTENSIONS = frozenset(
    {
        # Key material.
        ".key",
        ".pem",
        ".crt",
        ".cer",
        ".der",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".pub",
        ".asc",
        # Configuration, which is the other place a generated local credential lands.
        ".yaml",
        ".yml",
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".toml",
        ".json",
        ".tf",
        ".tfvars",
    }
)
"""Extensions where a non-production marker in the filename means something.

Deliberately no source extensions. `.py`, `.go`, `.ts`, `.rb`, `.java` and the rest are
where the measurement found the damage: a Django data migration is `.py`, and so is a
service."""


ONE_WORD_TEST_FILES = frozenset({"conftest", "runtests"})
"""Test-infrastructure filenames spelled as one word: pytest's `conftest.py`, and the
`runtests.py` test driver Cython, CPython and SciPy ship at their roots."""


#: Where a project keeps the tooling that builds, tests and releases it.
#:
#: Measured across 338 of the most-starred repositories on GitHub, roughly HALF of
#: every `SUSPECT.EXFIL.001`, `SUSPECT.DROPPER.001` and `SUSPECT.ANTI_ANALYSIS.001`
#: finding landed here -- `scripts/dist.sh`, `packaging/utils/coverity-scan.sh`,
#: `.buildkite/scripts/dra-workflow.trigger.sh`, `publish_vec_binaries.sh`,
#: `setup.py`. Each of those reads a token from the environment, calls an API and
#: runs a command, which is credential plus egress plus spawn, which is the
#: composite. It is also what publishing a release IS.
#:
#: The composite's own documentation admitted this shape was the problem -- "a deploy
#: script that pushes and posts to Slack" is in the comment explaining why a third
#: signal was added -- and it was still firing on exactly that, in a third of all
#: repositories.
#:
#: What separates publishing from exfiltration is where the data goes, which the rule
#: cannot decide offline. So this is a ceiling, not a suppression, and three things
#: keep it from being a hole:
#:
#: `MALICIOUS` findings are never ceilinged, so a dropper is still a dropper here.
#: The install-hook escalation is applied AFTER, so anything that runs unprompted
#: reaches CRITICAL regardless of the directory it sits in. And a script in here runs
#: when somebody runs it, which is not the threat model the composites are calibrated
#: for -- that one is code executing without being asked.
BUILD_TOOLING_PATHS = (
    "scripts/**",
    "**/scripts/**",
    "script/**",
    "**/.github/**",
    "**/.buildkite/**",
    "**/.circleci/**",
    "**/.gitlab/**",
    "**/.azure-pipelines/**",
    "ci/**",
    "**/ci/**",
    "**/build/**",
    "**/packaging/**",
    "**/tools/**",
    "**/tool/**",
    # webpack keeps its build helpers in `tooling/` and its bootstrap in `setup/`,
    # neither of which `tools/` reaches.
    "**/tooling/**",
    "**/dev-tools/**",
    "**/devtools/**",
    "**/build-tools/**",
    "**/buildtools/**",
    "**/build-tools-internal/**",
    "**/setup/**",
    "**/bin/**",
    "**/etc/**",
    "**/utils/build/**",
    # `buildutils` and its spellings. The list already carries `build-tools`,
    # `buildtools`, `dev-tools`, `devtools` and `tooling`, and missing this one
    # cost `jupyterlab/jupyterlab` its clean result: `buildutils/src/
    # local-repository.ts` runs `npm publish` against a local verdaccio registry
    # so the build can test publishing, and `SUSPECT.REGISTRY.SELF_PUBLISH.001`
    # read it as a registry-spam worm. The same asymmetry as `release-*.sh`
    # matching where `release-*.js` did not.
    "**/buildutils/**",
    "**/build-utils/**",
    "**/buildUtils/**",
    "**/hack/**",
    "**/dev/**",
    "**/devel/**",
    "**/devel-common/**",
    "**/contrib/**",
    "**/infra/**",
    "**/Makefile",
    "**/makefile",
    "**/*.mk",
    "**/setup.py",
    "**/conftest.py",
    "**/noxfile.py",
    "**/tasks.py",
    "**/Rakefile",
    "**/Gruntfile.js",
    "**/gulpfile.js",
    # Named for what they do, wherever they live. `publish_simdjson_binaries.sh`
    # sits under `libs/simdjson/native/`, which no directory glob reaches.
    # The verb has to be a whole word, the same discipline the credential keywords
    # needed: `**/publish*` also matched `src/publisher.py`, which is application
    # code. A separator or the end of the stem after the verb, never an arbitrary
    # continuation.
    "**/publish",
    "**/publish.*",
    "**/publish_*",
    "**/publish-*",
    "**/release.*",
    "**/release_*.sh",
    "**/release-*.sh",
    "**/deploy.*",
    "**/deploy_*.sh",
    "**/deploy-*.sh",
    "**/upload_*.sh",
    "**/upload-*.sh",
    # A release script is not written in one language. `publish-*` above takes
    # any extension and `release.*` takes any extension, but `release-*` and its
    # siblings were limited to `.sh` -- so `release.js` was the project's own
    # tooling and `release-if-necessary.js` was not. `apache/superset` keeps the
    # latter at `superset-embedded-sdk/`, where it checks the registry for the
    # current version and runs `npm publish` if it is missing, and it came out
    # as a HIGH registry-worm finding on that asymmetry alone.
    #
    # Named extensions rather than a bare wildcard, deliberately. The ceiling
    # says "written to be read rather than run", and widening it by name is how
    # a payload called `release-notes.bin` would inherit an excuse it has not
    # earned.
    "**/release_*.js",
    "**/release-*.js",
    "**/release_*.mjs",
    "**/release-*.mjs",
    "**/release_*.cjs",
    "**/release-*.cjs",
    "**/release_*.ts",
    "**/release-*.ts",
    "**/release_*.py",
    "**/release-*.py",
    "**/deploy_*.js",
    "**/deploy-*.js",
    "**/deploy_*.mjs",
    "**/deploy-*.mjs",
    "**/deploy_*.ts",
    "**/deploy-*.ts",
    "**/deploy_*.py",
    "**/deploy-*.py",
    "**/bootstrap.*",
    "**/bootstrap_*.sh",
    # `install/` as a DIRECTORY, not just `install.sh`. The Proxmox helper-script
    # collection keeps `install/mysql-install.sh`, `install/zammad-install.sh` and a
    # hundred siblings, each of which sets up a systemd unit - and persistence is what
    # an installer is for. `SUSPECT.PERSIST.001` produced five hundred findings across
    # 104 repositories, and installer directories were most of them.
    "**/install/**",
    "**/installer/**",
    "**/installers/**",
    "**/provision/**",
    "**/provisioning/**",
    "**/install.sh",
    "**/install_*.sh",
    "**/install-*.sh",
    "**/*-release.sh",
    "**/*_release.sh",
    "**/*-deploy.sh",
    "**/*_deploy.sh",
    "**/*_binaries.sh",
    "**/*-binaries.sh",
)


#: Build output: the compiled form of source that was reviewed in its readable form.
#:
#: A minified bundle contains a decoder next to an evaluator because that is what a
#: module loader is. `pdf.worker.min.mjs`, `.yarn/releases/yarn-4.17.1.cjs` and a
#: bundled GitHub Action's `dist/index.js` were all reported for decode-and-execute,
#: and all three are generated.
#:
#: Deliberately NOT including `vendor/` or `node_modules/`. Those hold somebody
#: else's SOURCE, which is exactly where a supply-chain payload lives, and ceilinging
#: them would blunt the rules where they matter most.
GENERATED_ARTEFACT_PATHS = (
    "**/*.min.js",
    "**/*.min.mjs",
    "**/*.min.cjs",
    "**/*.min.css",
    "**/*.bundle.js",
    "**/*.bundle.mjs",
    "**/.yarn/releases/**",
    "**/.yarn/plugins/**",
    "**/dist/**",
    "**/build/static/**",
    "**/*.map",
    "**/*.pb.go",
    "**/*_pb2.py",
    "**/*_pb2_grpc.py",
    "**/*.pb.cc",
    "**/*.generated.*",
    "**/generated/**",
    "**/__generated__/**",
)


CONTENT_HASHED_ASSET = re.compile(r"(?:^|/)[\w.-]{1,80}[.-][0-9a-f]{8,32}\.(?:m?js|cjs|css)$")
"""webpack's hex `[contenthash]`."""


BASE64URL_HASHED_ASSET = re.compile(r"(?:^|/)[\w.-]{1,80}[.-]([A-Za-z0-9_-]{8})\.(?:m?js|cjs|css)$")
"""Vite's eight-character base64url hash, `katex.B0YdJus7.js`. Accepted only with at least two
digits and two capitals, which `v2Helper` and every other camelCase word a person picks fail."""


BULK_DATA_EXTENSIONS = frozenset({".csv", ".tsv", ".psv", ".jsonl", ".ndjson"})
"""Extensions whose whole purpose is one record per line."""


BULK_DATA_ROWS = 200
"""How many rows before a file of records is a dataset rather than a table somebody typed.

High enough that a hand-maintained mapping -- a country list, a feature matrix, a
fixture of twenty users -- is nowhere near it, and low enough that anything scraped or
exported clears it easily.
"""


VENDORED_SEGMENTS = frozenset(
    {
        "node_modules",
        "bower_components",
        "vendor",
        "vendored",
        "extern",
        "third_party",
        "thirdparty",
        "3rdparty",
        "deps",
        "external",
        "site-packages",
        "dist-packages",
        ".venv",
        "venv",
        "pods",
        "carthage",
        ".cargo",
        ".gradle",
        ".m2",
        ".nuget",
        "gems",
        "bundle",
    }
)
"""Path segments under which the code belongs to somebody else.

The manifest detector has asked this question since the beginning -- whether a
`package.json` belongs to an installed dependency -- and the content detectors never
did, so a finding in vendored source was graded as though this repository had written
it. Homebrew vendors the `plist` gem under
`Library/Homebrew/vendor/bundle/ruby/4.0.0/gems/plist-3.7.2/`, whose XML parser decodes
base64 and evaluates, which is what a plist parser does. Node vendors OpenSSL under
`deps/`; Moby vendors a hundred Go modules under `vendor/`.

A ceiling rather than an exemption, because vendored code is exactly where a
supply-chain attack lands. It stays in the report, saying so, at a severity that does
not fail somebody else's build on this project's behalf."""


__all__ = [
    "BASE64URL_HASHED_ASSET",
    "BUILD_TOOLING_PATHS",
    "BULK_DATA_EXTENSIONS",
    "BULK_DATA_ROWS",
    "CONTENT_HASHED_ASSET",
    "DOCUMENTATION_PATHS",
    "FIXTURE_CEILING",
    "GENERATED_ARTEFACT_PATHS",
    "MARKED_EXTENSIONS",
    "NON_PRODUCTION_MARKERS",
    "NOT_A_TEST_WORD",
    "ONE_WORD_TEST_FILES",
    "TEST_DIRECTORY_COMPOUNDS",
    "TEST_DIRECTORY_SUFFIXES",
    "TEST_FILE_WORDS",
    "VENDORED_SEGMENTS",
    "SourcePaths",
]
