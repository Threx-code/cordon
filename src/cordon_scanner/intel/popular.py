"""Popular-package sets, for typosquat comparison.

Typosquat detection needs an answer to two questions: what is this name close
to, and is this name itself real? Both are answered locally, from data shipped
with the scanner, because constraint C2 forbids reaching the network at scan
time -- and a security tool that phones a registry to ask about the code it is
scanning is doing something worse than the thing it warns about.

The popular list is deliberately short, and that reasoning applies to it ONLY.
A typosquat is worth registering against a package popular enough that the
mistyped install happens by accident, and every name added here is another string
some legitimate package may sit one edit away from -- so growth costs precision.

The allowlist behaves in the opposite direction and lives in `intel/real.py`. It
answers "does this name exist", a name known to exist is never reported as a squat
of anything, and so growth there can only remove false accusations. Treating the
two sets as one thing is what produced the defect `real.py` documents: a
forty-name allowlist asserted "and is not itself a known package" about `psycopg`
and `colord`, at high severity, in two of the first four real repositories
scanned.

These are shipped as code rather than as a downloaded database because they
change slowly and because an offline install must work with no extra artefact.
A refreshable database supplements this set; it does not replace it.
"""

from __future__ import annotations

from typing import ClassVar, Final

from cordon_scanner.intel.real import REAL_PACKAGES

# The most-installed packages per ecosystem, plus the names most commonly
# targeted in published squatting incidents.
_NPM: Final = frozenset(
    {
        "lodash",
        "react",
        "react-dom",
        "axios",
        "express",
        "chalk",
        "commander",
        "debug",
        "moment",
        "request",
        "async",
        "underscore",
        "bluebird",
        "colors",
        "vue",
        "webpack",
        "babel-core",
        "typescript",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "chai",
        "socket.io",
        "mongoose",
        "dotenv",
        "uuid",
        "body-parser",
        "cors",
        "jsonwebtoken",
        "bcrypt",
        "redis",
        "next",
        "node-fetch",
        "cross-env",
        "rimraf",
        "glob",
        "minimist",
        "yargs",
        "semver",
        "tslib",
        "classnames",
        "prop-types",
        "redux",
        "rxjs",
        "graphql",
        "apollo-client",
        "styled-components",
        "tailwindcss",
        "@babel/core",
        "@types/node",
        "esbuild",
        "vite",
        "rollup",
        "postcss",
        "nodemon",
        "concurrently",
        "husky",
        "lint-staged",
        "cheerio",
        "puppeteer",
    }
)

_PYPI: Final = frozenset(
    {
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "setuptools",
        "six",
        "boto3",
        "botocore",
        "python-dateutil",
        "certifi",
        "idna",
        "charset-normalizer",
        "pyyaml",
        "click",
        "jinja2",
        "markupsafe",
        "flask",
        "sqlalchemy",
        "pytest",
        "attrs",
        "packaging",
        "typing-extensions",
        "cryptography",
        "pillow",
        "scipy",
        "matplotlib",
        "scikit-learn",
        "beautifulsoup4",
        "lxml",
        "colorama",
        "tqdm",
        "protobuf",
        "grpcio",
        "google-api-core",
        "pyparsing",
        "wheel",
        "pip",
        "virtualenv",
        "tomli",
        "rich",
        "httpx",
        "pydantic",
        "fastapi",
        "uvicorn",
        "starlette",
        "celery",
        "redis",
        "psycopg2",
        "pymongo",
        "openpyxl",
        "selenium",
        "paramiko",
        "pyjwt",
        "tensorflow",
        "torch",
        "transformers",
        "openai",
        "anthropic",
        "aiohttp",
    }
)

_CARGO: Final = frozenset(
    {
        "serde",
        "serde_json",
        "tokio",
        "rand",
        "libc",
        "log",
        "regex",
        "clap",
        "reqwest",
        "anyhow",
        "thiserror",
        "futures",
        "chrono",
        "itertools",
        "lazy_static",
        "once_cell",
        "bytes",
        "hyper",
        "syn",
        "quote",
        "proc-macro2",
        "tracing",
        "uuid",
        "base64",
        "sha2",
        "hex",
        "num-traits",
    }
)

_GO: Final = frozenset(
    {
        "github.com/stretchr/testify",
        "github.com/sirupsen/logrus",
        "github.com/spf13/cobra",
        "github.com/spf13/viper",
        "github.com/gin-gonic/gin",
        "github.com/gorilla/mux",
        "google.golang.org/grpc",
        "google.golang.org/protobuf",
        "github.com/pkg/errors",
        "gopkg.in/yaml.v3",
        "github.com/google/uuid",
        "github.com/aws/aws-sdk-go",
        "golang.org/x/crypto",
        "golang.org/x/net",
    }
)

_RUBYGEMS: Final = frozenset(
    {
        "rails",
        "rake",
        "bundler",
        "rspec",
        "nokogiri",
        "puma",
        "sinatra",
        "activesupport",
        "activerecord",
        "devise",
        "sidekiq",
        "pg",
        "mysql2",
        "redis",
        "json",
        "rubocop",
        "faraday",
        "httparty",
        "jwt",
        "dotenv",
    }
)

_COMPOSER: Final = frozenset(
    {
        "symfony/console",
        "monolog/monolog",
        "guzzlehttp/guzzle",
        "phpunit/phpunit",
        "laravel/framework",
        "doctrine/orm",
        "psr/log",
        "nikic/php-parser",
        "vlucas/phpdotenv",
        "ramsey/uuid",
        "firebase/php-jwt",
    }
)

_MAVEN: Final = frozenset(
    {
        "org.slf4j:slf4j-api",
        "com.google.guava:guava",
        "junit:junit",
        "org.apache.commons:commons-lang3",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.springframework:spring-core",
        "org.springframework.boot:spring-boot",
        "ch.qos.logback:logback-classic",
        "org.mockito:mockito-core",
    }
)

_NUGET: Final = frozenset(
    {
        "newtonsoft.json",
        "serilog",
        "automapper",
        "dapper",
        "nunit",
        "xunit",
        "moq",
        "polly",
        "fluentvalidation",
        "mediatr",
        "restsharp",
    }
)


class PackageIntel:
    """The set of package names known to exist, per ecosystem.

    Held as one class because the two tables are read together and mean nothing
    apart: the popular set is what typosquat comparison measures distance
    *from*, and the neighbour set is what stops a real package that happens to
    sit near a popular one being reported as a squat of it. Splitting them
    invites a change to one without the other, and that shows up as a false
    accusation against a real maintainer.

    Bundled rather than fetched. A scan works offline, so the data ships with
    the tool and is versioned with it.
    """

    POPULAR_PACKAGES: ClassVar[dict[str, frozenset[str]]] = {
        "npm": _NPM,
        "pypi": _PYPI,
        "cargo": _CARGO,
        "gomod": _GO,
        "rubygems": _RUBYGEMS,
        "composer": _COMPOSER,
        "maven": _MAVEN,
        "gradle": _MAVEN,
        "nuget": _NUGET,
    }

    # Kept as the hand-curated supplement to `intel/real.py`, which carries the
    # bulk of the allowlist. A name belongs here when it is a real package worth
    # recording beside the popular set it sits next to; anything else goes in
    # `real.py`, which is organised by ecosystem rather than by neighbour.
    #
    # This table alone WAS the allowlist, across nine ecosystems, five of which
    # had no entries at all. See `real.py` for what that cost.
    _KNOWN_NEIGHBOURS: ClassVar[dict[str, frozenset[str]]] = {
        "npm": frozenset(
            {
                "preact",
                "inferno",
                "reactor",
                "lodash-es",
                "lodash.merge",
                "async-mutex",
                "colorette",
                "debounce",
                "express-session",
                "node-forge",
                "axios-retry",
                "chalk-template",
                "commander-js",
                "vue-router",
                "webpack-cli",
                "jest-cli",
                "uuid-js",
                "cors-anywhere",
            }
        ),
        "pypi": frozenset(
            {
                "requests-oauthlib",
                "requests-toolbelt",
                "urllib3-secure-extra",
                "numpy-financial",
                "pandas-gbq",
                "pytest-cov",
                "pytest-django",
                "flask-cors",
                "flask-login",
                "click-default-group",
                "redis-py-cluster",
                "types-requests",
                "boto",
                "botocore-stubs",
                "torch-audio",
            }
        ),
        "cargo": frozenset({"serde_derive", "tokio-util", "rand_core", "regex-syntax"}),
    }

    @classmethod
    def is_known_package(cls, ecosystem: str, normalized_name: str) -> bool:
        """Whether a name is a package known to exist.

        Checked before typosquat comparison, so a real package that happens to
        sit near a popular one is never reported as a squat of it.

        Three sources, read as one: the popular set, the shipped allowlist in
        `intel/real.py`, and the curated neighbours below.

        Still not a registry, and it cannot be -- which is why the detector no
        longer reports an ASCII near-miss at a severity that blocks a build. The
        previous note here said an omission costs "one false positive on an
        unusual package". That was the wrong model of the risk: `psycopg` and
        `colord` are not unusual, and an omission costs a high-severity
        accusation against a real maintainer's package. The allowlist is sized for
        that now, and the severity reflects what a name comparison can actually
        support.
        """
        candidates = (
            cls.POPULAR_PACKAGES.get(ecosystem, frozenset())
            | REAL_PACKAGES.get(ecosystem, frozenset())
            | cls._KNOWN_NEIGHBOURS.get(ecosystem, frozenset())
        )
        if normalized_name in candidates:
            return True

        # Under the ecosystem's own normalisation, because the sets are written
        # as each project spells itself and the argument arrives normalised.
        # Cargo folds `_` to `-`, so `serde_json` in this set never matched the
        # `serde-json` it was asked about -- and the caller then went looking
        # for a typosquat target and found the same package.
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        implementation = EcosystemRegistry.get(ecosystem)
        if implementation is None:
            return False
        return any(implementation.normalize_name(name) == normalized_name for name in candidates)


__all__ = ["PackageIntel"]
