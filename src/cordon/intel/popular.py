"""Popular-package sets, for typosquat comparison.

Typosquat detection needs an answer to two questions: what is this name close
to, and is this name itself real? Both are answered locally, from data shipped
with the scanner, because constraint C2 forbids reaching the network at scan
time -- and a security tool that phones a registry to ask about the code it is
scanning is doing something worse than the thing it warns about.

The lists are deliberately short. A typosquat is only worth registering against
a package popular enough that the mistyped install happens by accident, and a
larger list makes false positives more likely without making detection better:
every additional name is another string that some legitimate package might sit
two edits away from.

These are shipped as code rather than as a downloaded database because they
change slowly and because an offline install must work with no extra artefact.
A refreshable database supplements this set; it does not replace it.
"""

from __future__ import annotations

from typing import Final

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

POPULAR_PACKAGES: Final[dict[str, frozenset[str]]] = {
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

# Names that are real packages but sit close to a popular one. Without this,
# every one of them is reported as a squat of its neighbour, which is exactly
# the false positive that gets a typosquat detector switched off.
#
# Each entry is a package that genuinely exists and is genuinely distinct.
_KNOWN_NEIGHBOURS: Final[dict[str, frozenset[str]]] = {
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


def is_known_package(ecosystem: str, normalized_name: str) -> bool:
    """Whether a name is a package known to exist.

    Checked before typosquat comparison, so a real package that happens to sit
    near a popular one is never reported as a squat of it.

    Necessarily incomplete: it lists the popular set plus a curated set of real
    neighbours, not every package in every registry. The consequence of an
    omission is one false positive on an unusual package, which is why the
    plausibility check in the detector must also pass before anything is
    reported.
    """
    if normalized_name in POPULAR_PACKAGES.get(ecosystem, frozenset()):
        return True
    return normalized_name in _KNOWN_NEIGHBOURS.get(ecosystem, frozenset())


__all__ = ["POPULAR_PACKAGES", "is_known_package"]
