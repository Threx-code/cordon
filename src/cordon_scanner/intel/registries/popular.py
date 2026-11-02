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

from cordon_scanner.intel.registries.real import RealPackages

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
        # Absent while `flask`, `fastapi`, `starlette` and `celery` were all
        # here, which is not a judgement about Django: it is the most used
        # Python web framework and a named target in published squatting
        # incidents. Nothing in the known-package set sits a plausible slip
        # from it, so the precision this list trades away per name costs
        # nothing here.
        "django",
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


# The eight ecosystems that had no popular set. `_typosquat_target` returns
# early when one is empty, so a Hex, CRAN, Swift, Conan, conda, Bazel, pub or
# CocoaPods dependency was never compared against anything: the check did not
# fire, and nothing said it had not run. Each set stays short for the reason
# stated at the top of this module -- every name here is another string a real
# package may sit one edit away from -- and each is paired with an allowlist in
# `intel/real.py`, which is what keeps that cost bounded.
_HEX_POPULAR: Final = frozenset(
    {
        "absinthe",
        "broadway",
        "cowboy",
        "credo",
        "ecto",
        "ecto_sql",
        "floki",
        "gettext",
        "httpoison",
        "jason",
        "nimble_parsec",
        "oban",
        "phoenix",
        "plug",
        "poison",
        "postgrex",
        "telemetry",
        "tesla",
    }
)

_CRAN_POPULAR: Final = frozenset(
    {
        "Rcpp",
        "caret",
        "data.table",
        "devtools",
        "dplyr",
        "ggplot2",
        "httr",
        "jsonlite",
        "knitr",
        "lubridate",
        "purrr",
        "readr",
        "rmarkdown",
        "shiny",
        "stringr",
        "testthat",
        "tibble",
        "tidyr",
    }
)

# Names of five characters or more only: `mtl`, `stm`, `text` and `lens` sit one edit from
# dozens of real Hackage packages each.
_HACKAGE_POPULAR: Final = frozenset(
    {
        "QuickCheck",
        "aeson",
        "attoparsec",
        "bytestring",
        "conduit",
        "containers",
        "hspec",
        "http-client",
        "megaparsec",
        "optparse-applicative",
        "servant",
        "unordered-containers",
        "vector",
    }
)

_JULIA_POPULAR: Final = frozenset(
    {
        "BenchmarkTools",
        "DataFrames",
        "DataStructures",
        "DifferentialEquations",
        "Distributions",
        "Documenter",
        "ForwardDiff",
        "JuMP",
        "Makie",
        "OrderedCollections",
        "Plots",
        "Revise",
        "StaticArrays",
        "StatsBase",
    }
)

_OPAM_POPULAR: Final = frozenset(
    {
        "alcotest",
        "cmdliner",
        "cohttp",
        "menhir",
        "ocamlfind",
        "ppx_deriving",
        "ppxlib",
        "sexplib",
        "yojson",
        "zarith",
    }
)

_VCPKG_POPULAR: Final = frozenset(
    {
        "abseil",
        "catch2",
        "eigen3",
        "gtest",
        "nlohmann-json",
        "opencv",
        "openssl",
        "protobuf",
        "spdlog",
        "sqlite3",
    }
)

_ANSIBLE_POPULAR: Final = frozenset(
    {
        "amazon.aws",
        "ansible.posix",
        "ansible.utils",
        "ansible.windows",
        "community.crypto",
        "community.docker",
        "community.general",
        "community.mysql",
        "geerlingguy.docker",
        "kubernetes.core",
    }
)

_TERRAFORM_POPULAR: Final = frozenset(
    {
        "hashicorp/aws",
        "hashicorp/azurerm",
        "hashicorp/google",
        "hashicorp/helm",
        "hashicorp/kubernetes",
        "hashicorp/random",
        "hashicorp/tls",
        "terraform-aws-modules/eks/aws",
        "terraform-aws-modules/vpc/aws",
    }
)

_HELM_POPULAR: Final = frozenset(
    {
        "argo-cd",
        "cert-manager",
        "external-dns",
        "grafana",
        "ingress-nginx",
        "kube-prometheus-stack",
        "metrics-server",
        "postgresql",
        "prometheus",
        "redis",
    }
)

_HOMEBREW_POPULAR: Final = frozenset(
    {
        "awscli",
        "bat",
        "cmake",
        "coreutils",
        "curl",
        "ffmpeg",
        "fzf",
        "gh",
        "git",
        "gnupg",
        "go",
        "htop",
        "imagemagick",
        "jq",
        "kubernetes-cli",
        "neovim",
        "node",
        "openssl@3",
        "postgresql@16",
        "python@3.12",
        "redis",
        "ripgrep",
        "rust",
        "terraform",
        "tmux",
        "tree",
        "wget",
        "yq",
        "zsh",
    }
)

_NIX_POPULAR: Final = frozenset(
    {
        "cachix/devenv",
        "hercules-ci/flake-parts",
        "nix-community/home-manager",
        "nix-community/nixvim",
        "nixos/nixpkgs",
        "numtide/flake-utils",
        "oxalica/rust-overlay",
    }
)

_SWIFT_POPULAR: Final = frozenset(
    {
        "alamofire/alamofire",
        "apple/swift-argument-parser",
        "apple/swift-collections",
        "apple/swift-crypto",
        "apple/swift-log",
        "apple/swift-nio",
        "apple/swift-protobuf",
        "grpc/grpc-swift",
        "jpsim/yams",
        "onevcat/kingfisher",
        "pointfreeco/swift-composable-architecture",
        "quick/nimble",
        "quick/quick",
        "realm/realm-swift",
        "snapkit/snapkit",
        "vapor/vapor",
    }
)

_CONAN_POPULAR: Final = frozenset(
    {
        "benchmark",
        "boost",
        "catch2",
        "eigen",
        "fmt",
        "gtest",
        "libcurl",
        "nlohmann_json",
        "opencv",
        "openssl",
        "poco",
        "protobuf",
        "rapidjson",
        "spdlog",
        "sqlite3",
        "zlib",
    }
)

_CONDA_POPULAR: Final = frozenset(
    {
        "django",
        "flask",
        "jupyter",
        "matplotlib",
        "numpy",
        "pandas",
        "pillow",
        "pytest",
        "pytorch",
        "pyyaml",
        "requests",
        "scikit-learn",
        "scipy",
        "seaborn",
        "sqlalchemy",
        "tensorflow",
    }
)

_BAZEL_POPULAR: Final = frozenset(
    {
        "abseil-cpp",
        "bazel_skylib",
        "gazelle",
        "googletest",
        "platforms",
        "protobuf",
        "rules_cc",
        "rules_docker",
        "rules_go",
        "rules_java",
        "rules_nodejs",
        "rules_oci",
        "rules_pkg",
        "rules_proto",
        "rules_python",
        "rules_rust",
    }
)

_PUB_POPULAR: Final = frozenset(
    {
        "bloc",
        "cached_network_image",
        "dio",
        "flutter_bloc",
        "freezed",
        "get",
        "http",
        "image_picker",
        "intl",
        "json_serializable",
        "path_provider",
        "provider",
        "riverpod",
        "shared_preferences",
        "sqflite",
        "url_launcher",
    }
)

#: GitHub Actions: GitHub publishes no ranked usage export, so this is curated -- GitHub's own
#: actions and the verified creators' most-used ones, the names an impersonating action copies.
_ACTIONS_POPULAR: Final = frozenset(
    {
        "actions/attest-build-provenance",
        "actions/cache",
        "actions/checkout",
        "actions/configure-pages",
        "actions/create-github-app-token",
        "actions/dependency-review-action",
        "actions/deploy-pages",
        "actions/download-artifact",
        "actions/github-script",
        "actions/labeler",
        "actions/setup-dotnet",
        "actions/setup-go",
        "actions/setup-java",
        "actions/setup-node",
        "actions/setup-python",
        "actions/stale",
        "actions/upload-artifact",
        "actions/upload-pages-artifact",
        "aquasecurity/trivy-action",
        "astral-sh/setup-uv",
        "aws-actions/amazon-ecr-login",
        "aws-actions/configure-aws-credentials",
        "azure/login",
        "azure/webapps-deploy",
        "codecov/codecov-action",
        "docker/build-push-action",
        "docker/login-action",
        "docker/metadata-action",
        "docker/setup-buildx-action",
        "docker/setup-qemu-action",
        "dorny/paths-filter",
        "dtolnay/rust-toolchain",
        "github/codeql-action",
        "github/super-linter",
        "golangci/golangci-lint-action",
        "google-github-actions/auth",
        "google-github-actions/setup-gcloud",
        "goreleaser/goreleaser-action",
        "gradle/actions",
        "hashicorp/setup-terraform",
        "ossf/scorecard-action",
        "oven-sh/setup-bun",
        "peaceiris/actions-gh-pages",
        "peter-evans/create-pull-request",
        "pnpm/action-setup",
        "pre-commit/action",
        "pypa/gh-action-pypi-publish",
        "ruby/setup-ruby",
        "shivammathur/setup-php",
        "sigstore/cosign-installer",
        "slackapi/slack-github-action",
        "softprops/action-gh-release",
        "stefanzweifel/git-auto-commit-action",
        "step-security/harden-runner",
        "subosito/flutter-action",
        "swatinem/rust-cache",
    }
)

_COCOAPODS_POPULAR: Final = frozenset(
    {
        "AFNetworking",
        "Alamofire",
        "CocoaLumberjack",
        "Firebase",
        "IQKeyboardManager",
        "Kingfisher",
        "MBProgressHUD",
        "Masonry",
        "PromiseKit",
        "Realm",
        "RxSwift",
        "SDWebImage",
        "SnapKit",
        "SwiftLint",
        "SwiftyJSON",
        "lottie-ios",
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
        "hex": _HEX_POPULAR,
        "cran": _CRAN_POPULAR,
        "hackage": _HACKAGE_POPULAR,
        "julia": _JULIA_POPULAR,
        "opam": _OPAM_POPULAR,
        "vcpkg": _VCPKG_POPULAR,
        "ansible": _ANSIBLE_POPULAR,
        "terraform": _TERRAFORM_POPULAR,
        "helm": _HELM_POPULAR,
        "nix": _NIX_POPULAR,
        "homebrew": _HOMEBREW_POPULAR,
        "swift": _SWIFT_POPULAR,
        "conan": _CONAN_POPULAR,
        "conda": _CONDA_POPULAR,
        "bazel": _BAZEL_POPULAR,
        "pub": _PUB_POPULAR,
        "cocoapods": _COCOAPODS_POPULAR,
        "actions": _ACTIONS_POPULAR,
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
        return normalized_name in cls._known(ecosystem)

    #: Per ecosystem: the three sets it was built from, and every name in them as spelled and as
    #: the ecosystem normalises it (`_known`).
    _KNOWN: ClassVar[dict[str, tuple[tuple[frozenset[str], ...], frozenset[str]]]] = {}

    #: The empty set a lookup takes for a list that has no entry for its ecosystem (`_known`).
    _NONE: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def _known(cls, ecosystem: str) -> frozenset[str]:
        """Every known name of an ecosystem, as written and under the ecosystem's own
        normalisation, worked out once per set of lists. The sets are written as each project
        spells itself and a name arrives normalised: Cargo folds `_` to `-`, so `serde_json` in
        the set never matched the `serde-json` it was asked about, and the caller then went looking
        for a typosquat target and found the same package. Normalising every candidate on every
        lookup cost 17.7 M calls for the 1,020 names of one package-lock (34 s of a 35 s scan)."""
        # One empty set for every ecosystem a list lacks: a new `frozenset()` per call is a new
        # object, so the `is` check below never matched and the set was rebuilt on every lookup.
        # `REAL_PACKAGES[eco]` is a new union on every ask, so its two stable parts are held instead
        sets = (
            cls.POPULAR_PACKAGES.get(ecosystem, cls._NONE),
            *RealPackages.parts(ecosystem),
            cls._KNOWN_NEIGHBOURS.get(ecosystem, cls._NONE),
        )
        kept = cls._KNOWN.get(ecosystem)
        # The very sets, held, not their ids: a set replaced (a test, a refresh) is rebuilt.
        if kept is not None and all(a is b for a, b in zip(kept[0], sets, strict=True)):
            return kept[1]
        candidates = frozenset().union(*sets)
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        implementation = EcosystemRegistry.get(ecosystem)
        known = frozenset(candidates) | (
            frozenset(implementation.normalize_name(name) for name in candidates)
            if implementation is not None
            else frozenset()
        )
        cls._KNOWN[ecosystem] = (sets, known)
        return known


__all__ = ["PackageIntel"]
