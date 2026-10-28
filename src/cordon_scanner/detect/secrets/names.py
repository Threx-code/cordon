"""What a variable's name says about the value it holds: a secret's name, a public environment
prefix, or one of the names that look like a secret's and are not.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


#: Name endings that say the value is configuration ABOUT a credential.
#:
#: `REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/` was reported at HIGH as
#: "a credential assigned to 'REFRESH_TOKEN_COOKIE_PATH'". The value is a URL path.
#: The name says so.
#:
#: Matched on the NAME rather than the value, and that is the point. The obvious
#: fix was to widen the path shape in `NOT_A_SECRET`, which refuses this value only
#: because `v1` has a digit in it and because of the trailing slash. Widening it
#: would have been a bad trade: a real AWS secret key looks like
#: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` -- slashes, digits, segment-shaped --
#: and a path alternative permissive enough to accept a versioned URL accepts that
#: too. The rule would have gone quiet on the exact credential it exists to find.
#:
#: A name is safer ground because a developer chose it to describe the value. What
#: is given up is the case where somebody names the secret itself
#: `SECRET_KEY_FILE`; and even there, a value with a recognisable provider shape is
#: still caught by the provider patterns, which do not consult the name at all.
#: Only the generic entropy heuristic steps back.
#:
#: `KEY` is deliberately absent. `SECRET_KEY` and `API_KEY` are what this rule is
#: for.
CONFIGURATION_SUFFIXES = (
    "path",
    "paths",
    "url",
    "urls",
    "uri",
    "endpoint",
    "host",
    "hostname",
    "port",
    "dir",
    "directory",
    "file",
    "filename",
    "header",
    "field",
    "param",
    "params",
    "query",
    "cookie",
    "prefix",
    "suffix",
    "name",
    "names",
    "label",
    "ttl",
    "timeout",
    "expiry",
    "expires",
    "lifetime",
    "algorithm",
    "algo",
    "hasher",
    "encoding",
    "length",
    "min_length",
    "max_length",
    "rounds",
    "iterations",
    "enabled",
    "required",
    "env",
    "var",
    "variable",
    "scheme",
    "format",
    "pattern",
    "regex",
    "version",
    "type",
    "kind",
    "mode",
    "policy",
    "count",
    "counts",
    "limit",
    "limits",
    "size",
    "sizes",
    # Turned up by measuring against real repositories, each the last word of a name
    # that declares something about a credential rather than being one.
    "units",
    "unit",
    "scope",
    "scopes",
    "methodname",
    "classname",
    "fieldname",
    "keyname",
    "varname",
    "id",
    "ids",
    "index",
    "key_id",
    "column",
    "table",
    "default",
    "example",
    "placeholder",
    "hint",
    "description",
    "title",
    "message",
    "error",
    "status",
    "state",
    "flag",
    "source",
    "target",
    "provider",
    "backend",
    "strategy",
    "handler",
    "validator",
    "serializer",
    "parser",
    "encoder",
    "decoder",
)

#: Words that say the value is a location, wherever they appear in the name.
#:
#: Checked anywhere rather than only at the end, unlike `CONFIGURATION_SUFFIXES`,
#: because a location word is not a suffix -- `vaultPathTokenCreate` is a route and
#: `TOKEN_URL_OVERRIDE` is a URL, and in both the telling word is in the middle.
LOCATION_WORDS = frozenset(
    {
        "path",
        "paths",
        "url",
        "urls",
        "uri",
        "uris",
        "endpoint",
        "endpoints",
        "route",
        "routes",
        "location",
        "locations",
        "dir",
        "directory",
        "folder",
        "host",
        "hostname",
        "address",
        "addr",
        # `link`, which is what half the front-end world calls a URL. Ant Design's
        # token table declares `customizeTokenLink:
        # '/docs/react/customize-theme#customize-design-token'`, and a link is a place
        # to go by the same argument `url` and `endpoint` are.
        "link",
        "links",
        "href",
    }
)

#: Words in a NAME that say the value was never meant to work.
#:
#: Distinct from `PLACEHOLDER`, which reads the value. These read the name, for the
#: case where the author wrote a realistic-looking value on purpose: Home Assistant's
#: TOTP module declares `DUMMY_SECRET = "FPPTH34D4E3MI2HG"`, a valid base32 secret
#: whose whole job is to be verified against and fail, so that a login attempt for a
#: user who has no MFA configured takes the same time as one who does.
#:
#: Deliberately short, and `test` is deliberately absent. A `TEST_API_KEY` in CI is
#: very often a real key for a test account, and the fixture ceiling already covers
#: the case where the surrounding path says test material. Each word here is an
#: assertion by the author that the value does not authenticate to anything.
NOT_REAL_WORDS = frozenset(
    {
        "dummy",
        "fake",
        "bogus",
        "placeholder",
        "example",
        "sample",
        "notreal",
        "invalid",
        "nonexistent",
        "mock",
        "stub",
        "canary",
        # `demo` is here and `test` is not, and the asymmetry is deliberate. A
        # `TEST_API_KEY` in CI is very often a real key for a test account; demo data is
        # data nobody authenticates to. `**/demo/**` has been a test-material path since
        # the beginning, so this only says the same thing about the name.
        "demo",
    }
)


class SecretNames:
    """What a variable's name says about the value it holds."""

    @staticmethod
    def _fold(text: str) -> str:
        """A name reduced to letters and digits, lowercased."""
        return re.sub(r"[^a-z0-9]+", "", text.lower())

    @staticmethod
    def value_is_the_name(name: str, value: str) -> bool:
        """Whether the value is the NAME, written in another case or separator style.

        `V2_UPGRADE_TOKEN = "v2UpgradeToken"` in `bitwarden/android`,
        `TOKEN_STORAGE_INITIALIZATION = 'token_storage_initialization'` in `gemini-cli`,
        `SUCCESSFULLY_TOKENIZED = "successfully_tokenized"`, `SERVER_PASSWORD1 =
        "serverPassword1"`. Four of seventy sampled assignment findings, and the shape is
        the commonest thing a credential-shaped constant holds: an enum member, a storage
        key, a feature flag, a telemetry event -- the name, spelled the way the wire spells
        it.

        Folded to letters and digits so that the comparison is about the WORDS rather than
        the convention: camelCase against SCREAMING_SNAKE, a hyphen against an underscore.
        Exact equality after folding, not a prefix or a containment test, because
        `API_KEY = "api_key_aB3kQ9mZ2xT7"` is a real credential with its own name in front
        of it and has to stay reported.
        """
        folded = SecretNames._fold(value)
        return bool(folded) and folded == SecretNames._fold(name)

    @staticmethod
    def value_restates_the_name(name: str, value: str) -> bool:
        """Whether the value is the name with at most a word or a number attached.

        `value_is_the_name` asks for exact equality after folding, and explains why
        containment is refused: a real credential often carries its own name in front of
        it. This asks the narrower question -- is the value the name, plus almost nothing?

        `E2E_ADMIN_PASSWORD: E2eAdmin12345` in `langgenius/dify`'s end-to-end workflow
        shares `e2eadmin` with its name and then five digits.
        `bot_token: 123456789:telegram-bot-token` contains `bottoken` and is otherwise the
        word `telegram` and a run of digits. `detectorXMLFactoryBypass=XMLFactoryBypass`
        in `netty`'s `.fbprefs` is the name's own tail, with nothing left over at all.
        """
        folded_name, folded_value = SecretNames._fold(name), SecretNames._fold(value)
        if len(folded_name) < MIN_RESTATED_NAME or not folded_value:
            return False
        if folded_value in folded_name:
            remainder = ""
        elif folded_name in folded_value:
            remainder = folded_value.replace(folded_name, "", 1)
        else:
            shared = 0
            for a, b in zip(folded_name, folded_value, strict=False):
                if a != b:
                    break
                shared += 1
            if shared < MIN_RESTATED_NAME:
                return False
            remainder = folded_value[shared:]
        runs = re.findall(r"[a-z]+|[0-9]+", remainder)
        return len(runs) <= MAX_RESTATE_RUNS

    @staticmethod
    def names_public_by_contract(name: str) -> bool:
        """Whether a build tool compiles this variable into the client bundle by design."""
        folded = name.lower().lstrip("_")
        return folded.startswith(PUBLIC_ENV_PREFIXES)

    @staticmethod
    def _name_words(name: str) -> list[str]:
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
        return [w for w in re.split(r"[_\-.]+", spaced.strip("_-.").lower()) if w]

    @staticmethod
    def names_identifier(name: str) -> bool:
        """Whether the name says its value identifies something rather than authenticates it.

        `COPILOT_OAUTH_CLIENT_ID`, `legacyClientID`, `APP_ID`. A name with a secret word in it is not
        one, whatever it ends in: Vault's `secret_id` is the credential half of an AppRole login.
        """
        words = SecretNames._name_words(name)
        if words and words[-1] in NAMING_WORDS:
            # `_SECRET_NAMESPACE = 'oauth2client:secrets#ns'`, `SECRET_PREFIX`, `secretLabel`: the
            # name of the place a secret is filed, which is not the secret whatever word precedes it.
            return True
        return bool(words) and words[-1] in ("id", "ids") and not (_SECRET_WORDS & set(words))

    @staticmethod
    def names_client_secret(name: str) -> bool:
        """`ClientSecret`, `client_secret`, `rcloneObscuredClientSecret`."""
        words = SecretNames._name_words(name)
        return "client" in words and "secret" in words

    @staticmethod
    def names_placeholder(name: str) -> bool:
        """Whether the variable's own name says its value is not a real credential."""
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
        words = re.split(r"[_\-.]+", spaced.strip("_-.").lower())
        return bool(NOT_REAL_WORDS & set(words))

    @staticmethod
    def names_configuration(name: str) -> bool:
        """Whether this variable name describes a credential rather than holding one.

        Compared against the final word, not as a substring. `TOKEN_PATHS` is
        configuration; `TOKEN_PATHOLOGY` is not a word anybody writes, and a substring
        test would treat `SECRET_KEY_FILENAME_OVERRIDE` and `SECRET_KEYFILE` as the same
        shape when only one of them is.

        CamelCase counts as a separator, because half the world spells a compound name
        that way and splitting on `_` and `-` alone could not see it. Measured across the
        most-starred repositories on GitHub, that blind spot reported
        `AntiforgeryTokenFieldName` in ASP.NET Core, `awsContainerAuthorizationTokenEnv`
        in the AWS SDK, `SpiffeJwtNormalizedTokenUnits` in Vault, `credentialType` and
        `CredentialScope` -- every one of them a field name, an environment variable
        name, a unit or a type, and every one of them ending in a word already on this
        list.
        """
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
        words = re.split(r"[_\-.]+", spaced.strip("_-.").lower())
        if not words:
            return False

        # A location word ANYWHERE in the name, not only at the end. `path`, `url` and
        # `endpoint` say the value is somewhere to go, and that is true of the name
        # whatever order its words are in.
        #
        # Vault declares nine Go constants called `vaultPathTokenCreate`,
        # `vaultPathTokenRevokeSelf`, `vaultPathTokenLookup` and so on, each holding an
        # API route like "auth/token/create". Every one was reported as a credential,
        # because the last word is `create` and the word that matters is in the middle.
        if LOCATION_WORDS & set(words):
            return True

        last = words[-1]
        if last in CONFIGURATION_SUFFIXES:
            return True
        # Two-word endings such as `MIN_LENGTH`, written with the separator.
        return len(words) >= 2 and f"{words[-2]}_{last}" in CONFIGURATION_SUFFIXES


MIN_RESTATED_NAME = 6
"""How much of the name must appear in the value before the overlap means anything.

Six folded characters. `api_key` folds to six and `token` to five, which is the line
this is drawn at: a five-letter word turns up inside a random run often enough to
matter, and six with the rest of the value accounted for does not.
"""

MAX_RESTATE_RUNS = 2
"""How many runs of letters-or-digits may be left over after removing the name.

This is what keeps `API_KEY = "api_key_aB3kQ9mZ2xT7"` reported -- a real credential
with its own name in front of it, which `value_is_the_name` refuses containment for.
Once `apikey` is removed, `ab3kq9mz2xt7` is eight alternating runs. Two is a prefix
like `dev` or a suffix like `12345`, and nothing more.
"""

#: Prefixes a build tool treats as PUBLIC, by documented contract.
#:
#: Every one of these frameworks inlines a variable with the prefix into the client
#: bundle, and says so: Next.js `NEXT_PUBLIC_`, Vite `VITE_`, SvelteKit and Astro
#: `PUBLIC_`, Create React App `REACT_APP_`, Vue CLI `VUE_APP_`, Gatsby `GATSBY_`, Nuxt
#: `NUXT_PUBLIC_`, Expo `EXPO_PUBLIC_`, Storybook `STORYBOOK_`.
#:
#: A value under one of them is in the shipped JavaScript where anybody can read it, so
#: a finding about it has no remediation: it is not leaked, it is published.
#: `unionlabs/union` declares `PUBLIC_LOG_TOKEN` and the name is the contract.
#:
#: This is a guarantee a build tool makes rather than a shape somebody chose, which is
#: why it is a prefix list and not a heuristic. `NEXT_PUBLIC_SECRET_KEY` holding a real
#: server secret is a mistake the framework already made public; the place to catch that
#: is a review of what was put there, not a scanner calling it a leak.
PUBLIC_ENV_PREFIXES = (
    "next_public_",
    "nuxt_public_",
    "expo_public_",
    "public_",
    "vite_",
    "react_app_",
    "vue_app_",
    "gatsby_",
    "storybook_",
)

_SECRET_WORDS = frozenset(
    {"secret", "password", "passwd", "pwd", "pass", "token", "key", "credential", "auth"}
)

NAMING_WORDS = frozenset({"namespace", "prefix", "suffix", "label"})

NOT_A_SECRET = re.compile(
    rb"""(?x)
    ^(?:
        [A-Za-z_][\w.-]{0,120}:[A-Za-z_0-9/][\w.:/+-]{0,200}  # module:attribute, or a
        # secret-store reference, which is the same shape with hyphens in it. Grafana
        # writes `SLACK_BOT_TOKEN=community-slack-bot:token` in its workflows -- the
        # name of a vault entry and the field to read from it -- twenty-eight times,
        # and the hyphens were the only reason this alternative did not already cover
        # it.
        #
        # A DIGIT after the colon as well as a letter, and a path after it. TeamCity
        # spells a store reference `credentialsJSON:57e22787-e451-48ed-9fea-b9bf30775b36`
        # -- five findings in one repository, every one a pointer to a credential the
        # build server holds -- and Postfix spells a map
        # `smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd`, which is a file
        # path with a type in front of it.
      | projects/[\w-]{1,60}/secrets/[\w.-]{1,120}(?:/versions/[\w.-]{1,40})?
        # A Google Secret Manager resource name, which is the thing you pass to the API
        # INSTEAD of the secret. `SLACK_SIGNING_SECRET =
        # "projects/455826092000/secrets/SlackSigningSecret/versions/latest"`.
      | arn:aws:(?:secretsmanager|ssm|kms)[\w:/.-]{1,200}
        # The AWS equivalent, and the two other services a secret is fetched from.
      | https://[\w.-]{1,80}\.vault\.azure\.net/[\w./-]{1,120}
        # And Azure's, which is a URL rather than a name.
      | -{1,2}[A-Za-z][\w:+.-]{0,60}(?:=[^\s]{0,120})?
        # A COMMAND-LINE FLAG. `habitat` sets
        # `HAB_STUDIO_SECRET_NODE_OPTIONS="--dns-result-order=ipv4first"` in three
        # scripts: the variable's name carries `SECRET` because that is the prefix
        # Habitat uses to pass a variable into its build studio, and the value is
        # node's own option string.
      | (?:\.{0,2}/|~/|[A-Za-z]:\\)[\w.@+-]{1,60}(?:[/\\][\w.@+ -]{1,60}){0,16}/?
        # A FILESYSTEM PATH. A credential is not a path, and a name ending in `_FILE`,
        # `_PATH` or `_MAPS` holds one by construction.
      | [0-9]{1,4}(?:\.[0-9]{1,6}){1,4}
        [\w.+~:-]{0,40}
        # A VERSION. Debian writes `5.0.0+~cs13.3.24-1build1` in a package list, and a
        # version string has dots and digits where a credential has entropy.
      | [@$]{0,2}[A-Za-z_0-9][\w-]{0,60}
        (?:(?:\.\??|::|\?\.)[@$]{0,2}[A-Za-z_0-9][\w-]{0,60}){1,8}  # a dotted name or scope,
        # `.?` and `?.` as separators as well as `.` and `::`. Safe dereference is
        # spelled one way or the other in Bicep, C#, TypeScript, Kotlin and Swift,
        # and a reference that guards against a missing parent is still a reference:
        # `Azure/bicep-registry-modules` writes `radiusServerSecret:
        # virtualWanParameters.?p2sVpnParameters.?radiusServerSecret` in
        # `avm/ptn/network/virtual-wan/main.bicep`, which passes a parameter through
        # and holds nothing. The question mark was the only reason the dotted-name
        # branch below did not already cover it.
        # with the sigils and the separators other languages use. Ruby writes
        # `@next_token = @scanner.next_token` and
        # `token = Homebrew::EnvConfig.github_packages_token`, PHP writes `$this->x`,
        # and a segment may begin with a digit: Rails writes
        # `ACCESS_TOKEN_UPDATE_FREQUENCY = 24.hours.freeze`. Each of those is a
        # reference to other code, and each was a credential finding.
      | 0[xX]?[0-9a-fA-F]{16,128}                    # a hex digest or identifier,
      # with or without the `0x` a contract address and a git object id are written
      # with. `toeverything/AFFiNE` declares `quoteToken:
      # "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"`, which is an Ethereum address --
      # the same forty hex characters the mining rule refuses to match for being
      # indistinguishable from a GPG fingerprint.
      | [0-9a-fA-F]{16,128}
      | /?[A-Za-z_.-]{1,60}(?:/[A-Za-z_.-]{1,60}){1,12} # a path, absolute or not
      # A ROOTED path, which may contain digits. The branch above deliberately admits
      # none: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` is an AWS secret key with two
      # slashes in it, and allowing digits there would excuse every one of them.
      #
      # A leading `/` or `./` is what separates the two. Stirling-PDF declares its API
      # routes as constants -- `REMOVE_PASSWORD = "/api/v1/security/remove-password"` --
      # and `v1` was the only reason that did not read as a path. A key is not written
      # with a leading slash; a route is written with nothing else.
      | (?:~|\.{0,2})/[A-Za-z0-9_.~@%+-]{1,60}(?:/[A-Za-z0-9_.~@%+-]{1,60}){0,12}
        (?:[#?][A-Za-z0-9_.~@%+=&-]{0,80})?/?
      # A fragment or a query on the end of it. Ant Design's token table links to
      # `/docs/react/customize-theme#customize-design-token`, which is a place in a
      # document.
      # `~/` as well as `/` and `./`. Ray's cluster config writes
      # `ssh_private_key: ~/ray-bootstrap-key.pem`, which names a file on the machine
      # rather than holding a key.
      | (?=_{0,2}[A-Za-z]{8,80}[0-9]{0,2}$)(?=[^a-z]{0,84}[a-z])(?=[^A-Z]{0,84}[A-Z])
        _{0,2}[A-Za-z]{8,80}[0-9]{0,2}             # a mixed-case type or name
        # Up to two TRAILING digits, and nowhere else. A field in a remote API is
        # named that way when the vendor ran out of names: `home-assistant/core`'s
        # Growatt integration describes each sensor with
        # `api_key="eChargeToday1"`, where `api_key` is the name of the field in
        # Growatt's response and the value is that field's name. Generated key
        # material carries digits THROUGHOUT -- a base64 or base62 run of this
        # length with every digit at the end does not occur.
        # Leading underscores, because a private member is written that way in C++,
        # Python and TypeScript alike: `auto bypass = _recoveredFromDisk` in
        # `mongodb/mongo` was reported as a credential assignment between two member
        # variables.
      # Twelve stays. Raising it to twenty, to let `continuation_token` through, was
      # tried and the existing suite refused it within one run:
      # `glpat-AAAAAAAAAAAAAAAA` is sixteen repeated characters, so a padded GitLab
      # token became "a separated identifier". `test_a_separator_does_not_launder_key_
      # material` exists for exactly that, and it was right.
      #
      # The variable-reference case is handled in `PLACEHOLDER` instead, where the
      # mechanism for "the words themselves, used as their own name" already lived.
      | (?![A-Za-z0-9_-]{0,60}(?:[a-z]{12,64}|[A-Z]{12,64}|[0-9]{12,64}))
        _{0,2}[A-Za-z][A-Za-z0-9]{0,23}(?:[_-]{1,2}[A-Za-z0-9]{1,23}){1,14}_{0,2}
                                                     # a separated identifier.
        # `[_-]{1,2}` and fourteen segments rather than one and eight. Stable
        # Diffusion's webui assigns
        # `DontStealMyGamePlz__WINNERS_DONT_USE_DRUGS__DONT_COPY_THAT_FLOPPY` to
        # `checksum_token`, which is a joke in English with doubled underscores in it,
        # and neither the separator nor the length fitted. The negative lookahead above
        # is what keeps this from swallowing key material, and it is unchanged.
      # A hyphenated lowercase phrase, with no digit in it: a slug, a header value, a
      # passphrase made of words. Kubernetes names every controller
      # `serviceaccount-token-controller`, and Elasticsearch's license utilities declare
      # `DEFAULT_PASS_PHRASE = "elasticsearch-license"`. The long-run guard above refuses
      # both, because `elasticsearch` is thirteen lowercase characters -- it cannot tell
      # a word from a padded run.
      #
      # Generated key material is base64, base62 or hex: it has digits, or mixed case,
      # or both. A value that is lowercase letters and separators and nothing else is
      # something somebody typed.
      # `_{0,4}` at each end rather than two at the front. A marker string is written
      # with as many underscores as it takes to be unmistakable: V8's fuzzer declares
      # `SMOKE_TEST_END_TOKEN = '___foozzie___smoke_test_end___'`, which is three at
      # each end and a doubled separator in the middle.
      | _{0,4}[a-z]{3,24}(?:[_.-]{1,3}[a-z]{2,24}){1,8}_{0,4}
      # The same thing with DIGITS in it, and a slash allowed as a separator. A slug is
      # written `border-violet-500/30` (a Tailwind class in `toeverything/AFFiNE`),
      # `worldmonitor-free-map-panel-access-v1`, `pm-27278-v2-password-registration`
      # (a Bitwarden feature flag) and `gh-app_installation_id`.
      #
      # What keeps this away from key material is the absence of CAPITALS together with
      # the requirement for a separator. Generated base64, base62 and base58 all mix
      # case -- every value this suite keeps as a guard does -- and a lowercase-only run
      # with no separator in it is not matched here at all.
      | (?![0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)
        [a-z0-9]{1,16}(?:[_.\-/][a-z0-9]{1,16}){2,12}/?
      # A trailing separator, because a route is written with one: Superset declares
      # `GUEST_TOKEN: 'api/v1/security/guest_token/'`, which is four segments and a
      # slash.
      # NOT a lowercase UUID, which is five hyphenated segments of sixteen characters
      # or fewer and would otherwise read as a slug. A UUID is graded to MEDIUM and
      # reported -- see `CANONICAL_UUID` -- and dismissing it here would have undone
      # that one alternative later in the same pattern. An existing test caught it.
      #
      # Three segments at least, each of sixteen characters at most, and no capital
      # anywhere. Each bound is doing work. The segment cap is what keeps a token out:
      # `sec-01e0d4agf6pfvwdjwxp61n3fvg` is two segments and the second is twenty-six
      # characters, so it is not matched and stays reported. Three segments is what
      # makes it a PHRASE rather than a prefixed value -- a slug is several words.
      # And the all-capitals form of the same thing: a header name, an environment
      # variable, a constant. ASP.NET Core declares
      # `MSAspNetCoreWinAuthToken = "MS-ASPNETCORE-WINAUTHTOKEN"`, where the guard
      # objects to `WINAUTHTOKEN` being twelve capitals.
      #
      # `glpat-AAAAAAAAAAAAAAAA` is unaffected by both and stays reported: it mixes case,
      # which neither of these admits.
      | _{0,4}[A-Z]{2,24}(?:[_.-][A-Z0-9]{2,24}){1,10}_{0,4}
      # A SENTINEL: one run of capitals wrapped in underscores, which is what a
      # substitution marker looks like. `PROGRAMDATA_TOKEN = '__PROGRAMDATA__'` in
      # `flow-launcher` is a placeholder an installer replaces with a path, and
      # `publicKeyToken="@_EM_PUBLIC_KEY_TOKEN@"` is the same idea wearing `@`.
      | _{1,4}[A-Z][A-Z0-9]{1,40}_{1,4}
      | [a-z][a-z0-9+.-]{1,15}://[^@\s]{1,200}       # a URL carrying no userinfo
      | [A-Za-z0-9][A-Za-z0-9._-]{0,80}@[A-Za-z0-9-]{1,60}
        (?:\.[A-Za-z0-9-]{1,60}){1,6}                 # a name qualified by a domain
      | (?:meth|class|func|ref|attr|mod|data|exc|obj|doc|term|py:[a-z]{1,10})
        :[`~][^\s]{1,110}                           # a Sphinx cross-reference
      # An EXPRESSION rather than a literal. Swift and Kotlin mark optionality,
      # force-unwrapping, inout arguments and member shorthand with characters no
      # generated credential contains, and every one of these is a declaration or
      # a reference that assigns no value at all:
      #
      #     public let credential: CmxIrohAdmissionCredential?
      #     private var socketPasswordObserver: NSObjectProtocol?
      #     let refreshToken = originalRefreshToken!
      #     let pendingToken = pendingWriter?.provisionalToken.id
      #     passwordAuthorization: &passwordAuthorization
      #     pendingSizingPassIntent = .inputChange
      #
      # `manaflow-ai/cmux` is a Swift codebase and supplied forty-three of those
      # against one real key. A marker is REQUIRED: a bare identifier is not
      # covered here, because `phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z` is
      # also a bare identifier and is a PostHog key.
      # `?` and `#` join the set. An Android layout writes
      # `app:passwordToggleTint="?colorControlNormal"`, where `?` is the theme-attribute
      # reference, and Meson writes `search_token = '#mesondefine'`.
      | [&*!~@+?#-]{1,2}\.?[$A-Za-z_][\w.?!@/-]{0,120}  # an operator-led expression,
      # `/` and `@` inside it as well as in front. A YAML tag is `!!python/tuple`, and a
      # build substitution marker is `@_EM_PUBLIC_KEY_TOKEN@`.
      # `++` and `--` because a counter is written `const token = ++tokenRef.current`
      # -- four of those in one repository -- and a CSS custom property is written
      # `inputTokenAccent: "--series-input-token"`, which is the NAME of a variable.
      # including Ruby's `@name` and `@@name`, which are a reference with no dot in it
      # A YAML alias is the commonest of those and earns its own note: `password:
      # *keyFileData` refers to an anchor defined elsewhere in the document, and
      # `mongodb/mongo` has fifteen across its resmoke suite definitions. `<<` is the
      # merge key that usually accompanies them.
      # A literal with a shell variable on the END of it. `kSecret =
      # "AWS4$AWS_SECRET_ACCESS_KEY"` is the SigV4 key-derivation prefix: the secret
      # arrives from the environment and the literal is the four characters in front.
      #
      # ALL-CAPS after the `$`, which is what distinguishes it from a PayPal access
      # token -- `access_token$production$<id>$<secret>` has lowercase and hex segments,
      # and `PLACEHOLDER`'s word-boundary guard exists so that pattern keeps firing.
      | [^\n$]{0,40}\$\{?[A-Z][A-Z0-9_]{5,60}\}?
      | <<[ \t]*\*?[A-Za-z_][\w-]{0,120}            # a YAML merge key
      # A value carrying a backslash. Generated key material is base64, base62 or
      # hex, and none of those alphabets contains one -- so a backslash means an
      # escape sequence, a Windows path or a regular expression. Boost's graphviz
      # parser assigns a lexer pattern to `basic_id_token`, and every parser in
      # existence has a few.
      | [^\n]{0,60}\\[^\n]{0,120}                   # anything carrying a backslash
      # Or a parenthesis. Kafka builds a `toString()` out of
      # `"DelegationTokenImage(" + String.join(...)`, which folds to a value that opens
      # a call. base64, base62 and hex have no parentheses in their alphabets, so one in
      # a value means code or a formatted string.
      | [^\n]{0,60}[()\[\]][^\n]{0,120}
      # A coordinate: `group:artifact:version`, `host:port:db`. The single-colon form is
      # above; `gkd-kit/gkd` declares
      # `lsposed-hiddenapibypass = "org.lsposed.hiddenapibypass:hiddenapibypass:6.1"` in
      # its Gradle version catalogue, which is three segments and a dependency.
      | [A-Za-z_][\w.-]{0,80}(?::[A-Za-z0-9_.+-]{1,80}){2,5}
      # A value that ENDS in a colon. No credential format does: base64 pads with
      # `=`, base62 and hex have no punctuation at all, and every provider prefix
      # puts its separator in the middle. A trailing colon means the value is the
      # NAME of a field, a label or a prefix -- `gorhill/uBlock`'s MV3 rule editor
      # carries an autocomplete table of nineteen entries, every one of them
      # `{ token: 'urlFilter:' }`, and the key is called `token` because that is
      # what a parser calls the thing it is completing.
      | [-$@.]{0,2}[A-Za-z_][\w.+-]{0,120}(?::[A-Za-z0-9_.+-]{0,120}){0,5}:
      # A COMMA-SEPARATED list, which is a list. No credential format contains a
      # comma: base64's alphabet has none, base62 and hex have no punctuation at all,
      # and a connection string separates with semicolons. `cherry-studio` declares
      # `defaultByPassRules = 'localhost,127.0.0.1,::1'` -- a proxy bypass list whose
      # name contains "pass" because it contains "byPass".
      | [^\n,]{0,16}(?:,[^\n,]{0,16}){1,16}
      # Sixteen items of sixteen characters rather than twelve of forty, which is the
      # same budget spent where the lists actually are: js-beautify declares its void
      # elements as one comma-separated string of fifteen tag names, and a list is
      # longer than it is wide.
      #
      # Sixteen on BOTH bounds, not a product under a thousand. The pattern validator
      # has two separate caps and this alternative met the wrong one first: a repeat
      # above `LARGE_REPEAT` counts as unbounded for the `(a+)+` check, so `{0,24}`
      # inside `{1,40}` read as an unbounded quantifier enclosing another even though
      # the product was 960.
      # A value carrying a NON-ASCII character. Every credential format there is --
      # base64, base64url, base62, base32, hex -- is ASCII by specification, so a byte
      # above 0x7f means human language. `localsend` ships Inno Setup language files
      # named after the language, and `Icelandic.isl` assigns the Icelandic word for
      # "password" to `WizardPassword`; Keycloak has the same thing in forty-odd
      # `messages_<locale>.properties`, and `dbeaver` in twelve.
      #
      # The words are described rather than written: this pattern is a bytes literal,
      # which cannot hold a non-ASCII character, and a comment beside a rule in a file
      # this tool scans is the wrong place for a faithful copy either way.
      #
      # The trade, stated rather than hidden: a committed password containing an
      # accented letter is missed by THIS rule. Its whole evidence is a
      # credential-shaped name beside an entropy measure, which is exactly the
      # evidence prose defeats -- and a provider-prefixed value is matched by that
      # provider's pattern, which consults none of this.
      | [^\n]{0,80}[\x80-\xff][^\n]{0,120}
      # A Ruby symbol, which is a name with a colon in front of it. RuboCop declares
      # `COMPLEX_STRING_BEGIN_TOKEN = :tSTRING_BEG`, naming one of the parser's token
      # types, and every cop that matches on token types has a few.
      | :[A-Za-z_]\w{0,120}[?!]?
      # A ROUTE TEMPLATE, which names its parameters with a colon. `twentyhq/twenty`
      # declares `ApiKeyDetail: 'api-webhooks/apis/:apiKeyId'`, and every Express and
      # React Router path in existence is written this way.
      | [A-Za-z0-9_.~/-]{0,80}/:[A-Za-z_]\w{0,40}[A-Za-z0-9_.~/:-]{0,80}
      # A TYPE or SCHEMA reference: a mixed-case identifier ending in one of the words
      # a type is named with. `stablyai/orca` declares
      # `resumeToken: Base64Url32ByteSchema`, a Zod schema, and the mixed-case
      # alternative above cannot admit it because the digits are in the middle.
      # A PREDICATE reference: a camelCase name opening with a word that asks a
      # question. `cline` writes `const apiKey = usesExplicitSigV4Auth`, which is a
      # boolean the line above computed, and the mixed-case alternative cannot admit it
      # because the digit sits in the middle.
      | (?-i:(?:is|has|have|use|uses|used|should|can|could|will|was|were|did|does|must
        |allow|allows|enable|enabled|disable|disabled|need|needs|require|requires|skip
        |include|includes|exclude|supports|support|prefer|prefers)
        [A-Z][a-z]{2,20}[A-Za-z0-9]{0,40})
      # Google's C++ constant convention: a `k` and then PascalCase WORDS. gRPC writes
      # `oauth2AccessToken:kDefaultOauth2AccessToken`, naming a constant defined above.
      #
      # Each hump has to carry three or more consecutive lowercase letters, and there
      # have to be at least two humps. `k[A-Z][A-Za-z0-9]{2,60}` was the first draft and
      # it would have excused roughly one random base62 secret in a hundred and fifty:
      # any value beginning with a `k` and a capital. Real words are what distinguishes
      # a constant's name from a generated run, so real words are what it asks for.
      | (?-i:k(?:[A-Z][a-z]{2,20}[0-9]{0,3}){2,8})
      | [A-Za-z][A-Za-z0-9]{0,60}
        (?:Schema|Type|Config|Options|Props|Model|Factory|Builder|Service|Provider
          |Handler|Manager|Client|Request|Response|Error|Exception|Enum|Interface
          |Dto|Entity|Context|Store|Reducer|Selector|Hook|Guard|Filter|Pipe)
      # A PARAMETER STRING: two or more `=` signs with nothing long between them.
      # Jellyfin builds an ffmpeg filter as `vpp_rkrga=format=bgra:afbc=1`, and base64
      # carries at most two `=` and only at the end.
      #
      # The length cap is what keeps an Azure connection string out:
      # `AccountKey=` is followed by eighty-eight characters of base64, and every run
      # here is at most twenty-four.
      | [^\n=]{1,24}=[^\n=]{1,24}=[^\n=]{0,24}(?:=[^\n=]{0,24}){0,4}
      # Semicolon-separated `key=value` pairs whose values are lowercase words. Symfony
      # declares console styles that way -- `TOKEN_STRING: "fg=yellow;options=bold"` --
      # and a terminal style is not a credential.
      #
      # Lowercase values only, which is what keeps an Azure connection string out:
      # `AccountKey=` is mixed case and its value is base64 with `+`, `/` and `=` in it.
      | [a-z][a-z0-9-]{0,20}=[a-z0-9-]{1,24}(?:;[a-z][a-z0-9-]{0,20}=[a-z0-9-]{1,24}){0,10}
      | \.[A-Za-z_][\w.?!-]{0,120}                  # member shorthand
      | [$A-Za-z_][\w$-]{0,60}
        (?:[?!&]{0,2}\.[$A-Za-z_]?[\w$-]{0,60}){1,8}[?!]{0,2}  # a chain, however it navigates
        # Two trailing marks, not one. Kotlin force-unwraps with `!!`, and
        # `DrKLO/Telegram` writes `curAccessToken = tokenResponse.accessToken!!` --
        # a chain AND a force-unwrap, which neither this branch nor the bare
        # force-unwrap branch below could match on its own.
        # `&.` is Ruby's safe navigation and is a separator like any other:
        # `pass = proxy_uri&.password` reads a value off another object and assigns no
        # literal at all.
        # `$` inside a segment as well as at the front. A TextMate grammar writes
        # `{ token: 'keyword.tag-$0' }`, where `$0` is the capture group the scope is
        # built from, and every syntax definition in a editor is full of them.
      | [$A-Za-z_][\w-]{0,60}[?!]{1,2}              # a name declared optional, or
      # force-unwrapped twice: Kotlin writes `webPoTokenStreamingPot =
      # webPoTokenGenerator!!`, which is a reference and assigns nothing.
      # A command in backticks, which is a shell substitution: `ente` writes
      # `museum_jwt_secret=`gen_jwt_secret`` in its setup script, and the value at
      # runtime is whatever that function prints.
      | ["']?[ \t]*\+[ \t]*[A-Za-z_$][\w$.]{0,60}[\s\S]{0,200}
        # A CONCATENATION. PrestaShop builds an ajax body as
        # `data: "token="+employee_token+'&ajax=1&action=...'`, where the credential-shaped
        # name is a query parameter in a string and the value is the rest of the
        # expression. A `+` straight after the opening quote is the author joining this
        # fragment to a variable, which is where the real value lives.
      | `[^`\n]{1,120}`
      # A regular expression literal. `NO_NEED_TOKEN_REG =
      # /text|hard_line_break|soft_line_break/` in `marktext` is a pattern, and the
      # alternation inside it is what makes it one.
      | /[^/\n]{1,120}/[gimsuyxd]{0,6}
    )$
    """
)
"""Values with a credential-shaped *name* that are plainly not credentials.

Matched by shape, not by path. `secrets = "cordon_scanner.detect.secrets.secrets:SecretDetector"`
in this project's own `pyproject.toml` has a name containing `secret`, a quoted
value of 36 characters, high entropy and three character classes -- everything
the generic assignment rule looks for, and it is an entry-point declaration.

PascalCase is included with camelCase because C# declares inheritance with a
colon -- `class QueryJsonSelectToken : TestFixtureBase` reads as an assignment
to the pattern below, and the name contains "Token" because the API is called
SelectToken.

That alternative used to be written as capitalised words: an initial letter
then runs of `[A-Z][a-z]+`. It could not express an acronym or a trailing
initialism, so `passwd: HTTPPasswordMgrWithDefaultRealm` and `session_token:
AuthenticationBackendXY` -- a type annotation in each case, assigning nothing
at all -- were reported as credentials, and a typed Python or TypeScript
codebase produces those by the hundred.

What it asks now is only that the value is eight or more letters with no digit
and no symbol in it, in mixed case. The trade is stated rather than hidden: an
all-letter passphrase assigned to a credential-shaped name is missed by *this*
rule. Generated key material is base64, base62 or hex and effectively always
carries a digit; a run of letters that long with none is a name somebody wrote.
A passphrase with a provider prefix is still matched by that provider's
pattern, which does not consult this list at all.

The hex alternative reaches down to sixteen characters rather than
thirty-two. `publicKeyToken = cc7b13ffcd2ddd51` in a .NET `App.config` is an
assembly identifier and is public by definition; hex is low entropy over its own
alphabet, so a short hex run is an identifier or a digest far more often than
it is key material. It accepts either case, because `2E75CB6A...` and
`2e75cb6a...` are the same digest and OpenSSL's own test vectors are written in
the upper one.

The separated-identifier alternative replaced the snake_case and
SCREAMING_CASE ones it subsumes. Those two required a single case throughout,
and the values that reach here are mixed: OpenSSL's EVP test data assigns
`ALICE_cf_brainpoolP160r1` to a key called `PrivateKey`, naming a key defined
elsewhere in the same file, and seven hundred and twenty-eight of those were
reported as leaked credentials in every project that vendors OpenSSL.

What makes it an identifier rather than key material is the word separators
together with what sits between them: generated secrets are one unbroken run,
so a value with no `_` or `-` is never matched here, and a value whose
separators merely punctuate a long run of one character class is not matched
either. That second half is the lookahead. Without it `"glpat-" +
"AAAAAAAAAAAAAAAA"` reads as a two-segment identifier, which is precisely the
shape of a provider token this tool has no dedicated pattern for.

A Sphinx cross-reference is documentation, not an assignment. Prose reaches
this rule because the name group matches inside a word -- "bypasses" ends in
"pass" plus "es" -- and a role such as ``:meth:`Registry.new``` that follows it
has a colon and no whitespace, which is the shape the unquoted branch looks
for.

A URL is excluded only when it carries no userinfo. `token_url =
"https://oauth2.googleapis.com/token"` is an endpoint, not a credential, and
naming an OAuth endpoint after the thing it issues is the convention rather
than the exception. A URL that does embed a credential is matched by the
connection-string rule, which is where that finding belongs.

camelCase allows no digits, and that restriction is load-bearing rather than
tidy. Written as `[a-z]+(?:[A-Z][a-z0-9]*)+` it also matches
`kR9mT2nQ8vL4xW7yZ3bC6dF1` -- base62 key material alternates case and includes
digits, so a permissive camelCase rule excludes exactly the values this
detector exists to find. Requiring letters after each capital separates an
identifier from a token.

camelCase is covered for the same reason as the other identifier shapes, and
found the same way: `firstTokenOfCallee = calleeParenCount` in ESLint's indent
rule is one variable assigned another, and the name contains "Token" because a
linter's tokens are lexical. The path alternative accepts a leading slash --
`credentials_file = /random/file/which/does/not/exist.yml` in Prometheus's test
data is a filename, and requiring a relative path missed every absolute one.

Hyphens are allowed inside a dotted name because scoped identifiers use them:
`token = "entity.other.attribute-name"` in a syntax theme is a TextMate scope,
and a hyphen-free pattern reported a hundred and forty of them across three
real projects.

The two identifier alternatives cover assignment between names rather than to a
literal. `token = TOKEN_BLOCK_BEGIN` in a lexer is one constant being given
another, and the unquoted branch of the assignment pattern -- which exists to
catch `PASSWORD=hunter2` in a dotenv file -- reads the right-hand side as a
value. Three of five widely used packages reported a credential for this shape.

The snake_case alternative covers the shape every enum, constant table and
string-union has: `SECRET_EXPOSURE = "secret_exposure"`, `AUTH_TOKEN_HEADER =
"authorization"`. Generated key material is never all-lowercase words joined by
underscores -- it carries digits and mixed case, which is where its entropy
comes from -- so requiring that shape to be *absent* costs no detection and
removes a noise class that appears in almost every codebase. This project's own
taxonomy module was the first thing it flagged.

Kept narrow and anchored: each alternative must match the whole value, so a
credential that merely contains a dot is unaffected."""


__all__ = [
    "CONFIGURATION_SUFFIXES",
    "LOCATION_WORDS",
    "MAX_RESTATE_RUNS",
    "MIN_RESTATED_NAME",
    "NAMING_WORDS",
    "NOT_A_SECRET",
    "NOT_REAL_WORDS",
    "PUBLIC_ENV_PREFIXES",
    "SecretNames",
]
