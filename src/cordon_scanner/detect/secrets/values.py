"""Whether a matched value is really a credential: its prefix, its randomness, whether it is a
placeholder, published on purpose (a public key, a client id), or one of the private keys and
credentials published as examples everywhere.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.secrets.names import NOT_A_SECRET, SecretNames

if TYPE_CHECKING:
    from collections.abc import Iterator


PASSWORD_HASH = re.compile(
    rb"^(?:\$(?:2[abxy]?|argon2(?:id|i|d)?|pbkdf2(?:-sha\d{1,3})?|scrypt|bcrypt|"
    rb"[156]|sha1|md5|y|7)\$|\{(?:SSHA|SHA|MD5|CRYPT|PBKDF2)\}|pbkdf2_sha\d{1,3}\$)"
)
"""A stored password hash, which is not a password.

The whole point of the format is that it can sit in a database, in a fixture and in a
repository: it is one-way, salted, and deliberately slow to attack. `$2a$`, `$2y$` and
`$2b$` are bcrypt, `$argon2id$` and `$pbkdf2-sha256$` name themselves, `$6$` is
sha512crypt, and `{SSHA}` is LDAP's. Django writes `pbkdf2_sha256$...`.

Two of seventy sampled assignment findings were one -- a bcrypt hash assigned to
`$password` in one PHP seed file and to `$passwordHash` in another -- and every seed
script, test fixture and `/etc/shadow` example in existence carries them. Recognised by
the prefix rather than by entropy, because a hash has exactly the entropy of the
credential it replaced, which is the property that makes entropy useless here.
"""


class SecretValues:
    """Whether a matched value is really a credential."""

    @staticmethod
    def is_password_hash(value: bytes) -> bool:
        """Whether this value is a stored hash rather than the credential it came from."""
        return PASSWORD_HASH.match(value) is not None

    @staticmethod
    def looks_sequential(value: bytes) -> bool:
        """Whether this value is mostly a run of consecutive characters.

        EVERY run counts towards the share, not just the longest one, and "mostly" is why.
        The alphabet and the digits are two runs, because `9` and `a` are not adjacent
        codepoints -- so `ci-deploy-check-key-0123456789abcdefghijklmnopqrstuvwxyz-throwaway`,
        which is this project's own CI `SECRET_KEY` and is as plainly not a credential as a
        value gets, scored 26 against a threshold of 26.4 and was reported at HIGH. Summed,
        it is 36 of 66 characters.

        Safe because of what it asks of real key material: a generated credential has no
        run of six consecutive codepoints at all, so its total is zero however many runs are
        added up. Measured against every value this suite keeps as a guard -- a GitLab PAT,
        an AWS key, a PostHog key, the PikPak client secret -- the longest run is two.
        """
        total = 0
        longest = run = 1
        for previous, current in itertools.pairwise(value):
            if current == previous + 1:
                run += 1
            else:
                if run >= SEQUENTIAL_RUN:
                    total += run
                run = 1
            longest = max(longest, run)
        if run >= SEQUENTIAL_RUN:
            total += run
        return longest >= SEQUENTIAL_RUN and total >= SEQUENTIAL_SHARE * len(value)

    @staticmethod
    def is_firebase_web_config(raw: bytes, start: int, end: int) -> bool:
        """Whether this key sits inside Firebase's published web configuration object."""
        window = raw[max(0, start - FIREBASE_CONFIG_WINDOW) : end + FIREBASE_CONFIG_WINDOW]
        return FIREBASE_WEB_CONFIG.search(window) is not None

    @staticmethod
    def is_public_by_design(value: bytes) -> bool:
        """Whether this value is a credential that is meant to be in the repository."""
        return value.startswith(PUBLIC_BY_DESIGN_PREFIXES)

    @staticmethod
    def decodes_to_prose(matched: bytes) -> bool:
        """Whether the body of this credential is base64 for an English sentence.

        `Significant-Gravitas/AutoGPT` ships Supabase's GoTrue configuration, and one
        commented line carries a Stripe-shaped webhook secret whose body decodes to a
        sentence announcing itself an example of a shorter base64 string. Upstream wrote
        it to illustrate the field's format.

        The claim is about randomness, not about the wording. A real secret is random
        bytes, and random bytes are printable ASCII with probability around a third per
        byte -- so a body of any length that decodes to words, spaces and punctuation
        throughout is not random, whatever the words say.

        The prefix is stripped first: a provider prefix is ASCII by construction and
        would otherwise be what the test reads.
        """
        body = matched.rsplit(b"_", 1)[-1].rsplit(b"-", 1)[-1]
        if len(body) < MIN_PROSE_DECODE:
            return False
        padded = body + b"=" * (-len(body) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            return False
        if len(decoded) < MIN_PROSE_DECODE:
            return False
        printable = sum(1 for byte in decoded if 0x20 <= byte < 0x7F)
        if printable != len(decoded):
            return False
        return PROSE_RUN.search(decoded) is not None

    @staticmethod
    def is_lone_access_key_id(raw: bytes, start: int, end: int, rule_id: str) -> bool:
        """Whether this AWS access key id appears without the secret half.

        An access key id is the public name of a credential, not the credential.
        `rust-lang/rust` commits two of them in `src/ci/github-actions/jobs.yml` with a
        comment above explaining the scheme: the ids are in the repository so a key can
        be rotated on one branch while another keeps the old one, and the secrets are in
        the CI provider's store. Knowing an id buys an attacker nothing.

        So this grades rather than dismisses. An id still identifies an account and is
        worth seeing; it is not the emergency that a usable key pair is, and reporting it
        at the same severity is what makes a reader stop reading.

        The secret half is forty characters of base64 alphabet, which is distinctive
        enough to find and common enough that a coincidence keeps the finding at its full
        severity -- the safe direction. `yt-dlp` hardcodes a genuine pair a line apart
        and is unaffected.
        """
        if rule_id not in AWS_KEY_ID_RULES:
            return False
        window = raw[max(0, start - AWS_PAIR_WINDOW) : end + AWS_PAIR_WINDOW]
        if AWS_SECRET_SHAPE.search(window) is not None:
            return False
        # The secret half labelled as one, whatever its alphabet: `aws_secret_access_key = ...` in
        # a credentials file, an `.env` or a config beside the id is the pair, and a random value
        # that strays outside base64 is still the value someone will try. A reference
        # (`${AWS_SECRET_ACCESS_KEY}`, `<secret>`, an empty value) is not a value.
        return AWS_LABELLED_SECRET.search(window) is None

    @staticmethod
    def reads_as_words(value: bytes) -> bool:
        """Whether this value is identifiers concatenated rather than a generated run.

        Measured against the corpus's own assignment findings: it dismisses
        `echarge1Today` and eleven siblings -- `api_key="bdc1DischargePower"` in an energy
        monitor, where `api_key` is the name of a data point and the value is the metric --
        along with `ss2022Method`, `SsoEmail2faSessionToken`, `Pkcs12SafeBag` (which is a
        C# base class, not a value at all) and `abc123def456`.

        Against the true positives in the same sample it dismisses none. Every one of
        `bR4SJwOkvnG5WvVJ`, `dbw2OtmVEeuUvIptb1Coyg`, `Og9Vr1L8Ee6bh0olFxFDRg`,
        `k0VMxyIJF9S35f3x2uaw5IWAl6Y536O7` and twenty more fails on a letter run that is
        one or two characters or three capitals -- which is what a generated value is made
        of and what a word is not.

        Digits and separators divide words and are otherwise ignored: the question is only
        ever asked of the letters.
        """
        if WORD_VALUE_CHARS.fullmatch(value) is None:
            return False
        words: list[bytes] = []
        for run in re.findall(rb"[A-Za-z]+", value):
            # Split each letter run at its capitals, so `SsoEmail` is two words and not one
            # unpronounceable eight-letter one.
            words.extend(part for part in re.findall(rb"[A-Z]?[a-z]*", run) if part)
        if len(words) < MIN_WORD_SEGMENTS:
            return False
        return all(WORD_SEGMENT.fullmatch(word) for word in words)

    @staticmethod
    def is_url_parameter(raw: bytes, start: int) -> bool:
        """Whether this match is a query parameter of a URL rather than an assignment.

        `iptv-org/iptv` lists five streams in `streams/my.m3u` whose playlist URLs carry
        `?token=` and `&auth_key=`, each a signed link with an epoch in it;
        `Asabeneh/30-Days-Of-Python`'s dataset holds a Vimeo CDN link of the same shape.

        A token in a URL is a signed link: it was issued to be handed to somebody, it
        authorises one object rather than an account, and it expires. It is graded rather
        than dropped, because a URL is also where a real API key gets pasted when somebody
        is in a hurry, and a graded finding still says where to look.

        Searched over the 2KB before the match so a long playlist line is covered, and the
        URL has to actually contain the match: a URL on the line above does not count.
        """
        window_start = max(0, start - 2000)
        for found in URL_RUN.finditer(raw, window_start, start + 1):
            if found.start() <= start < found.end():
                return b"?" in raw[found.start() : start] or b"&" in raw[found.start() : start]
        return False

    @staticmethod
    def decoded_is_not_a_secret(value: bytes) -> bool:
        """Whether the base64 this value holds decodes to something already dismissed.

        The predicates in this file read a value. A value that is base64 hides the thing they
        would read, and the corpus writes both halves down: `Cloudron` assigns a base64 blob
        to a key called `password` and puts the plaintext in a comment on the same line, and
        `harvester` assigns one that decodes to the words "encrypted password" with a hyphen
        between them.

        Both are described rather than quoted, because this file is scanned by the tool it
        configures and a faithful copy of a credential-shaped assignment is a true positive.
        The self-scan test caught the first draft of this docstring within one run, which is
        the same lesson the comment about an Icelandic word for "password" records further
        up.

        So decode once and ask the same questions of the result. Nothing new is claimed --
        whatever `PLACEHOLDER`, `NOT_A_SECRET` and `reads_as_words` already refuse, they
        refuse through a base64 layer too.
        """
        text = SecretValues._decoded_text(value)
        if not text:
            return False
        decoded = text.encode("ascii")
        return (
            PLACEHOLDER.search(decoded) is not None
            or NOT_A_SECRET.match(decoded) is not None
            or SecretValues.reads_as_words(decoded)
        )

    @staticmethod
    def _decoded_text(value: bytes) -> str:
        """The printable ASCII this value's base64 holds, or an empty string.

        Shared by `decoded_is_not_a_secret` and the name comparison, which ask different
        questions of the same bytes.
        """
        if len(value) < MIN_BASE64_RETEST or not set(value) <= B64_ALPHABET:
            return ""
        try:
            decoded = base64.b64decode(value + b"=" * (-len(value) % 4), validate=True)
        except (ValueError, binascii.Error):
            return ""
        decoded = decoded.strip()
        if len(decoded) < 4 or any(byte < 0x20 or byte >= 0x7F for byte in decoded):
            return ""
        return decoded.decode("ascii")

    @staticmethod
    def is_inside_example_literal(raw: bytes, start: int, language: str | None) -> bool:
        """Whether this match sits in a Go raw string declared as example or help text.

        Go only. A raw string is delimited by backticks and cannot contain one, so parity
        answers whether an offset is inside one: an odd number of backticks before it means
        the last of them opened the string the offset sits in. No other language in the
        corpus spells a multi-line literal this way, and the ones that use a triple quote or
        a hash-delimited raw string need a parser rather than a count.
        """
        if language != "go":
            return False
        before = raw[:start]
        if before.count(b"`") % 2 == 0:
            return False
        opening = before.rfind(b"`")
        head = before[max(0, opening - EXAMPLE_LITERAL_WINDOW) : opening]
        return EXAMPLE_LITERAL_INTRO.search(head) is not None

    @staticmethod
    def is_illustrated_by_its_key(raw: bytes, start: int) -> bool:
        """Whether the text just before this match names it as an example."""
        return PLACEHOLDER_KEY.search(raw, max(0, start - 120), start) is not None

    @staticmethod
    def is_presigned_credential(raw: bytes, start: int) -> bool:
        """Whether this match is the key id inside a presigned URL's query string."""
        return PRESIGNED_CREDENTIAL.search(raw, max(0, start - 60), start) is not None

    @staticmethod
    def is_client_configuration(path: str, rule_id: str) -> bool:
        """Whether this rule is reporting a key the vendor generated to be shipped."""
        return rule_id in CLIENT_CONFIG_RULES and SourcePaths._names(path, CLIENT_CONFIG_FILES)

    @staticmethod
    def holds_published_key(raw: bytes, start: int) -> bool:
        """Whether the key armour at `start` introduces a key its vendor publishes."""
        window = raw[start : start + PUBLISHED_KEY_WINDOW]
        return any(known in window for known in PUBLISHED_PRIVATE_KEY_BODIES)

    @staticmethod
    def key_name_is_illustrative(raw: bytes, start: int) -> bool:
        """Whether the name declaring this key says it is a sample.

        `PLACEHOLDER_KEY` asks the same question of the provider patterns and asks it of the
        SEPARATOR: a key word, then `=` or `:`, then the value. That shape does not reach a
        language where the name carries the word in the middle of itself. `vapor` declares

            static var sampleServerPrivateKeyPEM: String

        and then a full-length RSA key -- real key material, generated to be shipped in a
        development target, and `holds_illustrative_key` cannot help because the body is a
        genuine key of genuine length.

        So the name is read the way every other name in this file is read, with
        `names_placeholder`: split on separators and camel-case humps, and ask whether any
        word is one the author uses to mean "not real". `sample` is one; `test` deliberately
        is not, for the reason `NOT_REAL_WORDS` records.
        """
        head = raw[max(0, start - DECLARED_NAME_WINDOW) : start].rstrip()
        lines = head.rsplit(b"\n", 2)
        declaration = lines[-1]
        if len(lines) > 1 and DECLARED_NAME.search(declaration) is None:
            # The declaration line offers no name at all, because the value sits on
            # its own line and the key ended the line above it. Appwrite's function
            # templates write
            #
            #     'placeholder' =>
            #         'mongodb+srv://appwrite:<a password>@cluster0.<...>.mongodb.net/',
            #
            # where the key is the literal word `placeholder` and the value is the
            # example the form field shows a user. That was reported at high severity.
            #
            # Exactly one line back, and only when this line has no name to read at
            # all. Looking further is the over-reach this window was narrowed to fix:
            # four identifiers back reached `let sampleOther = 1` on an unrelated
            # statement and excused the declaration underneath it.
            previous = lines[-2].rstrip()
            if WRAPPED_ASSIGNMENT.search(previous):
                declaration = previous
        return any(
            SecretNames.names_placeholder(name.decode("utf-8", errors="replace"))
            for name in DECLARED_NAME.findall(declaration)
        )

    @staticmethod
    def holds_illustrative_key(raw: bytes, start: int) -> bool:
        """Whether the armour at `start` introduces something too small or too marked to be
        a key.

        Two tests over one window. The body may be too short to encode a key of any
        algorithm -- see `MIN_PEM_BODY` -- or it may carry a placeholder marker that the
        44-byte match cannot see: `n8n`'s Google credential documents the field as
        `'-----BEGIN PRIVATE KEY-----\nXIYEvQIBADANBg<...>0IhA7TMoGYPQc=\n-----END ...'`,
        where the elision in the middle is the whole point.
        """
        window = raw[start : start + 8000]
        match = PEM_BODY.match(window)
        if match is None:
            return False
        body = match.group(1)
        if PLACEHOLDER.search(body):
            return True
        return sum(1 for byte in body if byte in B64_ALPHABET) < MIN_PEM_BODY

    @staticmethod
    def is_published_credential(matched: bytes) -> bool:
        """Whether the matched text contains a credential its vendor publishes.

        A substring test rather than equality, because the match usually carries the
        field that introduced the value -- `AccountKey=` and then the key -- and the
        published fixture is the value, not the assignment around it.
        """
        return any(known in matched for known in PUBLISHED_CREDENTIALS)

    @staticmethod
    def fold_concatenations(raw: bytes) -> Iterator[tuple[int, int, bytes]]:
        """Adjacent string literals joined into the value they build.

        The fallback for everything the AST tier does not cover: JavaScript, PHP,
        Go, and any Python that will not parse. It understands only that literals
        separated by a joiner form one value, which is the form a split credential
        actually takes and is far short of understanding the language.

        Single literals are not returned. Those are contiguous bytes that the
        ordinary patterns have already matched.
        """
        run: list[bytes] = []
        start = 0
        end = 0

        for match in _LITERAL.finditer(raw):
            piece = match.group(1) if match.group(1) is not None else match.group(2)
            if piece is None:
                continue

            if run and _JOINER.match(raw[end : match.start()]):
                run.append(piece)
                end = match.end()
                continue

            if len(run) > 1:
                yield start, end, b"".join(run)

            run = [piece]
            start, end = match.start(), match.end()

        if len(run) > 1:
            yield start, end, b"".join(run)


SEQUENTIAL_RUN = 6
"""How many consecutive ascending characters make a value a sequence.

Entropy cannot tell `abcdefghijklmnopqrstuvwxyz0123456789` from a random string of
the same length: as a multiset of characters it is maximally diverse, which is what
Shannon entropy measures. What it is not is unpredictable.

Grafana assigns that exact value to `TOKEN_ALPHABET` in a branch-name generator --
it is the alphabet the generator draws FROM -- and Celery's documentation writes an
AWS access key as the alphabet in order.

Six rather than eight, and `123456abcdef` is why: Fastlane documents
`sonar_token: "123456abcdef"`, which is two runs of six and nothing else. Adding
`123456` to the placeholder vocabulary was tried first and five provider patterns
refused it within one run -- a Telegram bot token opens with a numeric chat id and a
Discord webhook url is two of them, so their own samples were being dismissed. A
SEQUENCE is the right mechanism for this value and a substring was not.

Six is still long enough that nothing generated contains such a run by chance, and the
`SEQUENTIAL_SHARE` floor below is what carries the weight: forty per cent of the value
has to sit inside runs that long.
"""

SEQUENTIAL_SHARE = 0.4
"""And how much of the value that run has to be.

Presence alone is too weak: a fake written by hand often has `1234567890` in the
middle of it, and so could a real credential. What distinguishes an alphabet from
key material is that the sequence IS the value -- 26 of
`abcdefghijklmnopqrstuvwxyz0123456789`, 24 of `provider_abcdefghijklmnopqrstuvwx` --
rather than ten characters of forty.
"""

# Values that look like secrets and are not. Matched by literal value, never by
# path, because a path exemption would also hide a real credential that happened
# to land in the same file.
PLACEHOLDER = re.compile(
    rb"(?i)(example|sample|dummy|placeholder|redacted|your[_\-]?|some[_\-]?|"
    # A mask, which is the string a logger puts WHERE a secret was. `actions/runner`
    # declares `PasswordRemovedMask = "**password-removed**"` and four more beside it,
    # in the utility whose job is to keep secrets out of logs.
    rb"removed|masked|scrubbed|redact|"
    rb"changeme|xxxx|test[_\-]?only|fake|not[_\-]?a[_\-]?real|\.\.\.|"
    # A run of zeros, which is what somebody types when a field is required and they
    # have nothing to put in it. `home-assistant/core`'s llama_cpp integration ships
    # `DEFAULT_API_KEY = "sk-0000000000000000000"` -- a local server that checks the
    # prefix and ignores the rest. Six zeros in a row, as a substring test: the odds
    # of that inside real base64 key material are about one in five billion.
    rb"0{6}|"
    # The rest of the vocabulary a test value is written in. `token="xoxb-wire-probe"`
    # and `token='123456:fixture'` are both wire-contract probes in
    # `NousResearch/hermes-agent`, and they say so.
    rb"fixture|probe|stub|canary|sentinel|scaffold|hardcoded|"
    # Filler text, which is what a value says when somebody needed A value. GORM's CI
    # starts SQL Server with `MSSQL_SA_PASSWORD: LoremIpsum86`.
    #
    # Two words only. `hunter2`, `letmein` and `changeit` were in this list for one run
    # and three tests refused them: this codebase uses `hunter2Sup3rSecretV` as its
    # stand-in for a REAL credential, and every entry here is a substring test, so a
    # short common word dismisses anything containing it. The suite was right -- a value
    # is not a placeholder because it opens with a joke.
    rb"lorem|ipsum|"
    # Values that announce they are not credentials. Vault's rollback test sets
    # `bindpass="intentionally-wrong-password"`, which is a sentence saying so.
    rb"wrong|invalid|bogus|nonexistent|do[_\-]?not[_\-]?use|deliberately|intentional|"
    # The words themselves, used as their own placeholder. Documentation is
    # written `redis://username:password@host`, and reading that as a
    # credential produced eighty-seven findings across Django's, Scrapy's and
    # axios's docs and tests. A real credential is not spelled "password".
    # A qualifier in front is allowed, because `next_token = continuation_token` is
    # one variable assigned to another and so is every pagination loop ever written.
    # Airflow's Glue hook supplied it; the value is an identifier, not a value.
    #
    # Anchored at both ends, which is what keeps it narrow: the WHOLE value has to
    # read as a name ending in a credential word. `glpat-AAAAAAAAAAAAAAAA` does not,
    # and neither does any base64 or hex run.
    rb"^(?:[a-z][a-z0-9]{0,20}[_-]){0,3}(?:my|your|the|some|a|next|prev|previous|"
    rb"continuation|page|current|new|old|raw|temp|tmp)?[_-]?"
    rb"(?:user(?:name)?|pass(?:wo?rd)?|token|secret|apikey|api[_-]?key|"
    rb"login|admin|root|credential)s?[0-9]{0,6}[=:]?$|"
    # The same sentence with the separators left out, which is how it is written when
    # somebody types it into a seed script: `password: 'thisIsAPassword123'` in
    # `immich`. The whole value has to read as those words run together, and the
    # vocabulary is closed, so nothing generated can fall into it.
    rb"^(?:this|that|it|here)?(?:is)?(?:a|an|the|my|your|our)?"
    rb"(?:very|super|really|not)?(?:long|short|strong|weak|secure|insecure|bad|good)?"
    rb"(?:user(?:name)?|pass(?:wo?rd)?|token|secret|api[_-]?key|key|login|credential)"
    rb"s?[0-9]{0,8}$|"
    # Any brace interpolation, not just `{{` and `${`. An f-string such as
    # `f"https://x:{TOKEN}@host"` is a template, and the braces say so; the
    # value that ends up there at runtime is not in this file.
    rb"<[^>]{3,}>|\{[^}]{0,64}\}|\$\{|"
    # A bare variable reference, not only a braced one. Configuration
    # templates are written `private_key = $dir/private/cakey.pem` and
    # `secret = $insta::secret`; the value at runtime is not in this file, and
    # OpenSSL's own `.cnf` templates produced hundreds of findings in every
    # project that vendors it.
    # `$` at a word boundary only. A template writes `$dir/private/cakey.pem`, where
    # the `$` follows whitespace or a separator; a PayPal access token is spelled
    # `access_token$production$<id>$<secret>`, where every `$` follows a letter.
    #
    # Without the boundary this alternative matched the `$p` inside a real PayPal
    # token, so that pattern could fire and its finding was then discarded as a
    # placeholder every single time - a rule that runs, matches, and reports nothing.
    # The provider-sample gate found it before it shipped; nothing else would have,
    # because a rule whose findings are all dropped looks exactly like a rule with
    # nothing to find.
    rb"(?<![A-Za-z0-9_])\$[A-Za-z_]|"
    # `$$` is the shell's process id, so a value carrying one is different on every run.
    # `Hmbown/Codewhale` writes `TOKEN="smoke_test_token_$$"` in a smoke test.
    rb"\$\$|"
    # The Windows spelling of the same thing. Django's documentation extension
    # builds `token = "%HOMEPATH%\\" + token[2:]`, which the assembled-literal path
    # folded into a twelve-character value assigned to something called `token` and
    # reported at HIGH. `%VAR%` says the value arrives from the environment exactly
    # as plainly as `$VAR` does, and any build script that touches Windows paths is
    # full of it.
    rb"%[A-Za-z_][A-Za-z0-9_]{0,64}%|"
    # `[PROPERTY_NAME]`, which is how an MSI or WiX installer and several
    # configuration formats write a value to be substituted at install time.
    # MongoDB's installer fragment sets `Password='[MONGO_SERVICE_ACCOUNT_PASSWORD]'`,
    # naming the property rather than holding it.
    rb"\[[A-Z_][A-Z0-9_]{2,64}\]|"
    # A template in doubled brackets, which is what a Go template with custom
    # delimiters looks like and what Grafana's `index.html` carries:
    # `data-recording-token="[[.MeticulousAIRecordingToken]]"`.
    rb"\[\[[ \t]{0,4}[.$A-Za-z_]|"
    # A printf conversion, which makes the value a format string:
    # `_TEX_DISPLAY_TOKEN = "HERMESTEXDISPLAY%dHERMESTEXEND"` is a marker a renderer
    # substitutes into, not a token.
    rb"%[-+ #0]{0,3}[0-9]{0,3}(?:\.[0-9]{1,3})?[sdifgGxXoeEc]|"
    # Interpolation and substitution that braces do not cover. Swift writes
    # `"\(token)"` and the shell writes `"$(get_token)"`, and in both the value at
    # runtime is not in this file -- `displayToken = "\(baseDisplayToken)\(suffix)"`
    # and `auth_token="$(cmux_computer_use_auth_token)"` were both reported at HIGH
    # in `manaflow-ai/cmux`, which assigns neither a credential nor a literal.
    rb"\\\(|\$\()"
)

#: Credentials the vendor publishes ON PURPOSE, as a fixture everyone shares.
#:
#: Not placeholders and not examples: these are live, working values that are meant
#: to be in your repository, because the service they authenticate to is an emulator
#: running on your own machine. Reporting one is not a near miss, it is a statement
#: that is wrong on its face.
#:
#: The first entry is the Azure Storage emulator key, which Azurite and the older
#: Storage Emulator both ship. It was found reported at CRITICAL in Celery's
#: `docker-compose.yml` and `tox.ini` and in two of Elasticsearch's Azure tests -- and
#: the fact that the SAME eighty-eight characters appear in two unrelated projects is
#: the proof that it is a shared public fixture rather than anybody's secret. Every
#: Azure development setup in the world contains it, alongside the account name
#: `devstoreaccount1`.
#:
#: Matched on the exact value, which is what makes this safe: an exact string cannot
#: over-suppress the way a shape can. A list of published fixtures grows by one entry
#: per vendor and can never quietly widen.
#:
#: Deliberately NOT the place for "credentials we think are probably fake". That
#: judgement belongs to `PLACEHOLDER`, which tests for the shapes humans use when they
#: mean "put yours here". This list is only for values a vendor documents as public.
FIREBASE_WEB_CONFIG = re.compile(rb"(?i)authDomain[\"'\s:]{1,6}[^\"'\s]{1,200}firebaseapp\.com")
"""Firebase's web configuration object, identified by the field only it has.

`excalidraw` commits one in `.env.development` and `.env.production` as
`VITE_APP_FIREBASE_CONFIG='{"apiKey":"AIzaSy...","authDomain":"x.firebaseapp.com",...}'`.
Firebase's own documentation says this object is not a secret: the browser needs every
field in it to reach the project at all, so it ships in the bundle by construction, and
what protects the data is the security rules rather than the key.

Identified on `authDomain` pointing at `firebaseapp.com`, which is the server half of
the handshake and appears in no other kind of configuration. The name it is assigned to
cannot answer this -- `VITE_APP_FIREBASE_CONFIG` is public by contract and
`names_public_by_contract` would have said so, but the key is inside a JSON blob and
the name the assignment rule sees is `apiKey`.
"""

FIREBASE_CONFIG_WINDOW = 400
"""How far around a key to look for the `authDomain` that identifies its config."""

PUBLIC_BY_DESIGN_PREFIXES = (
    # PostHog's PROJECT api key, which is write-only ingestion and goes in the browser.
    # PostHog's own documentation says to put it in client-side code; the secret one is
    # the personal api key, spelled `phx_`, and that prefix is deliberately not here.
    #
    # `browser-use`, `Fission-AI/OpenSpec` and `hoppscotch` each commit one in their
    # telemetry module, and a finding about it has no remediation: nothing to rotate,
    # nothing to remove, and it is already in every published bundle.
    b"phc_",
    # RevenueCat's PUBLIC SDK keys, which ship inside the app binary because that is
    # where the SDK runs. `appl_` is the Apple platform key and `goog_` the Android
    # one; the secret is the v2 API key, which RevenueCat spells `sk_`, and that
    # prefix is deliberately not here. `AFFiNE` declares one in its paywall bridge.
    b"appl_",
    b"goog_",
)
"""Credential prefixes whose whole purpose is to be published.

Checked at the finding site rather than in `NOT_A_SECRET`, and the distinction matters:
the patterns must go on refusing to launder a prefixed value, because that is what
stops `"glpat-" + "AAAA..."` from reading as an identifier. What this list says is
narrower -- that for these specific prefixes the value being present is not a leak.
"""

#: Client configuration files a vendor generates for you to SHIP.
#:
#: Firebase's `google-services.json` and `GoogleService-Info.plist` hold an `AIza` key,
#: and Google's own documentation says that key is not a secret: it identifies the
#: project, access is controlled by Firebase security rules, and every Android and iOS
#: binary that uses Firebase carries it where anybody can read it with `strings`.
#:
#: `SECRET.GOOGLE.API_KEY.001` reported it in eight corpus repositories -- `nickbutcher/
#: plaid`, `deckerst/aves`, SmartTube, two of `nisrulz/flutter-examples`, Firebase's own
#: `mock-google-services.json`, and FlutterFire's service-worker example -- at HIGH,
#: with a remediation that says to rotate it. There is nothing to rotate.
#:
#: Scoped to these FILENAMES and to that one rule. An `AIza` key anywhere else stays a
#: finding, because a Google Cloud api key with billing or a server-side key is a real
#: one and is written the same way.
CLIENT_CONFIG_FILES = (
    "**/google-services.json",
    "**/mock-google-services.json",
    "**/google-services-*.json",
    "**/GoogleService-Info.plist",
    "**/GoogleService-Info-*.plist",
    "**/firebase-messaging-sw.*",
    "**/firebase_options.dart",
    "**/firebaseConfig.*",
    # An Android manifest, which is compiled into the APK and readable in any copy of
    # it. A Maps key goes here as `com.google.android.geo.API_KEY` because that is
    # where the Maps SDK reads it from, and Google restricts it to the app's signing
    # certificate rather than keeping it secret. `DrKLO/Telegram` keeps six of them
    # across its debug, release and standalone manifests.
    "**/AndroidManifest.xml",
    "**/AndroidManifest_*.xml",
)

CLIENT_CONFIG_RULES = frozenset({"SECRET.GOOGLE.API_KEY.001"})
"""The rules `CLIENT_CONFIG_FILES` excuses. Nothing else in those files is excused."""

PLACEHOLDER_KEY = re.compile(
    rb"(?i)(?:^|[^\w.])(?:placeholder|example|examples|hint|sample|demo|default_?value"
    rb"|dummy|template|format|pattern|mask)[\s\]\)\}]{0,4}[=:][^\n]{0,40}$"
)
"""A key whose VALUE is an illustration, by the key's own name.

A form field's `placeholder` is the greyed-out text in the box. `anything-llm` writes
`placeholder="sk-myApiKeyToAccessMyChromaInstance"`, `makeplane/plane` writes
`placeholder: "sk-asddassdfasdefqsdfasd23das3dasdcasd"` and a GitLab one beside it.

Matched against the text BEFORE the credential rather than against the credential, and
applied to the provider patterns, which is the difference that matters: `PLACEHOLDER`
reads the value and cannot see that the key is called `placeholder`, and the provider
patterns deliberately consult almost nothing -- a `ghp_` prefix is a token wherever it
sits. The key's own name is the exception, because it is a statement by the author about
what the value is for.
"""

PRESIGNED_CREDENTIAL = re.compile(rb"(?i)X-Amz-Credential=")
"""The public half of a SigV4 signature, which a presigned URL carries by construction.

`Asabeneh/30-Days-Of-Python` ships a 14,000-row Hacker News dataset, and one row holds a
GitHub-generated presigned S3 URL with `X-Amz-Credential=AKIA...` in the
query string. A presigned URL exists to be handed to somebody: the key ID is in it by
design, the signature is what authorises, and the signature expires.
"""

PROSE_RUN = re.compile(rb"[A-Za-z]{2,24}(?: [A-Za-z0-9][A-Za-z0-9,.';:!?()\-]{0,23}){2,16}")
"""Three or more space-separated words, which is what a sentence decodes to.

Spaces are the whole of it. The first draft allowed `-` and `.` as separators too, and
`invented-secret-value-x9` -- the value an existing test uses precisely because it is
not a secret but must still be reported as one -- read as prose. A hyphenated
identifier is not a sentence; nothing written by a person to be read goes three words
without a space.
"""

MIN_PROSE_DECODE = 12
"""How many decoded bytes before reading them as prose means anything.

Short enough that a four-word sentence qualifies, long enough that three random
bytes landing on printable characters do not.
"""

AWS_SECRET_SHAPE = re.compile(rb"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")

AWS_LABELLED_SECRET = re.compile(
    rb"""(?i)(?:aws_?)?secret_?access_?key["']?\s*[:=]\s*["']?(?![$<{%]|\s|["']|\Z)"""
    rb"""(?!(?:none|null|nil|changeme|example|your|xxx|\*{3}|redacted|placeholder|todo)\b)"""
    rb"""[^\s"'#;,]{16,}"""
)
"""The shape of an AWS secret access key: forty characters of base64 alphabet."""

AWS_KEY_ID_RULES = frozenset({"SECRET.AWS.ACCESS_KEY.001"})
"""The rules the pairing test below applies to."""

AWS_PAIR_WINDOW = 400
"""How far from a key id to look for the secret that would make it usable."""

WORD_VALUE_CHARS = re.compile(rb"[A-Za-z0-9_.\-]{4,120}")
"""The characters a concatenated-identifier value may contain.

No `+`, `/`, `=`, `~`, `@`, `:` or anything else. Base64 and the connection-string
shapes carry at least one of those, which is most of what keeps them out before the
word test below runs at all.
"""

WORD_SEGMENT = re.compile(rb"[A-Z][a-z]{2,20}|[a-z]{3,20}")
"""One word: a capital and two lowercase letters, or three lowercase on their own.

Three without a capital, two with one. The capital is evidence that somebody chose a
boundary there, and a two-letter run with none is what a generated value is full of:
`hc2wb63opyfxnwn` is a real corpus credential whose runs are `hc`, `wb` and
`opyfxnwn`, and an earlier draft of this asked only for two lowercase and dismissed
it. An existing guard value caught that within one run, which is what the guard is
for.

What the asymmetry costs is `ss2022Method` and `SsoEmail2faSessionToken`, whose
`ss` and `fa` are real words' worth of letters and too short to prove it. Both stay
reported, which is the safe direction.
"""

MIN_WORD_SEGMENTS = 2
"""How many words before a value is a name rather than a string that happens to read.

One word is `password` or `fluttergo`, which this would dismiss either way and which
`PLACEHOLDER` and the entropy floor already answer. Two is where the claim starts to
mean something: nothing generated produces two consecutive real words.
"""

URL_RUN = re.compile(rb"[a-z][a-z0-9+.\-]{1,12}://[^\s\"'`<>]{1,2000}")
"""A URL, taken as far as the first character that cannot be in one."""

MIN_BASE64_RETEST = 12
"""How many decoded bytes before re-asking the value predicates means anything."""

EXAMPLE_LITERAL_INTRO = re.compile(
    rb"(?i)(?:example|examples|longdesc|usage|synopsis|help)[A-Za-z0-9_]{0,20}"
    rb"[\s:=,]{0,8}(?:[A-Za-z0-9_.]{0,40}\([\s]{0,4}(?:[A-Za-z0-9_.]{0,40}\([\s]{0,4}){0,2})?$"
)
"""A declaration that says the string literal about to open is an example.

Every Go CLI built on cobra writes its help text this way, and `kubectl` is the one the
corpus found: `set_credentials.go` declares
`setCredentialsExample = templates.Examples(` and six lines into the raw string shows
`kubectl config set-credentials cluster-admin --username=admin --password=...`. The
password is an example of a flag, in the text the command prints when you ask it for
help.

`EXAMPLE_PROMPT` cannot see this -- a kubectl example block has no `$` or `>>>` in front
of it, because the reader is meant to copy the line as it stands. What identifies it is
the author's own name for the variable.
"""

EXAMPLE_LITERAL_WINDOW = 120
"""How far back from the opening backtick to look for that declaration."""

PUBLISHED_PRIVATE_KEY_BODIES = (
    # Vagrant's insecure ed25519 key, the successor to the RSA one below. It lives at
    # `keys/vagrant.key.ed25519` in `hashicorp/vagrant` and on every box that has not
    # replaced it, which is the whole point: Vagrant inserts a generated keypair on
    # first boot and this is what it uses to get in and do that.
    #
    # The slice starts at the public point and not at the armour. An unencrypted
    # OpenSSH-format ed25519 key opens with a fixed seventy characters -- the format
    # name, `none` twice for the cipher and the kdf, and the key count -- and the first
    # draft of this entry was exactly those bytes, which would have dismissed every
    # ed25519 private key in existence.
    b"QyNTUxOQAAACDdWHcQaTZc8Q6nycsP0CqMNRfsLxvYVxqKosrHyTp+WA",
    # The Vagrant insecure keypair, shipped in every base box since 2010 and
    # documented by HashiCorp as insecure: Vagrant replaces it on first `vagrant up`,
    # and its whole purpose is to be known. It is committed in `hashicorp/vagrant`
    # itself -- twice, once per algorithm -- and in every repository that vendors a
    # box or a test harness built on one.
    #
    # Matched on the body rather than the path, because the path is whatever the
    # vendoring project called it.
    b"MIIEogIBAAKCAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzI",
)
"""Private keys whose publication is the point.

Matched on a prefix of the base64 body, which for an RSA key encodes the modulus and
is therefore unique to the keypair. A prefix rather than the whole body so that line
wrapping and the header variant do not matter.

Checked against the FILE rather than against the match, and that is not a detail: the
private-key pattern captures the armour plus twelve base64 characters, and the first
twelve characters of every 2048-bit RSA key are the same -- `MIIEogIBAAKC` is the DER
header, not the modulus. Testing the match would have excused every RSA key there is.
"""

PUBLISHED_KEY_WINDOW = 400
"""How far past the armour to look for a published body.

Bounded so that a file holding the Vagrant key AND a real one reports the real one. The
body begins on the line after the header, so a few hundred bytes is generous."""

PEM_BODY = re.compile(rb"-{3,6}BEGIN[ A-Z0-9]{0,60}-{3,6}([\s\S]{0,8000}?)-{3,6}END")

MIN_PEM_BODY = 60
"""How many base64 characters a PEM block needs before it can be a key.

An Ed25519 private key in PKCS#8 is about sixty-four; an EC P-256 key in SEC1 is about
a hundred and twenty; RSA runs into the hundreds. Below sixty there is no key of any
algorithm, so the block is an ILLUSTRATION of the format:

    key_content: "-----BEGIN EC PRIVATE KEY-----\nfewfawefawfe\n-----END EC PRIVATE KEY-----"

is `fastlane`'s documentation for its App Store Connect action, and twelve characters of
keyboard mash is what an example looks like. `juspay/hyperswitch` writes the same shape
into an OpenAPI `example =` annotation.

Checked against the FILE rather than the match, for the reason `holds_published_key`
already records: the provider pattern captures the armour plus twelve characters, which
is too little to judge either question.
"""

DECLARED_NAME = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{2,60}")
"""An identifier. Every one in the window is asked, last first."""

DECLARED_NAME_WINDOW = 160
"""How far back from the armour to look for the name that introduces it."""

WRAPPED_ASSIGNMENT = re.compile(rb"(?:=>|[=:])[ \t]*$")
"""A line that ends where its value has not started yet.

`=>` for PHP and Ruby hashes, `=` for most things, `:` for YAML, JSON and object
literals. Read only by `key_name_is_illustrative`, and only to decide whether the
name on the previous line belongs to the value on this one."""

B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

PUBLISHED_CREDENTIALS = frozenset(
    {
        # Azure Storage emulator, account `devstoreaccount1`.
        b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        # MinIO's default root credentials, which its own quickstart prints.
        b"minioadmin",
        # Grafana's default `secret_key`, which ships in `conf/defaults.ini` in every
        # installation. It turns up twice in one repository -- once in that file and once
        # as a Go constant in `apps/advisor/.../security_config_step.go`, where the
        # advisor's whole job is to tell an operator they have not changed it.
        b"SW2YcwTIb9zpOOhoPsMm",
        # The account NAME the emulator key above belongs to. The key was listed and
        # the name was not, so `Azure/azure-sdk-for-cpp` writing
        # `auto accessKey = "devstoreaccount1";` reported an access key.
        b"devstoreaccount1",
        # Google's documented reCAPTCHA test keys, published so that a test suite can
        # always pass the challenge. The site key is the other half and is public by
        # definition. Copied into a great many repositories, because Google's own
        # documentation says to.
        b"6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe",
        b"6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI",
        # AWS's documented example credentials, which appear in the signing
        # specification and in most of its SDK documentation.
        b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        b"AKIAIOSFODNN7EXAMPLE",
        # The Stripe documentation's test card and publishable fixtures are covered by
        # PLACEHOLDER's `test` handling; nothing further is needed for them here.
        #
        # Supabase's self-host quickstart, whose `docker-compose.yml` every project
        # that self-hosts Supabase copies. `Significant-Gravitas/AutoGPT` keeps it at
        # `autogpt_platform/db/docker/docker-compose.yml`, and the file identifies
        # itself twice over: it opens with `name: supabase`, and the anon and
        # service-role JWTs beside this value carry `"iss": "supabase-demo"` in their
        # payloads -- the tokens say whose demo they are. This one has no claims to
        # read, which is why it is listed and they are not.
        b"UpNVntn3cDxHJpq99YMc1T1AQgQpc8kfYTuRgBiYa15BLrx8etQoXz3gZv1/u2oq",
    }
)

_LITERAL = re.compile(rb"""'([^'\n]{0,240})'|"([^"\n]{0,240})\"""")
"""One quoted string literal.

Two branches, each a simple character run. Nothing nests, so this cannot be
made to backtrack -- the same property Cordon requires of every rule pack
pattern, and the engine does not get an exemption from it."""

_JOINER = re.compile(rb"^[\s\\]{0,32}[+.][\s\\]{0,32}$")
"""What may sit between two literals for them to still be one value.

Concatenation is `+` in most languages and `.` in PHP and Perl; a trailing
backslash continues the line. Anything else -- a comma, a parenthesis, an
identifier -- means these are two separate values rather than one split one.

An operator is **required**, not merely permitted. Allowing whitespace alone
merges any two literals that happen to sit on consecutive lines, which is what
a list of regex patterns in a rule pack, a table of URLs in `pyproject.toml`
and a fenced code block in a document all look like -- each of which this
flagged before the requirement was added."""


__all__ = [
    "AWS_KEY_ID_RULES",
    "AWS_LABELLED_SECRET",
    "AWS_PAIR_WINDOW",
    "AWS_SECRET_SHAPE",
    "B64_ALPHABET",
    "CLIENT_CONFIG_FILES",
    "CLIENT_CONFIG_RULES",
    "DECLARED_NAME",
    "DECLARED_NAME_WINDOW",
    "EXAMPLE_LITERAL_INTRO",
    "EXAMPLE_LITERAL_WINDOW",
    "FIREBASE_CONFIG_WINDOW",
    "FIREBASE_WEB_CONFIG",
    "MIN_BASE64_RETEST",
    "MIN_PEM_BODY",
    "MIN_PROSE_DECODE",
    "MIN_WORD_SEGMENTS",
    "PASSWORD_HASH",
    "PEM_BODY",
    "PLACEHOLDER",
    "PLACEHOLDER_KEY",
    "PRESIGNED_CREDENTIAL",
    "PROSE_RUN",
    "PUBLIC_BY_DESIGN_PREFIXES",
    "PUBLISHED_CREDENTIALS",
    "PUBLISHED_KEY_WINDOW",
    "PUBLISHED_PRIVATE_KEY_BODIES",
    "SEQUENTIAL_RUN",
    "SEQUENTIAL_SHARE",
    "URL_RUN",
    "WORD_SEGMENT",
    "WORD_VALUE_CHARS",
    "WRAPPED_ASSIGNMENT",
    "SecretValues",
]
