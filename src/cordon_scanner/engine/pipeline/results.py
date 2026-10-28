"""Folding a scan's findings into what a reader needs: one finding and a count for an issue repeated
across copies of a tree, one for a library idiom seen in many files, one for a corpus of keys or
credential names, and one for a graded pair reported twice.

Each fold keeps every location it absorbed (the finding says how many and lists the first few), and
none folds two findings that differ in what they matched.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.engine.pipeline.constants import (
    CREDENTIAL_NAME_CEILING,
    CREDENTIAL_NAME_FILES,
    KEY_CORPUS_CEILING,
    KEY_CORPUS_CONFIDENCE,
    KEY_TABLE_SIZE,
    MAX_REPEAT_PATHS_LISTED,
    MIN_IDIOM_FILES,
    MIN_IDIOM_SNIPPET,
    POLYGLOT_CORPUS,
    POLYGLOT_CORPUS_CEILING,
    POLYGLOT_RULE,
    PRIVATE_KEY_CORPUS,
    PRIVATE_KEY_RULE,
)
from cordon_scanner.foundation.models import (
    Category,
    Finding,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class ResultFolding:
    """Folds repeated findings into one finding and a count."""

    @staticmethod
    def repeats(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """One finding per distinct issue, however many copies of the file exist.

        A repository that keeps an old copy of a tree reports everything in it twice.
        `stacksimplify/terraform-on-aws-ec2` keeps `BACKUP-BEFORE-DEC2023-UPDATES/` and
        `V1-UPDATES-DEC2023/` beside the current material, and 124 of its 180 findings
        were in those two directories -- the same security group, the same key, reported
        again. `terraform-on-aws-eks` commits one RSA private key into 179 directories,
        one per lesson, and `community-scripts/ProxmoxVE` has 618 scripts that source
        the same bootstrap function from the same mutable branch.

        In each of those a reader needs one finding and a count, not N findings. So
        findings that share a rule AND the hash of the VALUE they matched collapse to
        the first by path, carrying the number of files and the first few names.

        The grouping key is the rule and the hash of the FILE, which is the only
        definition of "a copy" that holds up. Two earlier keys were tried and both were
        wrong:

        * The hash of the matched VALUE. For a private key that match is the PEM header
          plus twelve characters of body, and every 2048-bit RSA key in the world begins
          `MIIEogIBAAKC` -- so Spring Boot's nineteen distinct client keys would have
          collapsed into one finding claiming they were the same value. A test written
          to assert the opposite caught it.
        * The hash of a matched SNIPPET. `cidr_blocks = ["0.0.0.0/0"]` hashes the same
          in a hundred unrelated modules and `eval(` the same in fifty unrelated files,
          and saying "this is one thing to fix" about fifty independent problems is
          false. This project's own suite caught that one: two tests write the same
          payload to two paths to prove a point about path selection.

        Identical files are immune to both. A duplicated lesson directory, a `BACKUP-`
        copy of a tree, one key committed into 179 places: same bytes, same finding,
        one report.

        Only across DIFFERENT paths, and never operational notes -- those are already
        aggregated where it helps and are about the scan rather than the code.

        The trade is SARIF: a consumer that renders one alert per location now gets one
        alert for the group. That is the right answer for the text report and the wrong
        answer for a code-scanning annotation, and the count in the message and the
        `copies` metadata are what a reader has instead.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        order: list[Finding] = []
        for finding in findings:
            file_hash = dict(finding.evidence.metadata).get(Finding.FILE_HASH_KEY)
            if not file_hash or finding.category is Category.OPERATIONAL:
                order.append(finding)
                continue
            groups.setdefault((finding.rule_id, file_hash), []).append(finding)

        for group in groups.values():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            if len(paths) < 2:
                order.extend(group)
                continue
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            order.append(
                replace(
                    first,
                    message=(
                        f"{first.message} This file is byte-for-byte identical in "
                        f"{len(paths)} places ({listed}{more}), so the finding is "
                        f"reported once: it is one thing to fix, not {len(paths)}."
                    ),
                    evidence=replace(
                        first.evidence,
                        metadata=(*first.evidence.metadata, ("copies", str(len(paths)))),
                    ),
                )
            )

        return tuple(sorted(order, key=lambda f: (f.location.path, f.location.line or 0)))

    @staticmethod
    def idiom(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """One decision made in many files is one finding.

        `community-scripts/ProxmoxVE` ships about six hundred container install scripts
        and every one of them opens the same way: source a bootstrap function from the
        `main` branch of a GitHub repository. 601 of its 618 dropper findings carry a
        byte-identical snippet, and 97 of its 98 persistence findings carry another.

        That is one design decision applied six hundred times. It is a real finding --
        what runs is whatever that branch holds at install time -- and it is ONE thing
        for the project to change, in the generator that writes those scripts.

        Two conditions, and both exist to keep this away from independent findings:

        * Ten or more distinct files. Three modules with the same one-line mistake are
          three things to fix, and a test asserts they stay three.
        * A snippet long enough to be specific -- forty bytes. `cidr_blocks =
          ["0.0.0.0/0"]` is twenty-seven and hashes the same in a hundred unrelated
          modules; the ProxmoxVE line is eighty and could not arrive by coincidence.

        The count and the first few paths are in the message, so nothing is hidden: a
        reader who wants the full list has the rule id and can ask for it without the
        collapsing.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        for finding in findings:
            evidence = finding.evidence
            snippet = evidence.snippet or ""
            if finding.category is Category.OPERATIONAL:
                continue
            # A composite carries its own key, because the hit its evidence
            # points at and the construct its files SHARE are different hits.
            # `_anchor` moved the evidence onto the specific half -- the
            # `curl | bash` rather than the banner above it -- and keying this
            # on the evidence therefore switched the collapse off: ProxmoxVE's
            # persistence findings went from one to twenty-seven in a pass. See
            # `FindingAnchor.with_idiom_key`, which is where the shared
            # half is hashed, and which applies this same length test to it.
            idiom = dict(evidence.metadata).get("idiom_hash")
            if idiom is None and (not evidence.match_hash or len(snippet) < MIN_IDIOM_SNIPPET):
                continue
            groups.setdefault((finding.rule_id, idiom or evidence.match_hash), []).append(finding)

        replaced: dict[int, Finding | None] = {}
        for group in groups.values():
            paths = sorted({f.location.path for f in group})
            if len(paths) < MIN_IDIOM_FILES:
                continue
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            kept = replace(
                first,
                message=(
                    f"{first.message} The identical construct appears in {len(paths)} "
                    f"files ({listed}{more}), so it is reported once: that is one "
                    f"decision applied {len(paths)} times, and one place to change it."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("occurrences", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        if not replaced:
            return tuple(findings)

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def key_corpus(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """A directory full of private keys is a corpus, not a disclosure.

        OpenSSL ships eleven in `apps/` -- `ca-key.pem`, `pca-key.pem`, `privkey.pem`,
        `s512-key.pem`, `rsa8192.pem` and the rest -- and has since the 1990s. They are
        in every release tarball and vendored into Node, Python and most of the
        internet. Metasploit ships thirty under `data/exploits/CVE-2023-34039/`, one per
        affected appliance version, because the vulnerability IS that the vendor shipped
        those keys. MongoDB keeps twenty-eight under `x509/static/`; rustls keeps eight
        per algorithm under `test-ca/`.

        None of those is a key somebody leaked, and eleven CRITICAL findings is not how
        to tell a reader so. One finding naming the directory and the count is, and it
        is also what they would act on: baseline the directory, or explain it.

        The threshold is what makes this safe to do at all. One or two keys in a
        directory is what a leak looks like -- a stray `id_rsa`, a `server.key` beside a
        `deploy.sh` -- and those are untouched. Five distinct key FILES in one directory
        is a hierarchy somebody generated: a CA, an intermediate, a client, a server, a
        revoked one.

        Ceilinged rather than dropped, and the count is in the message, so a directory
        of live keys is still in the report and still says how many. What changes is
        that it stops failing a build eleven times over.
        """
        keys: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == PRIVATE_KEY_RULE:
                keys.setdefault(finding.location.path.rpartition("/")[0], []).append(finding)

        corpora = {
            directory: group
            for directory, group in keys.items()
            if len({f.location.path for f in group}) >= PRIVATE_KEY_CORPUS
        }
        if not corpora:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for directory, group in corpora.items():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(path.rpartition("/")[2] for path in paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            where = directory or "the repository root"
            kept = replace(
                first,
                severity=min(first.severity, KEY_CORPUS_CEILING),
                confidence=min(first.confidence, KEY_CORPUS_CONFIDENCE),
                message=(
                    f"{where} holds {len(paths)} private keys ({listed}{more}). A "
                    f"directory of keys is a generated hierarchy -- a CA, an "
                    f"intermediate, a client, a server -- far more often than it is a "
                    f"disclosure, so this is reported once and below its usual "
                    f"severity. If any of these protects something live, every one of "
                    f"them is public: they are in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("keys_in_directory", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def credential_name(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """The same credential-shaped name assigned in many files is one decision.

        `_collapse_idiom` makes this argument already and cannot reach a secret: it groups
        on a forty-byte snippet, and a secret's evidence is hash-only by policy, so there
        is no snippet to group on. What a secret finding does carry is the name the value
        was assigned to, and that is the key here.

        `rclone` declares `rcloneEncryptedClientSecret` in sixteen backend modules. Each
        value differs -- one OAuth app per cloud provider -- and the decision is one: ship
        a client secret in the binary, which a native application has to do, because RFC
        8252 says it cannot keep one confidential and `obscure.MustReveal` un-obscures it
        at runtime anyway.

        The threshold is `_collapse_idiom`'s ten, for the reason that docstring gives:
        three modules with the same mistake are three things to fix.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        for finding in findings:
            if not finding.rule_id.startswith("SECRET."):
                continue
            kind = dict(finding.evidence.metadata).get("kind")
            if not kind:
                continue
            groups.setdefault((finding.rule_id, kind), []).append(finding)

        replaced: dict[int, Finding | None] = {}
        for (_, kind), group in groups.items():
            paths = sorted({f.location.path for f in group})
            if len(paths) < CREDENTIAL_NAME_FILES:
                continue
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            kept = replace(
                first,
                severity=min(first.severity, CREDENTIAL_NAME_CEILING),
                message=(
                    f"The same {kind} appears in {len(paths)} files ({listed}{more}). The "
                    f"same name in that many files is one decision rather than that many "
                    f"leaks -- a "
                    f"credential per backend, per provider or per tenant -- so it is "
                    f"reported once and below its usual severity. Every value is still "
                    f"committed: if any of them protects something live, all of them are "
                    f"in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("files_with_this_name", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def polyglot_corpus(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """A directory full of format mismatches is a collection of them.

        Built from `_collapse_key_corpus` above, which makes the same argument about the
        same kind of place, and the thresholds match for the same reason: one or two files
        whose contents contradict their names is what a disguise looks like, and five in
        one directory is somebody's collection.

        `swisskyrepo/PayloadsAllTheThings` keeps sixteen under
        `Upload Insecure Files/Picture ImageMagick/`. Every one is a genuine polyglot and
        the repository exists to collect them; what the reader needs is one finding saying
        the directory holds sixteen, which is also the thing they would act on.
        """
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == POLYGLOT_RULE:
                groups.setdefault(finding.location.path.rpartition("/")[0], []).append(finding)

        corpora = {
            directory: group
            for directory, group in groups.items()
            if len({f.location.path for f in group}) >= POLYGLOT_CORPUS
        }
        if not corpora:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for directory, group in corpora.items():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(path.rpartition("/")[2] for path in paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            where = directory or "the repository root"
            kept = replace(
                first,
                severity=min(first.severity, POLYGLOT_CORPUS_CEILING),
                message=(
                    f"{where} holds {len(paths)} files whose contents contradict their "
                    f"names ({listed}{more}). A directory of them is a collection -- an "
                    f"upload-test corpus, a fuzzing corpus, a payload reference -- far "
                    f"more often than it is a disguise, so this is reported once and "
                    f"below its usual severity. Each file is still a polyglot: if any of "
                    f"them is served to a browser or passed to an image library, the "
                    f"contents are what runs."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(
                        *first.evidence.metadata,
                        ("polyglots_in_directory", str(len(paths))),
                    ),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def key_table(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """Several private keys in ONE file are a table of keys.

        The directory form above needs five, because a directory is a place a leak can
        land in: a stray `id_rsa`, a `server.key` beside a `deploy.sh`. A FILE is not.
        A leak is one key in a file -- it got there by being copied in -- and three in
        one file is a fixture table somebody generated on purpose.

        `bitwarden/server` keeps four in `util/RustSdk/rust/src/rsa_keys.rs`, which is
        test key material for its SDK bindings held as Rust constants, and mbedtls's
        `certs.c` and its vendored copies hold a dozen apiece. Four CRITICAL findings
        pointing at four lines of one file is not how to tell a reader that.

        Same ceiling and same shape as the directory form, for the same reason: the
        count is in the message, so a file of live keys is still in the report and still
        says how many.
        """
        keys: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == PRIVATE_KEY_RULE:
                keys.setdefault(finding.location.path, []).append(finding)

        tables = {path: group for path, group in keys.items() if len(group) >= KEY_TABLE_SIZE}
        if not tables:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for path, group in tables.items():
            first = min(group, key=lambda f: f.location.line or 0)
            kept = replace(
                first,
                severity=min(first.severity, KEY_CORPUS_CEILING),
                confidence=min(first.confidence, KEY_CORPUS_CONFIDENCE),
                message=(
                    f"{path} holds {len(group)} private keys. Several keys in one file "
                    f"is a table somebody generated -- test material for a TLS handshake, "
                    f"a fixture per algorithm -- far more often than it is a disclosure, "
                    f"so this is reported once and below its usual severity. If any of "
                    f"them protects something live, every one of them is public: they are "
                    f"in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("keys_in_file", str(len(group)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def graded_pair(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """`MALWARE.X` and `SUSPECT.X` on one span are one observation.

        The composites come in graded pairs on purpose: `SUSPECT.EXFIL.001` is
        credential access with egress, and `MALWARE.EXFIL.001` is the same pair
        in an install hook. Where the install hook is what the file is, both
        match the same capabilities at the same place, and the report carried
        each of them -- so `saltstack/salt`'s `setup.py:459` and
        `tinyhumansai/openhuman`'s `install.js:9` appeared twice, and a reader
        counting findings counted one thing as two.

        The stronger rule already says everything the weaker one says: its match
        clause is the weaker clause plus the context. So the weaker finding is
        dropped rather than ceilinged -- there is no residual claim left in it.

        Only within a family and only on an identical span. `SUSPECT.DROPPER.001`
        elsewhere in the same file is a second place that fetches and executes,
        and it stays.

        Measured: seven findings across five repositories of 1,427. Small, and
        the reason to fix it anyway is that severity counts are what a gate
        reads -- two criticals for one line makes the number mean less than it
        appears to.
        """
        Span = tuple[str, int | None, int | None, int | None]
        by_span: dict[Span, set[str]] = {}
        for finding in findings:
            location = finding.location
            span = (location.path, location.line, location.byte_start, location.byte_end)
            by_span.setdefault(span, set()).add(finding.rule_id)

        superseded: set[tuple[Span, str]] = set()
        for span, rule_ids in by_span.items():
            for rule_id in rule_ids:
                if not rule_id.startswith("MALWARE."):
                    continue
                weaker = f"SUSPECT.{rule_id[len('MALWARE.') :]}"
                if weaker in rule_ids:
                    superseded.add((span, weaker))
        if not superseded:
            return tuple(findings)

        out: list[Finding] = []
        for finding in findings:
            location = finding.location
            span = (location.path, location.line, location.byte_start, location.byte_end)
            if (span, finding.rule_id) in superseded:
                continue
            out.append(finding)
        return tuple(out)


__all__ = ["ResultFolding"]
