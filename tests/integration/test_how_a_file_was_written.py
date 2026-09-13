"""The scanner's answer must not depend on how a file was written.

Two defects found on the first Windows CI run, and two more found by the probe
this file grew out of, were all one thing: a rule that reads bytes and an
assumption about which bytes a line ends with, or begins with.

    a webhook reported as a wildcard RBAC grant      -- `$` will not step over `\r`
    argo-cd's cluster-admin role not reported at all -- `[ \t]` does not contain `\r`
    a Dockerfile's `FROM` not checked                -- `^` will not step over a BOM
    a polyglot losing SUSPECT.DROPPER.001 at HIGH    -- nor will `startswith(b"#!")`

Three of the four are false NEGATIVES, which is the direction that does not
announce itself: the report simply comes back shorter. A syntactic check over
the rule packs would have caught two of them. This catches all four, and it
catches the ones that are not regexes at all -- line arithmetic, byte offsets,
the line-counted proximity windows, and `_is_minified`'s mean line length, each
of which shifts when every line grows by a byte.

The corpus is the fixture because it is the only body of files in the project
whose expected findings are already written down.
"""

from __future__ import annotations

import pathlib

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from support import CORPUS, requires_malicious_corpus

#: How the same file looks when a different editor on a different platform saves it.
TRANSFORMS = {
    "crlf": lambda raw: raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"),
    "bom": lambda raw: raw if raw.startswith(b"\xef\xbb\xbf") else b"\xef\xbb\xbf" + raw,
    "bom_and_crlf": lambda raw: (
        b"\xef\xbb\xbf" + raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    ),
}


def _samples() -> list[pathlib.Path]:
    return [path for path in sorted(CORPUS.glob("*/*")) if path.is_dir()]


def _rewrite(source: pathlib.Path, destination: pathlib.Path, transform) -> None:
    """Copy a sample, rewriting every text file the way another editor would.

    Binary files are copied untouched: a byte-order mark in front of a PNG's
    magic makes it a different file rather than the same file written twice.
    """
    for entry in source.rglob("*"):
        target = destination / entry.relative_to(source)
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = entry.read_bytes()
        target.write_bytes(raw if b"\x00" in raw[:1024] else transform(raw))


def _findings(root: pathlib.Path) -> list[tuple[str, str]]:
    config = Config.default().with_overrides(use_cache=False)
    return sorted((f.rule_id, f.severity.name) for f in Scanner(config).scan(root).findings)


@requires_malicious_corpus
@pytest.mark.parametrize("transform", sorted(TRANSFORMS))
@pytest.mark.parametrize("sample", _samples(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_the_same_file_written_differently_reports_the_same(
    sample: pathlib.Path, transform: str, tmp_path: pathlib.Path
) -> None:
    expected = _findings(sample)
    rewritten = tmp_path / sample.name
    rewritten.mkdir(parents=True)
    _rewrite(sample, rewritten, TRANSFORMS[transform])
    assert _findings(rewritten) == expected


@requires_malicious_corpus
def test_the_corpus_is_actually_being_read() -> None:
    """The guard the corpus tests all carry: an empty parametrisation passes."""
    samples = _samples()
    assert len(samples) > 40, samples
    # From the MALICIOUS half. `glob("*/*")` sorts `benign` first, and a benign
    # sample reporting nothing is the point of it rather than a sign the corpus
    # went missing -- which is how the first draft of this guard failed.
    malicious = [s for s in samples if s.parent.name == "malicious"]
    assert malicious, samples
    assert any(_findings(s) for s in malicious[:5])
