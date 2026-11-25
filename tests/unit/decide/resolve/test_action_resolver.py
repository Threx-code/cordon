"""Row BP-3-5: a CI action's artifact is its commit, resolved from the tag through the SCM API.

`uses: actions/checkout@v4` resolves to the commit sha the tag points at; a moved tag gives a new artifact, never the old decision.
The SCM API is a fake that can move a tag and go down; `GitHubScm` is tested over a stub of the one HTTP call it makes.
"""

from __future__ import annotations

import hashlib

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.resolve.action import ActionResolver, GitHubScm
from cordon_scanner.decide.resolve.resolution import NotFound, SourceUnavailable

COMMIT_A = "0123456789abcdef0123456789abcdef01234567"
COMMIT_B = "fedcba9876543210fedcba9876543210fedcba98"


class FakeScm:
    def __init__(self, refs: dict[tuple[str, str, str], str] | None = None) -> None:
        self.refs = refs or {}
        self.calls: list[tuple[str, str, str]] = []
        self.down = False

    def commit_of(self, owner: str, repo: str, ref: str) -> str:
        self.calls.append((owner, repo, ref))
        if self.down:
            raise SourceUnavailable("no network")
        try:
            return self.refs[(owner.lower(), repo.lower(), ref)]
        except KeyError:
            raise NotFound(ref) from None


class TestATagIsResolvedToItsCommit:
    def test_checkout_v4_is_the_commit_the_tag_points_at(self) -> None:
        scm = FakeScm({("actions", "checkout", "v4"): COMMIT_A})
        found = ActionResolver.resolve("actions/checkout@v4", scm)
        assert found.resolved
        assert (found.kind, found.subject_id) == ("ci_action", "ci:github/actions/checkout")
        assert (found.version, found.commit) == ("v4", COMMIT_A)
        assert found.digest == ArtifactDigests.of_git_commit(COMMIT_A)

    def test_a_moved_tag_is_a_new_artifact_of_the_same_subject(self) -> None:
        scm = FakeScm({("actions", "checkout", "v4"): COMMIT_A})
        before = ActionResolver.resolve("actions/checkout@v4", scm)
        scm.refs[("actions", "checkout", "v4")] = COMMIT_B
        after = ActionResolver.resolve("actions/checkout@v4", scm)
        assert before.subject_id == after.subject_id
        assert before.digest != after.digest
        assert before.artifact().digest != after.artifact().digest

    def test_an_action_in_a_folder_of_a_repository(self) -> None:
        scm = FakeScm({("github", "codeql-action", "v3"): COMMIT_A})
        found = ActionResolver.resolve("github/codeql-action/analyze@v3", scm)
        assert found.subject_id == "ci:github/github/codeql-action/analyze"

    def test_the_owner_and_repository_fold_to_lower_case(self) -> None:
        scm = FakeScm({("actions", "checkout", "v4"): COMMIT_A})
        assert (
            ActionResolver.resolve("Actions/Checkout@v4", scm).subject_id
            == ActionResolver.resolve("actions/checkout@v4", scm).subject_id
        )


class TestAFullCommitNeedsNoCall:
    @pytest.mark.parametrize("commit", [COMMIT_A, COMMIT_A.upper(), "a" * 64])
    def test_a_commit_is_its_own_artifact(self, commit: str) -> None:
        scm = FakeScm()
        found = ActionResolver.resolve(f"actions/checkout@{commit}", scm)
        assert found.resolved and found.version is None
        assert found.commit == commit.lower()
        assert found.digest == ArtifactDigests.of_git_commit(commit)
        assert scm.calls == []

    def test_an_abbreviated_commit_is_asked_of_the_api(self) -> None:
        scm = FakeScm({("actions", "checkout", "0123456"): COMMIT_A})
        found = ActionResolver.resolve("actions/checkout@0123456", scm)
        assert found.commit == COMMIT_A and scm.calls == [("actions", "checkout", "0123456")]


class TestWhenTheApiCannotAnswer:
    def test_an_unreachable_api_leaves_the_name_unresolved_with_no_digest(self) -> None:
        scm = FakeScm()
        scm.down = True
        found = ActionResolver.resolve("actions/checkout@v4", scm)
        assert not found.resolved
        assert (found.reason, found.digest, found.commit) == ("source_unreachable", None, None)
        assert found.subject_id == "ci:github/actions/checkout" and found.version == "v4"
        assert found.artifact().digest is None
        assert found.evidence().unresolved is True

    def test_a_ref_that_does_not_exist(self) -> None:
        found = ActionResolver.resolve("actions/checkout@nope", FakeScm())
        assert (found.resolved, found.reason) == (False, "not_found")

    def test_an_answer_that_is_not_a_commit_is_no_answer(self) -> None:
        class Odd:
            def commit_of(self, owner: str, repo: str, ref: str) -> str:
                return "<html>rate limited</html>"

        assert ActionResolver.resolve("actions/checkout@v4", Odd()).reason == "source_unreachable"


class TestWhatIsNotARepositoryAction:
    @pytest.mark.parametrize(
        ("uses", "reason"),
        [
            ("./.github/actions/build", "local_action"),
            ("../shared/action", "local_action"),
            ("docker://alpine:3.20", "not_a_registry_package"),
            ("actions/checkout", "unparseable"),
            ("actions@v4", "unparseable"),
            ("a/b@c@d", "unparseable"),
            ("", "unparseable"),
            ("actions/check out@v4", "unparseable"),
        ],
    )
    def test_each_is_unresolved_with_its_reason_and_never_a_call(
        self, uses: str, reason: str
    ) -> None:
        scm = FakeScm()
        found = ActionResolver.resolve(uses, scm)
        assert (found.resolved, found.reason, found.digest) == (False, reason, None)
        assert scm.calls == []

    def test_the_subject_of_an_unreadable_reference_names_it_by_hash_only(self) -> None:
        found = ActionResolver.resolve("docker://private.example/secret-image:1", FakeScm())
        assert "secret-image" not in found.subject_id and found.subject_id.startswith(
            "ci:unparsed/"
        )
        again = ActionResolver.resolve("docker://private.example/secret-image:1", FakeScm())
        assert found.subject_id == again.subject_id


class TestTheGitHubApi:
    def test_it_asks_for_the_commit_alone_and_returns_it(self) -> None:
        seen: list[tuple[str, dict[str, str]]] = []

        def fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
            seen.append((url, headers))
            return 200, (COMMIT_A + "\n").encode()

        assert GitHubScm(fetch).commit_of("actions", "checkout", "v4") == COMMIT_A
        assert seen[0][0] == "https://api.github.com/repos/actions/checkout/commits/v4"
        assert seen[0][1]["Accept"] == "application/vnd.github.sha"

    @pytest.mark.parametrize("status", [404, 422])
    def test_no_such_ref_is_not_found(self, status: int) -> None:
        with pytest.raises(NotFound):
            GitHubScm(lambda url, headers: (status, b"")).commit_of("a", "b", "c")

    @pytest.mark.parametrize("status", [403, 429, 500, 502, 301])
    def test_any_other_answer_is_unavailable(self, status: int) -> None:
        with pytest.raises(SourceUnavailable):
            GitHubScm(lambda url, headers: (status, b"")).commit_of("a", "b", "c")

    def test_a_failure_to_ask_is_unavailable(self) -> None:
        def fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
            raise TimeoutError("timed out")

        with pytest.raises(SourceUnavailable):
            GitHubScm(fetch).commit_of("a", "b", "c")


class TestTheCommitDigestRule:
    def test_it_is_the_sha256_of_a_tag_and_the_lower_case_id(self) -> None:
        expected = "sha256:" + hashlib.sha256(b"git-commit\0" + COMMIT_A.encode()).hexdigest()
        assert ArtifactDigests.of_git_commit(COMMIT_A) == expected
        assert ArtifactDigests.of_git_commit(COMMIT_A.upper()) == expected
        assert expected == "sha256:eba49e065097a78aae6b82bda8cbe2b48c3553ccf3f9291ea9b8d33cee97e168"

    @pytest.mark.parametrize("bad", ["", "abc", "g" * 40, "a" * 41, "a" * 39])
    def test_a_text_that_is_not_a_commit_id_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_git_commit(bad)
