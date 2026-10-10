"""GitHub Actions: the actions and reusable workflows a repository's CI runs, as dependencies.

```
  .github/workflows/*.yml   steps' `uses: owner/repo[/path]@ref`, jobs' `uses:` of a reusable
                            workflow (`owner/repo/.github/workflows/x.yml@ref`), local actions
                            (`./path`), and container images (`docker://image:tag`)
  action.yml                an action: composite (its steps' `uses:`), docker (`runs.image`), or
                            JavaScript (`runs.main`, with `pre` and `post`)
```

`uses: owner/repo@ref` fetches and runs that repository's code with the job's token and secrets.
The version is only what the ref pins exactly: a full `vX.Y.Z` tag, or the `# vX.Y.Z` comment
Dependabot and Renovate keep beside a commit SHA. A moving major tag (`@v4`) is left unresolved --
read as version 4 it would match every advisory fixed in 4.x, though the tag has long since moved
past the fix. A commit SHA is the record's integrity: the registry check compares it with the
commit the commented tag names, so a comment that does not match its commit is caught.

Workflow misconfiguration (expression injection, permissions, secrets) is the CI detectors' job;
this module reads dependencies only.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent


class ActionReference:
    """One `uses:` value, classified."""

    FULL_VERSION: ClassVar[re.Pattern[str]] = re.compile(
        r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$"
    )
    SHA: ClassVar[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
    WORKFLOW: ClassVar[re.Pattern[str]] = re.compile(
        r"^[^/]+/[^/]+/\.github/workflows/[^/@]+\.ya?ml$"
    )

    @staticmethod
    def spec(pin: str, comment: str | None) -> tuple[str, str | None]:
        """`(spec, commit)`: an exact version when the ref pins one, else a spec no version
        reading accepts; the commit when the ref is a SHA."""
        exact = ActionReference.FULL_VERSION.match(pin)
        if exact:
            return exact.group(1), None
        if ActionReference.SHA.match(pin.lower()):
            stated = ActionReference.FULL_VERSION.match(comment or "")
            return (stated.group(1) if stated else f"sha:{pin.lower()}"), pin.lower()
        # A moving tag or a branch: whatever it points at today.
        return f"ref:{pin}", None

    @staticmethod
    def declare(ref: str, comment: str | None, field_name: str) -> DeclaredDependency | None:
        if "${{" in ref:
            # Chosen at run time from an expression: nothing to resolve here.
            return None
        if ref.startswith(("./", "../")):
            return DeclaredDependency(
                name=ref.rstrip("/"),
                spec=f"path:{ref}",
                scope=Scope.BUILD,
                field_name=f"{field_name} (local action)",
            )
        if ref.startswith("docker://"):
            from cordon_scanner.ecosystems.image import ImageReference

            # An image the job runs: read as the Docker client reads the reference, its digest the
            # pin it is.
            return ImageReference.declare(
                ref.removeprefix("docker://"),
                scope=Scope.BUILD,
                field_name=f"{field_name} (container)",
            )
        if "@" not in ref:
            return None
        target, _, pin = ref.rpartition("@")
        parts = [part for part in target.split("/") if part]
        if len(parts) < 2:
            return None
        repository = f"{parts[0]}/{parts[1]}"
        spec, commit = ActionReference.spec(pin, comment)
        reusable = bool(ActionReference.WORKFLOW.match(target))
        return DeclaredDependency(
            name=repository,
            spec=spec,
            scope=Scope.BUILD,
            field_name=f"{field_name} (reusable workflow)" if reusable else field_name,
            # An action in a subdirectory (`github/codeql-action/init`) or a reusable workflow is
            # the repository's code: advisories name the repository, the manifest names the path.
            alias=target if len(parts) > 2 else None,
            source=f"git+https://github.com/{repository}#{commit}" if commit else None,
            integrity=commit,
        )


class ActionsFile:
    USES: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?m)^[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*["']?(?P<ref>[^\s"'#]+)["']?[ \t]*(?:#[ \t]*(?P<comment>\S+))?"""
    )
    RUNS_USING: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?m)^[ \t]+using[ \t]*:[ \t]*["']?(?P<using>[A-Za-z0-9_\-]+)"""
    )
    IMAGE_KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?m)^[ \t]+(?P<key>container|image)[ \t]*:[ \t]*["']?(?P<image>(?!\$\{\{)[A-Za-z0-9][^\s"'#]*)["']?[ \t]*(?:#.*)?$"""
    )
    RUNS_IMAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?m)^[ \t]+image[ \t]*:[ \t]*["']?(?P<image>[^\s"'#]+)"""
    )

    JOB_KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"""^(?P<indent>[ \t]+)["']?[A-Za-z_][\w-]*["']?[ \t]*:[ \t]*(?:#.*)?$"""
    )

    @staticmethod
    def block_scalar_lines(text: str) -> set[int]:
        """Line numbers inside a YAML block scalar (`run: |`, `script: >-`): text, not keys."""
        inside: set[int] = set()
        opener: int | None = None
        for number, line in enumerate(text.splitlines()):
            indent = len(line) - len(line.lstrip())
            if opener is not None:
                if not line.strip() or indent > opener:
                    inside.add(number)
                    continue
                opener = None
            if re.search(r":[ \t]*[|>][+-]?[0-9]?[ \t]*(?:#.*)?$", line):
                opener = indent
        return inside

    @staticmethod
    def incomplete_job(text: str) -> str | None:
        """A job GitHub would refuse: one with neither `steps` nor `uses` (a reusable workflow) --
        what a workflow cut short ends with. Read from the text's indentation rather than through
        a YAML reader: a strict reader refuses valid workflows a lenient one would read, and
        neither is GitHub's."""
        lines = text.splitlines()
        start = next(
            (i for i, line in enumerate(lines) if re.match(r"^jobs[ \t]*:[ \t]*(?:#.*)?$", line)),
            None,
        )
        if start is None:
            return None
        body: list[str] = []
        for line in lines[start + 1 :]:
            if line.strip() and not line.startswith((" ", "\t", "#")):
                break  # the next top-level key
            body.append(line)
        keys = [
            i for i, line in enumerate(body) if line.strip() and not line.lstrip().startswith("#")
        ]
        if not keys:
            return "a workflow whose `jobs` holds no job"
        indent = len(body[keys[0]]) - len(body[keys[0]].lstrip())
        jobs: list[list[str]] = []
        for line in body:
            found = ActionsFile.JOB_KEY.match(line)
            if found and len(found.group("indent")) == indent:
                jobs.append([])
            elif jobs:
                jobs[-1].append(line)
        if not jobs:
            return None  # written in a form this reading does not follow; not judged
        for job in jobs:
            if not any(re.match(r"^[ \t]+(?:steps|uses)[ \t]*:", line) for line in job):
                return "a job with neither steps nor uses"
            if ActionsFile.incomplete_step(job):
                return "a step with neither uses nor run"
        return None

    @staticmethod
    def incomplete_step(job: list[str]) -> bool:
        """A step GitHub would refuse: every item under `steps:` is a mapping (`- name: ...`). A
        bare word (`- na`) is what a file cut inside a step's first key leaves. Which keys a step
        has is not judged -- GitHub keeps adding kinds of step (`wait`, `background`)."""
        start = next(
            (
                i
                for i, line in enumerate(job)
                if re.match(r"^[ \t]+steps[ \t]*:[ \t]*(?:#.*)?$", line)
            ),
            None,
        )
        if start is None:
            return False
        steps: list[list[str]] = []
        indent: int | None = None
        for line in job[start + 1 :]:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            current = len(line) - len(line.lstrip())
            item = re.match(r"^([ \t]*)-(?:[ \t]+|$)", line)
            if indent is None and item:
                indent = len(item.group(1))
            if indent is not None and current < indent:
                break
            if item and len(item.group(1)) == indent:
                steps.append([line])
            elif steps:
                steps[-1].append(line)
        # A YAML anchor may open a step (`- &CHECKOUT`, its keys below or after it) and an alias
        # may be one (`- *CHECKOUT`): koreader reuses its checkout step that way, and GitHub reads
        # anchors and aliases.
        mapping = re.compile(
            r"""^[ \t]*-(?:[ \t]*$"""
            r"""|[ \t]+[*&][\w-]+[ \t]*(?:#.*)?$"""
            r"""|[ \t]+(?:&[\w-]+[ \t]+)?(?:["'][^"']+["']|[\w-]+)[ \t]*:(?:[ \t]|$))"""
        )
        return any(not mapping.match(step[0]) for step in steps)

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        # A Windows checkout's `\r\n`. The block-scalar and `steps:` patterns below are written
        # against `\n`, and with CRLF a local action's steps and a job's container went unread.
        # Only line ends change: line numbers are counted, never columns.
        text = content.text.replace("\r\n", "\n")
        # A workflow is a file directly in `.github/workflows/`: GitHub runs no file in a folder
        # below it, and elixir keeps composite actions there (`.github/workflows/ort/action.yml`),
        # which were refused as workflows without `jobs`.
        workflow = re.search(r"(?:^|/)\.github/workflows/[^/]+$", content.path) is not None
        if workflow and not re.search(r"(?m)^jobs[ \t]*:", text):
            return BaseEcosystem._err(content, ecosystem, "a workflow without `jobs`")
        if not workflow and not re.search(r"(?m)^runs[ \t]*:", text):
            return BaseEcosystem._err(content, ecosystem, "an action.yml without `runs`")
        if workflow and (incomplete := ActionsFile.incomplete_job(text)):
            return BaseEcosystem._err(content, ecosystem, incomplete)
        declared: list[DeclaredDependency] = []
        seen: set[tuple[str, str, str | None]] = set()
        scalars = ActionsFile.block_scalar_lines(text)
        for match in ActionsFile.USES.finditer(text):
            if text.count("\n", 0, match.start()) in scalars:
                # Text inside a `run: |` script (one that writes a workflow, say), not a step.
                continue
            # A job's `uses:` (a reusable workflow) and a step's are both read; the reference itself
            # says which kind it is.
            dependency = ActionReference.declare(match.group("ref"), match.group("comment"), "uses")
            if dependency is None:
                continue
            key = (dependency.name.lower(), dependency.spec, dependency.alias)
            if key in seen:
                continue
            seen.add(key)
            declared.append(dependency)
        if workflow:
            # A job's `container:` and its `services:` run as images on the runner.
            for found in ActionsFile.IMAGE_KEY.finditer(text):
                if text.count("\n", 0, found.start()) in scalars:
                    continue
                value = found.group("image")
                reference = value if value.startswith("docker://") else f"docker://{value}"
                container = ActionReference.declare(reference, None, found.group("key"))
                if container is not None and (container.name, container.spec) not in {
                    (d.name, d.spec) for d in declared
                }:
                    declared.append(container)
        sources: list[str] = []
        hooks: list[Hook] = []
        if not workflow:
            using = ActionsFile.RUNS_USING.search(text)
            kind = using.group("using") if using else "unknown"
            required = {"docker": "image", "composite": "steps"}.get(
                kind, "main" if kind.startswith("node") else None
            )
            if required and not re.search(rf"(?m)^[ \t]+{required}[ \t]*:", text):
                # GitHub refuses an action without what its kind runs: what a file cut short is.
                return BaseEcosystem._err(
                    content, ecosystem, f"a {kind} action without `{required}`"
                )
            if kind == "composite" and not re.search(
                r"(?ms)^[ \t]+steps[ \t]*:[ \t]*(?:\[[ \t]*\S|(?:#[^\n]*)?\n(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]+-)",
                text,
            ):
                return BaseEcosystem._err(
                    content, ecosystem, "a composite action whose steps hold no step"
                )
            # A JavaScript action's main, pre and post scripts (and a container action's
            # entrypoint) run in every job that uses the action, with that job's token.
            for stage in ("pre", "main", "post", "entrypoint", "pre-entrypoint", "post-entrypoint"):
                script = re.search(
                    rf"""(?m)^[ \t]+{stage}[ \t]*:[ \t]*["']?(?P<script>[^\s"'#]+)""", text
                )
                if script and (kind.startswith("node") or kind == "docker"):
                    hooks.append(
                        Hook(
                            kind="ci",
                            path=content.path,
                            name=f"runs.{stage}",
                            command=script.group("script"),
                            ecosystem=ecosystem,
                        )
                    )
            sources.append(
                f"{'composite' if kind == 'composite' else 'container' if kind == 'docker' else 'JavaScript' if kind.startswith('node') else kind} action ({kind})"
            )
            image = ActionsFile.RUNS_IMAGE.search(text) if kind == "docker" else None
            if image is not None:
                value = image.group("image")
                if value.startswith("docker://"):
                    container = ActionReference.declare(value, None, "runs.image")
                    if container is not None:
                        declared.append(container)
                elif value.rpartition("/")[2] == "Dockerfile":
                    # Built from a Dockerfile in the action's repository: read as source.
                    sources.append(f"container built from {value}")
                else:
                    # GitHub takes `docker://<image>` or a path to a file named Dockerfile, nothing
                    # else: a value that is neither is a file cut short, or not an action GitHub runs.
                    return BaseEcosystem._err(
                        content,
                        ecosystem,
                        "a container action image that is neither docker:// nor a Dockerfile",
                    )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            dependencies=tuple(declared),
            hooks=tuple(hooks),
            sources=tuple(sources),
        )


class GitHubActionsEcosystem(BaseEcosystem):
    """The actions and reusable workflows a repository's CI runs."""

    id = "actions"
    purl_type = "githubactions"
    manifest_globs: tuple[str, ...] = (
        "**/.github/workflows/*.yml",
        "**/.github/workflows/*.yaml",
        "**/action.yml",
        "**/action.yaml",
    )
    lockfile_globs: tuple[str, ...] = ()
    registry_hosts: frozenset[str] = frozenset({"github.com"})
    records_integrity = False
    """A tag records no hash; a commit SHA pins one, and is kept as the record's integrity."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        """An action's repository on github.com is where actions come from: the registry."""
        if url and re.match(r"^(?:git\+)?https://github\.com/", url):
            return True
        return super().is_registry_host(url)

    def parse_manifest(self, content: FileContent) -> Manifest:
        return ActionsFile.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return LockGraph(path=content.path, ecosystem=self.id)


__all__ = ["ActionReference", "ActionsFile", "GitHubActionsEcosystem"]
