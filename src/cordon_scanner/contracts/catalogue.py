"""What each subject kind is, how its id starts and which parts it takes (design spec 3.1).

The table the console and the backend read as JSON (`data/subject-kinds.json`, written from here by
`ContractData`): they never copy it. `SubjectParts` holds the vocabularies, so the choices listed
here are the ones `canonical_id` accepts.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.contracts.subjects import SubjectKind, SubjectParts


class SubjectCatalogue:
    """The ten kinds, in the order the spec lists them."""

    #: kind -> (id prefix, required parts, optional parts, what it is)
    TABLE: ClassVar[dict[SubjectKind, tuple[str, tuple[str, ...], tuple[str, ...], str]]] = {
        SubjectKind.PACKAGE: (
            "pkg:<type>/",
            ("ecosystem", "name"),
            ("namespace",),
            "a package of a public or private registry, as a package URL without a version",
        ),
        SubjectKind.CONTAINER_IMAGE: (
            "pkg:oci/",
            ("name",),
            ("registry",),
            "a container image, by repository and registry; the tag or digest is not part of the name",
        ),
        SubjectKind.CI_ACTION: (
            "ci:",
            ("host",),
            ("owner", "repo", "path", "project", "component"),
            "a CI action or component: owner, repo and optional path on GitHub; project and component on GitLab",
        ),
        SubjectKind.IDE_EXTENSION: (
            "ext:",
            ("marketplace", "publisher", "name"),
            (),
            "an editor extension, by marketplace, publisher and name",
        ),
        SubjectKind.AGENT_SKILL: (
            "skill:",
            ("source", "locator"),
            (),
            "an agent skill, by where it comes from and its locator",
        ),
        SubjectKind.MCP_SERVER: (
            "mcp:",
            ("transport", "locator"),
            ("registry",),
            "an MCP server, by how it is reached and its locator",
        ),
        SubjectKind.AI_MODEL: (
            "model:",
            ("provider", "name"),
            (),
            "a model, by provider and name (a Hugging Face model is a package URL of type huggingface)",
        ),
        SubjectKind.AGENT: ("agent:", ("product",), (), "an AI agent product"),
        SubjectKind.SOURCE_REPOSITORY: (
            "repo:",
            ("scm", "owner", "name"),
            (),
            "a source repository",
        ),
        SubjectKind.BUILD_ARTIFACT: (
            "art:",
            ("scope", "name"),
            (),
            "a build artifact of one tenant, by scope and name",
        ),
    }

    #: Parts that take one of a short list of values: part -> the values `canonical_id` accepts.
    CHOICES: ClassVar[dict[SubjectKind, dict[str, tuple[str, ...]]]] = {
        SubjectKind.CI_ACTION: {"host": ("github", "gitlab")},
        SubjectKind.IDE_EXTENSION: {"marketplace": SubjectParts.MARKETPLACES},
        SubjectKind.AGENT_SKILL: {"source": SubjectParts.SKILL_SOURCES},
        SubjectKind.MCP_SERVER: {"transport": SubjectParts.MCP_TRANSPORTS},
        SubjectKind.SOURCE_REPOSITORY: {"scm": SubjectParts.SOURCE_CONTROL},
    }

    @classmethod
    def as_json(cls) -> dict[str, Any]:
        """The table as the JSON document the other languages read."""
        return {
            "kinds": [
                {
                    "kind": kind.value,
                    "id_prefix": prefix,
                    "required": list(required),
                    "optional": list(optional),
                    "choices": {
                        part: list(values) for part, values in cls.CHOICES.get(kind, {}).items()
                    },
                    "description": text,
                }
                for kind, (prefix, required, optional, text) in cls.TABLE.items()
            ]
        }


__all__ = ["SubjectCatalogue"]
