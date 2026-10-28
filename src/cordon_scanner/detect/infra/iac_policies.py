"""The infrastructure policy table.

Data, not code. Every entry is one control over one kind of resource, carrying
the two samples that decide whether it works: one block it must report and one
it must not. `tests/unit/detect/infra/test_iac_policies.py` runs both for every policy on
every push, so a policy that stops matching fails the build rather than quietly
reporting nothing -- the same discipline the YAML rule packs get from
`cordon-scanner rules test`.

Most entries come from a *family*: one control expressed once and applied to
every resource that has it. "Encryption at rest is not enabled" is one sentence
and thirty resources, and writing it thirty times would mean thirty chances to
write it differently. The family builders below take the resource, the attribute
that provider actually names, and a severity, and produce the policy, its
identifier, its message and its samples from that row. Adding a resource is a
line of data.

Two shapes, and the distinction is what makes this detector worth having:

`require`
    The block does not say something it must. `storage_encrypted = true` absent
    from an `aws_db_instance` means the database is unencrypted, because that is
    the provider's default -- a fact no file-level regex can see, since there is
    nothing written down to match.

`forbid`
    The block says something insecure outright: `acl = "public-read"`,
    `privileged: true`, `container_access_type = "container"`.

A `require` policy is only correct when the attribute belongs to the block it is
required in. Where a provider moved a setting into its own resource -- S3
encryption, S3 public access -- the policy is written against that resource
instead, because requiring it inside the bucket would report every modern
configuration as insecure.
"""

from __future__ import annotations

from typing import Final

from cordon_scanner.detect.infra.cloud_policies import (
    AZURE_NATIVE,
    CFN,
    IDENTITY,
    TERRAFORM_HYGIENE,
)
from cordon_scanner.detect.infra.data_protection_policies import (
    AT_REST,
    AT_REST_EXTRA,
    AT_REST_NON_BOOLEAN,
    BACKUP,
    DELETION_PROTECTION,
    IN_TRANSIT,
    LOGGING,
    LOGGING_EXTRA,
    OPEN_STORAGE,
    PUBLIC_ACCESS_BLOCK,
    PUBLIC_TRUE,
    WEAK_TLS,
)
from cordon_scanner.detect.infra.iac import IacPolicy
from cordon_scanner.detect.infra.plaintext_policies import PLAINTEXT
from cordon_scanner.detect.infra.policy_terms import HIGH, PresenceGate
from cordon_scanner.detect.infra.workload_policies import (
    COMPOSE,
    DEPRECATED_RUNTIMES,
    DOCKERFILE,
    K8S,
    K8S_EXTRA,
    WORKLOAD_KINDS,
)
from cordon_scanner.foundation import references
from cordon_scanner.foundation.models import Category, Confidence, Severity


class CuratedPolicies:
    """The hand-written infrastructure policies, by control family."""

    @staticmethod
    def _slug(resource: str) -> str:
        """`aws_db_instance` -> `AWS_DB_INSTANCE`, for a readable rule id."""
        return resource.replace(":", "_").replace("-", "_").replace(".", "_").upper()

    @staticmethod
    def _require_true(
        *,
        family: str,
        resource: str,
        attribute: str,
        severity: Severity,
        subject: str,
        consequence: str,
        extra_body: str = "",
        unless: tuple[str, ...] = (),
    ) -> IacPolicy:
        """A boolean the provider defaults to the insecure value.

        Fires when the attribute is absent as well as when it is `false`, because
        those are the same deployment. The sample pair is generated from the row, so
        a policy cannot be added without one that proves it and one that clears it.
        """
        return IacPolicy(
            id=f"POLICY.IAC.{family}.{CuratedPolicies._slug(resource)}.001",
            title=f"{resource}: {subject} is not enabled",
            message=(
                f"{subject} is not enabled on this resource. {consequence} The "
                f"provider's default for `{attribute}` is the insecure one, so a "
                f"block that does not mention it is a block that does not have it."
            ),
            remediation=f"Set `{attribute} = true` on this resource.",
            severity=severity,
            confidence=Confidence.HIGH,
            category=Category.POLICY,
            resources=(resource,),
            require=(rf"{attribute}\s*=\s*true",),
            unless=unless,
            bad=f'  name = "example"\n{extra_body}',
            good=f'  name = "example"\n  {attribute} = true\n{extra_body}',
        )

    @staticmethod
    def _forbid_value(
        *,
        family: str,
        resource: str,
        attribute: str,
        pattern: str,
        severity: Severity,
        title: str,
        message: str,
        remediation: str,
        bad: str,
        good: str,
        category: Category = Category.POLICY,
        confidence: Confidence = Confidence.HIGH,
        unless: tuple[str, ...] = (),
    ) -> IacPolicy:
        """A value that is insecure where it is written."""
        return IacPolicy(
            id=f"{'SUSPECT' if category is Category.SUSPICIOUS else 'POLICY'}"
            f".IAC.{family}.{CuratedPolicies._slug(resource)}.001",
            title=title,
            message=message,
            remediation=remediation,
            severity=severity,
            confidence=confidence,
            category=category,
            resources=(resource,),
            forbid=(pattern,),
            unless=unless,
            bad=bad,
            good=good,
        )

    @staticmethod
    def _at_rest_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, severity in AT_REST:
            if attribute in AT_REST_NON_BOOLEAN:
                policies.append(
                    IacPolicy(
                        id=f"POLICY.IAC.ENCRYPT_AT_REST.{CuratedPolicies._slug(resource)}.001",
                        title=f"{resource}: encryption at rest is not configured",
                        message=(
                            f"No `{attribute}` is configured on this resource. {_AT_REST_CONSEQUENCE}"
                        ),
                        remediation=(
                            f"Set `{attribute}` on this resource, referring to a key you "
                            f"control rather than relying on the platform default."
                        ),
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        category=Category.POLICY,
                        resources=(resource,),
                        require=(rf"{attribute}\s*[=:]",),
                        bad='  name = "example"\n',
                        good=f'  name = "example"\n  {attribute} = aws_kms_key.this.arn\n',
                    )
                )
                continue
            policies.append(
                CuratedPolicies._require_true(
                    family="ENCRYPT_AT_REST",
                    resource=resource,
                    attribute=attribute,
                    severity=severity,
                    subject="Encryption at rest",
                    consequence=_AT_REST_CONSEQUENCE,
                )
            )
        return policies

    @staticmethod
    def _in_transit_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, severity in IN_TRANSIT:
            if attribute in {"ssl_mode", "policy"}:
                continue
            policies.append(
                CuratedPolicies._require_true(
                    family="ENCRYPT_IN_TRANSIT",
                    resource=resource,
                    attribute=attribute,
                    severity=severity,
                    subject="Encryption in transit",
                    consequence=_IN_TRANSIT_CONSEQUENCE,
                )
            )
        return policies

    @staticmethod
    def _public_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, severity in PUBLIC_TRUE:
            # Two spellings of the same setting: a boolean on most resources, and
            # the word "Enabled" on the SageMaker one.
            worded = attribute == "direct_internet_access"
            insecure = '"Enabled"' if worded else "true"
            secure = '"Disabled"' if worded else "false"
            policies.append(
                CuratedPolicies._forbid_value(
                    family="PUBLIC_ACCESS",
                    resource=resource,
                    attribute=attribute,
                    pattern=rf"{attribute}\s*=\s*" + ('"Enabled"' if worded else "true"),
                    severity=severity,
                    title=f"{resource}: reachable from the public internet",
                    message=f"`{attribute}` is set on this resource. {_PUBLIC_CONSEQUENCE}",
                    remediation=(
                        f"Set `{attribute} = {secure}` and reach the resource over a "
                        f"private endpoint or a peered network."
                    ),
                    bad=f'  name = "example"\n  {attribute} = {insecure}\n',
                    good=f'  name = "example"\n  {attribute} = {secure}\n',
                    category=Category.SUSPICIOUS,
                )
            )
        return policies

    @staticmethod
    def _presence_policies(
        rows: tuple[tuple[str, str, Severity] | tuple[str, str, Severity, PresenceGate], ...],
        *,
        family: str,
        subject: str,
        consequence: str,
        remediation: str,
    ) -> list[IacPolicy]:
        """One policy per row, fired by the attribute being absent from the block.

        A row may carry a fourth element gating the policy: the patterns the block
        must also contain, and a line to put in the samples so they satisfy it. It
        is there for the resources where the attribute only matters in one mode --
        an SSM parameter needs a key when it holds a secret and not when it holds a
        region name -- and asking for it unconditionally reports the majority that
        are fine.
        """
        policies: list[IacPolicy] = []
        for row in rows:
            resource, attribute, severity = row[0], row[1], row[2]
            gate: PresenceGate | None = row[3] if len(row) > 3 else None
            context = f"  {gate.sample}\n" if gate else ""
            policies.append(
                IacPolicy(
                    id=f"POLICY.IAC.{family}.{CuratedPolicies._slug(resource)}_{attribute.upper()}.001",
                    title=f"{resource}: {subject} is not configured",
                    message=(
                        f"This resource does not configure `{attribute}`. "
                        f"{gate.qualifier + ' ' if gate else ''}{consequence}"
                    ),
                    remediation=remediation.format(attribute=attribute),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    category=Category.POLICY,
                    resources=(resource,),
                    require=(rf"{attribute}\s*[=:]",),
                    when=gate.when if gate else (),
                    bad=f'  name = "example"\n{context}',
                    good=f'  name = "example"\n{context}  {attribute} = 7\n',
                )
            )
        return policies

    @staticmethod
    def _zero_retention_policies() -> list[IacPolicy]:
        """Retention explicitly set to nothing, which is the same as no backup."""
        policies: list[IacPolicy] = []
        for resource, attribute, severity in BACKUP:
            policies.append(
                CuratedPolicies._forbid_value(
                    family="BACKUP_DISABLED",
                    resource=resource,
                    attribute=attribute,
                    pattern=rf"{attribute}\s*=\s*0\b",
                    severity=severity,
                    title=f"{resource}: backups are switched off",
                    message=(
                        f"`{attribute} = 0` disables automated backups entirely. A "
                        f"deletion, a corruption or a ransom event leaves nothing to "
                        f"restore from, and the setting reads as configured rather than "
                        f"forgotten."
                    ),
                    remediation=f"Set `{attribute}` to the number of days the data is worth.",
                    bad=f'  name = "example"\n  {attribute} = 0\n',
                    good=f'  name = "example"\n  {attribute} = 7\n',
                )
            )
        return policies

    @staticmethod
    def _open_storage_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, pattern, severity, bad, good in OPEN_STORAGE:
            policies.append(
                CuratedPolicies._forbid_value(
                    family="PUBLIC_STORAGE",
                    resource=resource,
                    attribute=attribute,
                    pattern=pattern,
                    severity=severity,
                    title=f"{resource}: storage is readable by anyone",
                    message=(
                        "This grants read access to the whole internet. Object storage "
                        "left open is the single most common cause of a public data "
                        "breach, and it is found by continuous automated scanning within "
                        "hours rather than by anyone who meant to look."
                    ),
                    remediation=(
                        "Grant access to named principals, and serve public content "
                        "through a CDN origin identity rather than by opening the bucket."
                    ),
                    bad=bad,
                    good=good,
                    category=Category.SUSPICIOUS,
                )
            )
        return policies

    @staticmethod
    def _public_access_block_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for attribute in PUBLIC_ACCESS_BLOCK:
            policies.append(
                IacPolicy(
                    id=f"SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.{attribute.upper()}.001",
                    title=f"aws_s3_bucket_public_access_block: {attribute} is off",
                    message=(
                        f"`{attribute}` is false, so the account-level guard that exists "
                        f"to stop a bucket becoming public does not apply here. The "
                        f"resource is named for blocking public access and is configured "
                        f"not to."
                    ),
                    remediation=f"Set `{attribute} = true` unless the bucket serves public content deliberately.",
                    severity=HIGH,
                    confidence=Confidence.HIGH,
                    category=Category.SUSPICIOUS,
                    resources=("aws_s3_bucket_public_access_block",),
                    forbid=(rf"{attribute}\s*=\s*false",),
                    bad=f"  bucket = aws_s3_bucket.b.id\n  {attribute} = false\n",
                    good=f"  bucket = aws_s3_bucket.b.id\n  {attribute} = true\n",
                )
            )
        return policies

    @staticmethod
    def _weak_tls_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, pattern, severity, bad, good in WEAK_TLS:
            policies.append(
                CuratedPolicies._forbid_value(
                    family="WEAK_TLS",
                    resource=resource,
                    attribute=attribute,
                    pattern=pattern,
                    severity=severity,
                    title=f"{resource}: obsolete TLS version accepted",
                    message=(
                        "This accepts TLS 1.0 or 1.1. Both are withdrawn, both have "
                        "practical attacks against them, and a client that negotiates one "
                        "gets a connection that looks encrypted in every log while not "
                        "being worth the label."
                    ),
                    remediation="Require TLS 1.2 or later.",
                    bad=bad,
                    good=good,
                )
            )
        return policies

    @staticmethod
    def _k8s_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for (
            family,
            attribute,
            pattern,
            severity,
            category,
            subject,
            consequence,
            fix,
            sample,
        ) in K8S:
            if family in ALREADY_REPORTED:
                continue
            prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
            bad_value = {
                "capabilities": "        capabilities:\n          add: [SYS_ADMIN]\n",
                "readOnlyRootFilesystem": "        readOnlyRootFilesystem: false\n",
                "image": "      image: nginx:latest\n",
                "runAsUser": "        runAsUser: 0\n",
                "hostPath": "      volumes:\n        - hostPath:\n            path: /\n",
            }.get(sample, f"        {attribute}: true\n")
            good_value = {
                "capabilities": "        capabilities:\n          drop: [ALL]\n",
                "image": "      image: nginx@sha256:aaaa\n",
                "runAsUser": "        runAsUser: 1001\n",
                "hostPath": "      volumes:\n        - emptyDir: {}\n",
                "readOnlyRootFilesystem": "        readOnlyRootFilesystem: true\n",
            }.get(sample, f"        {attribute}: false\n")
            policies.append(
                IacPolicy(
                    id=f"{prefix}.K8S.{family}.001",
                    title=f"Kubernetes workload: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    resources=WORKLOAD_KINDS,
                    forbid=(pattern,),
                    bad=f"kind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n{bad_value}",
                    good=f"kind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n{good_value}",
                )
            )
        return policies

    @staticmethod
    def _compose_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for family, pattern, bad_line, severity, subject, consequence, fix, good_line in COMPOSE:
            if family in ALREADY_REPORTED:
                continue
            policies.append(
                IacPolicy(
                    id=f"SUSPECT.COMPOSE.{family}.001",
                    title=f"Compose service: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=Category.SUSPICIOUS,
                    resources=("compose:service",),
                    forbid=(pattern,),
                    bad=f"  app:\n    image: example\n    {bad_line}\n",
                    good=f"  app:\n    image: example\n    {good_line}\n",
                )
            )
        return policies

    @staticmethod
    def _cfn_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for (
            family,
            resource,
            pattern,
            severity,
            category,
            subject,
            consequence,
            fix,
            bad,
            good,
        ) in CFN:
            prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
            short = resource.split("::")[-1].upper()
            policies.append(
                IacPolicy(
                    id=f"{prefix}.CFN.{family}.{short}.001",
                    title=f"{resource.removeprefix('cfn:')}: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    resources=(resource,),
                    forbid=(pattern,),
                    bad=bad,
                    good=good,
                )
            )
        return policies

    @staticmethod
    def _deprecated_runtime_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for resource, attribute, pattern, severity, bad, good in DEPRECATED_RUNTIMES:
            policies.append(
                CuratedPolicies._forbid_value(
                    family="DEPRECATED_RUNTIME",
                    resource=resource,
                    attribute=attribute,
                    pattern=pattern,
                    severity=severity,
                    title=f"{resource}: the runtime is out of support",
                    message=(
                        "This runtime no longer receives security updates from the "
                        "platform. Nothing fails, and the function keeps running on an "
                        "interpreter whose known vulnerabilities will not be fixed."
                    ),
                    remediation="Move to a supported runtime version.",
                    bad=bad,
                    good=good,
                )
            )
        return policies

    @staticmethod
    def _dockerfile_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for (
            family,
            _instruction,
            pattern,
            severity,
            category,
            subject,
            consequence,
            fix,
            bad,
            good,
        ) in DOCKERFILE:
            prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
            # `NO_HEALTHCHECK` is the one that fires on absence; the rest fire on
            # something written down.
            absent = family == "NO_HEALTHCHECK"
            policies.append(
                IacPolicy(
                    id=f"{prefix}.DOCKERFILE.{family}.001",
                    title=f"Dockerfile: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    resources=("dockerfile",),
                    forbid=() if absent else (pattern,),
                    require=(pattern,) if absent else (),
                    # A health check is about an image that serves something. A
                    # command-line image has nothing to check, and requiring one of
                    # it reports a control that would do nothing.
                    when=(r"(?m)^\s*EXPOSE\s",) if family == "NO_HEALTHCHECK" else (),
                    bad=bad,
                    good=good,
                )
            )
        return policies

    @staticmethod
    def _k8s_extra_policies() -> list[IacPolicy]:
        policies: list[IacPolicy] = []
        for (
            family,
            _attribute,
            pattern,
            severity,
            category,
            subject,
            consequence,
            fix,
            sample,
        ) in K8S_EXTRA:
            prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
            absent = family.startswith("NO_") or family == "DEFAULT_SERVICE_ACCOUNT"
            body = "kind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n"
            samples = {
                "limits": (
                    body + "      resources:\n        requests:\n          cpu: 100m\n",
                    body + "      resources:\n        limits:\n          cpu: 500m\n",
                ),
                "serviceAccountName": (
                    body,
                    "kind: Pod\nmetadata:\n  name: example\nspec:\n  serviceAccountName: app\n"
                    "  containers:\n    - name: app\n",
                ),
                "hostPort": (
                    body + "      ports:\n        - hostPort: 8080\n",
                    body + "      ports:\n        - containerPort: 8080\n",
                ),
                "runAsNonRoot": (
                    body,
                    body + "      securityContext:\n        runAsNonRoot: true\n",
                ),
                "seccompProfile": (
                    body,
                    body
                    + "      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n",
                ),
                "env": (
                    body + "      env:\n        - name: API_TOKEN\n          value: sk-live-aaaa\n",
                    body + "      env:\n        - name: API_TOKEN\n          valueFrom:\n"
                    "            secretKeyRef:\n              name: creds\n              key: token\n",
                ),
            }[sample]
            policies.append(
                IacPolicy(
                    id=f"{prefix}.K8S.{family}.001",
                    title=f"Kubernetes workload: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.MEDIUM if absent else Confidence.HIGH,
                    category=category,
                    resources=WORKLOAD_KINDS,
                    forbid=() if absent else (pattern,),
                    require=(pattern,) if absent else (),
                    bad=samples[0],
                    good=samples[1],
                )
            )
        return policies

    @staticmethod
    def _azure_native_policies() -> list[IacPolicy]:
        """The same controls, for the two formats Azure itself publishes."""
        policies: list[IacPolicy] = []
        for (
            family,
            resource,
            attribute,
            pattern,
            severity,
            category,
            subject,
            consequence,
            fix,
            sample_pair,
        ) in AZURE_NATIVE:
            insecure, secure = sample_pair.split("|")
            prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
            short = resource.replace("Microsoft.", "").replace("/", "_").replace("*", "ANY").upper()
            # Two conditions the pattern cannot carry on its own. A rule that
            # denies, or one that governs outbound traffic, admits nothing -- and an
            # administrative port is what makes an open source prefix a finding
            # rather than the description of a public web tier.
            when = (
                (
                    r"access\"?\s*:\s*['\"]Allow['\"]",
                    r"direction\"?\s*:\s*['\"]Inbound['\"]",
                    r"destinationPortRange\w*\"?\s*:\s*\[?\s*['\"]"
                    r"(?:\*|22|3389|1433|3306|5432|6379|27017|5984|9200|11211|23|21)",
                )
                if family == "OPEN_INGRESS"
                else ()
            )
            policies.append(
                IacPolicy(
                    id=f"{prefix}.AZURE.{family}.{short}_{attribute.upper()}.001",
                    title=f"{resource}: {subject}",
                    message=consequence,
                    remediation=fix,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    resources=(f"azure:{resource}",),
                    forbid=(pattern,),
                    when=when,
                    bad=(
                        "  name: 'example'\n  properties: {\n"
                        "    access: 'Allow'\n    direction: 'Inbound'\n"
                        "    destinationPortRange: '22'\n"
                        f"    {attribute}: {insecure}\n  }}\n"
                        if when
                        else f"  name: 'example'\n  properties: {{\n    {attribute}: {insecure}\n  }}\n"
                    ),
                    good=(
                        "  name: 'example'\n  properties: {\n"
                        "    access: 'Allow'\n    direction: 'Inbound'\n"
                        "    destinationPortRange: '22'\n"
                        f"    {attribute}: {secure}\n  }}\n"
                        if when
                        else f"  name: 'example'\n  properties: {{\n    {attribute}: {secure}\n  }}\n"
                    ),
                )
            )
        return policies

    @staticmethod
    def references_for(policy_id: str) -> tuple[str, ...]:
        """The references a policy inherits from its control family."""
        parts = policy_id.split(".")
        return FAMILY_REFERENCES.get(parts[2], ()) if len(parts) > 2 else ()


_AT_REST_CONSEQUENCE = (
    "The data is stored unencrypted, so anything that reaches the underlying "
    "storage -- a snapshot copied to another account, a disk reattached, an "
    "operator with platform access -- reads it directly."
)

_IN_TRANSIT_CONSEQUENCE = (
    "Traffic to this resource is readable and modifiable by anything on the "
    "path between the client and it, which includes every network the provider "
    "routes it over."
)

_PUBLIC_CONSEQUENCE = (
    "The resource is reachable from the public internet, so its own "
    "authentication is the only thing between an anonymous scanner and the data "
    "behind it -- and scanning for exactly this is continuous and automated."
)

_LOGGING_CONSEQUENCE = (
    "Nothing records what happened here, so an incident involving this resource "
    "cannot be reconstructed afterwards -- and the absence is only ever "
    "discovered when somebody goes looking for the records."
)

#: Controls `detect/config_files.py` already reports on these same files.
#: `SUSPECT.IAC.PRIVILEGED.001` and `SUSPECT.IAC.HOST_MOUNT.001` fire on a
#: privileged container and a host mount wherever they appear, so building a
#: second policy for them would mean two findings about one line.
ALREADY_REPORTED = frozenset({"PRIVILEGED", "HOST_PATH", "DOCKER_SOCKET"})

CURATED: tuple[IacPolicy, ...] = tuple(
    CuratedPolicies._at_rest_policies()
    + CuratedPolicies._in_transit_policies()
    + CuratedPolicies._public_policies()
    + CuratedPolicies._presence_policies(
        LOGGING,
        family="LOGGING",
        subject="audit logging",
        consequence=_LOGGING_CONSEQUENCE,
        remediation="Configure `{attribute}` so this resource's activity is recorded.",
    )
    + CuratedPolicies._presence_policies(
        BACKUP,
        family="BACKUP",
        subject="a backup retention period",
        consequence=(
            "Nothing is retained, so a deletion or a corruption is permanent -- and "
            "the first time anybody checks is after one."
        ),
        remediation="Set `{attribute}` to the number of days the data is worth.",
    )
    + CuratedPolicies._presence_policies(
        DELETION_PROTECTION,
        family="DELETION_PROTECTION",
        subject="deletion protection",
        consequence=(
            "The resource can be destroyed by one apply, one console click or one "
            "credential that should not have had the permission."
        ),
        remediation="Set `{attribute} = true` on anything holding state you cannot rebuild.",
    )
    + CuratedPolicies._zero_retention_policies()
    + CuratedPolicies._open_storage_policies()
    + CuratedPolicies._public_access_block_policies()
    + CuratedPolicies._weak_tls_policies()
    + list(PLAINTEXT)
    + CuratedPolicies._k8s_policies()
    + CuratedPolicies._compose_policies()
    + CuratedPolicies._cfn_policies()
    + CuratedPolicies._presence_policies(
        AT_REST_EXTRA,
        family="ENCRYPT_AT_REST",
        subject="a customer-managed key",
        consequence=_AT_REST_CONSEQUENCE,
        remediation="Set `{attribute}` to a key you control.",
    )
    + CuratedPolicies._presence_policies(
        LOGGING_EXTRA,
        family="LOGGING",
        subject="audit logging",
        consequence=_LOGGING_CONSEQUENCE,
        remediation="Configure `{attribute}` so this resource's activity is recorded.",
    )
    + CuratedPolicies._deprecated_runtime_policies()
    + list(TERRAFORM_HYGIENE)
    + CuratedPolicies._dockerfile_policies()
    + CuratedPolicies._k8s_extra_policies()
    + list(IDENTITY)
    + CuratedPolicies._azure_native_policies()
)

#: Where each control family's claim is written down by somebody else.
#:
#: Keyed by the family segment of a policy id -- `POLICY.IAC.CMEK.…` is `CMEK`
#: -- because the family IS the claim: every policy in it says the same thing
#: about a different resource, so they share an authority and there are seventy
#: of these rather than 1,081.
#:
#: A family absent from this table gets no reference rather than a guessed one.
#: A link that rots reads as authority and delivers a 404, which is worse than
#: saying nothing.
FAMILY_REFERENCES: Final[dict[str, tuple[str, ...]]] = {
    "ADD_REMOTE": (references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
    "ADMIN_ENABLED": (references.IMPROPER_PRIVILEGE_MANAGEMENT,),
    "AUTOMOUNT_TOKEN": (references.KUBERNETES_POD_SECURITY, references.EXPOSED_RESOURCE),
    "BACKUP": (references.MISSING_BACKUP,),
    "BACKUP_DISABLED": (references.MISSING_BACKUP,),
    "BOOT_INTEGRITY": (references.INSUFFICIENT_VERIFICATION,),
    "CMEK": (references.MISSING_ENCRYPTION, references.AWS_KMS, references.GOOGLE_CMEK),
    "CREDENTIALS_INLINE": (references.HARDCODED_CREDENTIALS,),
    "DANGEROUS_CAPABILITY": (
        references.KUBERNETES_POD_SECURITY,
        references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
    ),
    "DEFAULT_SERVICE_ACCOUNT": (references.KUBERNETES_POD_SECURITY,),
    "DELETION_PROTECTION": (references.INSECURE_DEFAULT,),
    "DEPRECATED_RUNTIME": (references.INSECURE_DEFAULT,),
    "ENCRYPT_AT_REST": (references.CLEARTEXT_STORAGE, references.MISSING_ENCRYPTION),
    "ENCRYPT_IN_TRANSIT": (references.CLEARTEXT_TRANSMISSION,),
    "FORCE_DESTROY": (references.INSECURE_DEFAULT,),
    "GOVERNANCE": (references.IMPROPER_ACCESS_CONTROL,),
    "HOST_IPC": (references.KUBERNETES_POD_SECURITY,),
    "HOST_NAMESPACE": (references.KUBERNETES_POD_SECURITY,),
    "HOST_NETWORK": (references.KUBERNETES_POD_SECURITY,),
    "HOST_PID": (references.KUBERNETES_POD_SECURITY,),
    "HOST_PORT": (references.KUBERNETES_POD_SECURITY,),
    "IAM_WILDCARD": (references.IMPROPER_ACCESS_CONTROL,),
    "IMDSV1": (references.AWS_IMDSV2, references.MISSING_AUTHENTICATION),
    "KEY_ROTATION": (references.WEAK_CRYPTO, references.AWS_KMS),
    "LATEST_TAG": (references.DOCKER_BUILD_BEST_PRACTICE, references.INSUFFICIENT_VERIFICATION),
    "LEGACY_ABAC": (references.IMPROPER_ACCESS_CONTROL,),
    "LOCAL_EXEC": (references.CODE_INJECTION,),
    "EXTERNAL_PROGRAM": (references.CODE_INJECTION,),
    "LOGGING": (references.INSUFFICIENT_LOGGING,),
    "MFA": (references.MISSING_AUTHENTICATION,),
    "MUTABLE_TAGS": (references.INSUFFICIENT_VERIFICATION,),
    "NETWORK_DEFAULT_ALLOW": (references.IMPROPER_ACCESS_CONTROL,),
    "NO_AUTH": (references.MISSING_AUTHENTICATION,),
    "NO_HEALTHCHECK": (references.DOCKER_BUILD_BEST_PRACTICE,),
    "NO_MFA": (references.MISSING_AUTHENTICATION,),
    "NO_RESOURCE_LIMITS": (references.UNCONTROLLED_RESOURCE, references.KUBERNETES_POD_SECURITY),
    "NO_RUN_AS_NON_ROOT": (
        references.KUBERNETES_POD_SECURITY,
        references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
    ),
    "NO_SECCOMP": (references.KUBERNETES_POD_SECURITY,),
    "OPEN_INGRESS": (references.IMPROPER_ACCESS_CONTROL, references.EXPOSED_RESOURCE),
    "ORPHANED_DATA": (references.INSECURE_DEFAULT,),
    "OWNER_ROLE": (references.IMPROPER_PRIVILEGE_MANAGEMENT,),
    "PASSWORD_AUTH": (references.MISSING_AUTHENTICATION,),
    "PATCHING": (references.INSECURE_DEFAULT,),
    "PLAINTEXT": (references.CLEARTEXT_TRANSMISSION,),
    "PRIVILEGED": (
        references.KUBERNETES_POD_SECURITY,
        references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
    ),
    "PRIVILEGED_BUILD": (references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,),
    "PRIVILEGE_ESCALATION": (references.PRIVILEGE_ESCALATION, references.KUBERNETES_POD_SECURITY),
    "PUBLIC_ACCESS": (references.EXPOSED_RESOURCE, references.AZURE_PRIVATE_LINK),
    "PUBLIC_ACCESS_BLOCK": (references.EXPOSED_RESOURCE,),
    "PUBLIC_IAM": (references.IMPROPER_ACCESS_CONTROL,),
    "PUBLIC_IP": (references.EXPOSED_RESOURCE,),
    "PUBLIC_SQL": (references.EXPOSED_RESOURCE,),
    "PUBLIC_STORAGE": (references.EXPOSED_RESOURCE,),
    "RBAC": (references.IMPROPER_ACCESS_CONTROL,),
    "RBAC_DISABLED": (references.IMPROPER_ACCESS_CONTROL,),
    "RESILIENCE": (references.INSECURE_DEFAULT,),
    "RETENTION": (references.INSUFFICIENT_LOGGING,),
    "ROOT_ACCESS": (references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,),
    "ROOT_USER": (
        references.DOCKER_BUILD_BEST_PRACTICE,
        references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
    ),
    "RUN_AS_ROOT": (
        references.KUBERNETES_POD_SECURITY,
        references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,
    ),
    "SCAN_ON_PUSH": (references.INSECURE_DEFAULT,),
    "SECRET_ARG": (references.HARDCODED_CREDENTIALS, references.DOCKER_BUILD_BEST_PRACTICE),
    "SECRET_ARG_DECLARED": (
        references.HARDCODED_CREDENTIALS,
        references.DOCKER_BUILD_BEST_PRACTICE,
    ),
    "SECRET_ENV_VALUE": (references.HARDCODED_CREDENTIALS, references.KUBERNETES_POD_SECURITY),
    "SERIAL_PORT": (references.EXPOSED_RESOURCE,),
    "SHARED_KEY_AUTH": (references.AZURE_SHARED_KEY, references.MISSING_AUTHENTICATION),
    "SQL_REQUIRE_SSL": (references.CLEARTEXT_TRANSMISSION,),
    "SUDO": (references.EXECUTION_WITH_UNNECESSARY_PRIVILEGE,),
    "UNENCRYPTED_STATE": (references.CLEARTEXT_STORAGE,),
    "WEAK_TLS": (references.WEAK_CRYPTO, references.IMPROPER_CERT_VALIDATION),
    "WILDCARD_PRINCIPAL": (references.IMPROPER_ACCESS_CONTROL,),
    "WRITABLE_ROOT": (references.KUBERNETES_POD_SECURITY,),
}

#: Kept as the name the rest of the code and the tests already use.
POLICIES = CURATED


__all__ = ["ALREADY_REPORTED", "CURATED", "FAMILY_REFERENCES", "POLICIES", "CuratedPolicies"]
