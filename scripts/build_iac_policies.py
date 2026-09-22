#!/usr/bin/env python3
"""Generate infrastructure policies from real Terraform provider schemas.

The hand-written table in `detect/iac_policies.py` is one row per control per
resource, which is honest and does not scale: "encryption at rest is not
enabled" is one sentence and several hundred resources, and nobody can type the
attribute name each provider chose for each of them without getting some of them
wrong. Guessing is worse than not shipping the check -- a policy that names an
attribute the provider does not have can never fire, and looks exactly like a
clean scan.

So the resource list comes from the provider itself. `terraform providers schema
-json` prints every resource and every attribute with its type and whether it
can be set at all, and this reads that: for each control in `CONTROLS` it emits
one policy for each resource whose schema actually declares the attribute, with
the right type, as something the user can write. A control is still a human
decision -- what `deletion_protection` means and why its absence matters is not
in the schema -- but which resources have it is not a decision, it is a fact,
and this is where the fact comes from.

    terraform providers schema -json > schema.json
    python scripts/build_iac_policies.py --schema schema.json

The output is a gzipped JSON file shipped in the wheel beside the advisory data,
with a metadata sidecar recording the provider versions it was built from. A
policy without a provenance is a policy nobody can check.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "src" / "cordon_scanner" / "detect" / "data"
OUTPUT_NAME = "iac-policies.json.gz"
META_NAME = "iac-policies-meta.json"
DIGESTS_NAME = "iac-policies-digests.json"


@dataclass(frozen=True)
class Control:
    """One security decision, and the attribute that carries it.

    `kind` says what the policy asserts about the attribute:

    `require_true`   the attribute must be present and true; absent means the
                     provider's default, which for these is the insecure one
    `require_false`  the same, inverted: shared-key auth, legacy modes
    `require_set`    the attribute must be present at all (a key reference, a
                     retention period)
    `forbid_true`    the attribute is insecure where it is written
    `forbid_values`  a value from a named set is insecure (TLS 1.0, "Enabled")
    """

    family: str
    kind: str
    severity: str
    confidence: str
    category: str
    subject: str
    consequence: str
    remediation: str
    types: tuple[str, ...] = ("bool",)
    values: tuple[str, ...] = ()
    """For `forbid_values`: the value spellings that are insecure."""

    sample_value: str = "true"
    """What a compliant block writes, for the generated `good` sample."""

    skip_resources: tuple[str, ...] = ()
    """Resources where this control is wrong, by name or by prefix with `*`."""


#: The attribute names, and what each one means. Keyed by the name the provider
#: uses, because that is what the schema is keyed by and what a policy has to
#: match in a file. Names that mean different things in different providers are
#: listed per provider prefix below rather than here.
CONTROLS: dict[str, Control] = {
    "encrypted": Control(
        family="ENCRYPT_AT_REST",
        kind="require_true",
        severity="high",
        confidence="high",
        category="policy",
        subject="Encryption at rest",
        consequence=(
            "The data is stored unencrypted, so anything that reaches the underlying "
            "storage reads it directly: a snapshot copied to another account, a disk "
            "reattached elsewhere, an operator with platform access."
        ),
        remediation="Set `encrypted = true`.",
    ),
    "storage_encrypted": Control(
        family="ENCRYPT_AT_REST",
        kind="require_true",
        severity="high",
        confidence="high",
        category="policy",
        subject="Storage encryption",
        consequence=(
            "The database is stored unencrypted, so a snapshot taken from it is "
            "readable by whoever can restore it."
        ),
        remediation="Set `storage_encrypted = true`.",
    ),
    "encryption_at_host_enabled": Control(
        family="ENCRYPT_AT_REST",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Host-level encryption",
        consequence=(
            "Temporary disks and caches on the host stay unencrypted, which is where "
            "a workload's data sits while it is being used."
        ),
        remediation="Set `encryption_at_host_enabled = true`.",
    ),
    "infrastructure_encryption_enabled": Control(
        family="ENCRYPT_AT_REST",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Infrastructure encryption",
        consequence=(
            "Only one layer of encryption is applied, so a failure in it is a failure "
            "of the whole protection rather than one of two."
        ),
        remediation="Set `infrastructure_encryption_enabled = true`.",
    ),
    "at_rest_encryption_enabled": Control(
        family="ENCRYPT_AT_REST",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Encryption at rest",
        consequence="The stored data is readable by anything that reaches the storage.",
        remediation="Set `at_rest_encryption_enabled = true`.",
    ),
    "transit_encryption_enabled": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="require_true",
        severity="high",
        confidence="high",
        category="policy",
        subject="Encryption in transit",
        consequence=(
            "Traffic to this resource is readable and modifiable by anything on the "
            "path, which includes every network the provider routes it over."
        ),
        remediation="Set `transit_encryption_enabled = true`.",
    ),
    "kms_key_id": Control(
        family="CMEK",
        kind="require_set",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A customer-managed key",
        consequence=(
            "Encryption uses the provider's own key, so access to the data is "
            "governed by the platform rather than by a key policy you write, and "
            "revoking it is not something you can do."
        ),
        remediation="Set `kms_key_id` to a key you control.",
        types=("string",),
        sample_value="aws_kms_key.this.arn",
    ),
    "kms_key_arn": Control(
        family="CMEK",
        kind="require_set",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A customer-managed key",
        consequence=(
            "Encryption uses the provider's own key, so access to the data is "
            "governed by the platform rather than by a key policy you write."
        ),
        remediation="Set `kms_key_arn` to a key you control.",
        types=("string",),
        sample_value="aws_kms_key.this.arn",
    ),
    "kms_key_name": Control(
        family="CMEK",
        kind="require_set",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A customer-managed key",
        consequence=(
            "Encryption uses Google's own key, so access to the data is governed by "
            "the platform rather than by a key policy you write."
        ),
        remediation="Set `kms_key_name` to a key you control.",
        types=("string",),
        sample_value="google_kms_crypto_key.this.id",
    ),
    "disk_encryption_set_id": Control(
        family="CMEK",
        kind="require_set",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A customer-managed disk encryption set",
        consequence=(
            "The disk is encrypted with a platform-managed key, so the key's lifecycle "
            "and access policy are Azure's rather than yours."
        ),
        remediation="Set `disk_encryption_set_id`.",
        types=("string",),
        sample_value="azurerm_disk_encryption_set.this.id",
    ),
    "public_network_access_enabled": Control(
        family="PUBLIC_ACCESS",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="Reachable from the public internet",
        consequence=(
            "The service answers on a public endpoint, so its own authentication is "
            "the only control between an anonymous scanner and the data behind it -- "
            "and scanning for exactly this is continuous and automated."
        ),
        remediation=(
            "Set `public_network_access_enabled = false` and reach the service through "
            "a private endpoint."
        ),
    ),
    "publicly_accessible": Control(
        family="PUBLIC_ACCESS",
        kind="forbid_true",
        severity="high",
        confidence="high",
        category="suspicious",
        subject="Reachable from the public internet",
        consequence=(
            "The resource is given a public address, leaving its own authentication "
            "as the only thing in front of the data."
        ),
        remediation="Set `publicly_accessible = false` and reach it from inside the VPC.",
    ),
    "local_auth_enabled": Control(
        family="SHARED_KEY_AUTH",
        kind="require_false",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Shared-key authentication",
        consequence=(
            "Local authentication is a connection string with an embedded key: it "
            "cannot be scoped, it is not attributable to anyone, it does not expire, "
            "and it is the credential that ends up in a pipeline variable."
        ),
        remediation="Set `local_auth_enabled = false` and use a managed identity.",
        sample_value="false",
    ),
    "local_authentication_enabled": Control(
        family="SHARED_KEY_AUTH",
        kind="require_false",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Shared-key authentication",
        consequence=(
            "Local authentication is a shared key that cannot be scoped, is not "
            "attributable, and does not expire."
        ),
        remediation="Set `local_authentication_enabled = false`.",
        sample_value="false",
    ),
    "https_only": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="HTTPS-only traffic",
        consequence=(
            "The service answers plain HTTP, so session cookies, tokens in headers and "
            "request bodies are readable and modifiable on the path."
        ),
        remediation="Set `https_only = true`.",
    ),
    "enforce_https": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="require_true",
        severity="high",
        confidence="high",
        category="policy",
        subject="HTTPS enforcement",
        consequence=(
            "Requests, responses and the credentials in their headers cross the network readable."
        ),
        remediation="Set `enforce_https = true`.",
    ),
    "ssl_enforcement_enabled": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="require_true",
        severity="high",
        confidence="high",
        category="policy",
        subject="SSL enforcement",
        consequence=(
            "A client that does not ask for TLS gets a plaintext connection carrying "
            "the database credentials."
        ),
        remediation="Set `ssl_enforcement_enabled = true`.",
    ),
    "allow_insecure": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="Insecure transport is allowed",
        consequence=(
            "The endpoint accepts connections that are not verified or not encrypted, "
            "so a client that downgrades gets one that looks the same in every log."
        ),
        remediation="Set `allow_insecure = false`.",
    ),
    "deletion_protection": Control(
        family="DELETION_PROTECTION",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Deletion protection",
        consequence=(
            "The resource can be destroyed by one apply, one console click, or one "
            "credential that should not have had the permission."
        ),
        remediation="Set `deletion_protection = true` on anything holding state you cannot rebuild.",
    ),
    "deletion_protection_enabled": Control(
        family="DELETION_PROTECTION",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Deletion protection",
        consequence="The resource can be destroyed in one step, with its data.",
        remediation="Set `deletion_protection_enabled = true`.",
    ),
    "enable_deletion_protection": Control(
        family="DELETION_PROTECTION",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Deletion protection",
        consequence="The resource can be destroyed in one step, with its data.",
        remediation="Set `enable_deletion_protection = true`.",
    ),
    "force_destroy": Control(
        family="FORCE_DESTROY",
        kind="forbid_true",
        severity="low",
        confidence="high",
        category="policy",
        subject="A destroy will not be stopped by the data in it",
        consequence=(
            "`force_destroy` removes the provider's own safety catch: a `terraform "
            "destroy`, or a rename that forces replacement, deletes the contents "
            "without the error that would otherwise have asked somebody."
        ),
        remediation="Leave `force_destroy` unset on anything holding data you would miss.",
    ),
    "privileged": Control(
        family="PRIVILEGED",
        kind="forbid_true",
        severity="high",
        confidence="high",
        category="suspicious",
        subject="The container runs privileged",
        consequence=(
            "A privileged container has the host's full capability set and access to "
            "its devices. It is a container boundary in name only: escaping to the "
            "host is a documented one-liner."
        ),
        remediation="Remove `privileged` and grant only the capabilities the workload needs.",
    ),
    "privileged_mode": Control(
        family="PRIVILEGED",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="The build runs privileged",
        consequence=(
            "The build container has the host's capabilities, and everything the build "
            "executes -- including a dependency's install script -- runs with them."
        ),
        remediation="Leave privileged mode off unless the build genuinely builds images.",
    ),
    "run_as_non_root": Control(
        family="RUN_AS_ROOT",
        kind="require_true",
        severity="medium",
        confidence="medium",
        category="policy",
        subject="A non-root user",
        consequence=(
            "Nothing requires the container to run as a non-root user, so the "
            "manifest's intent depends on whatever the image's default user happens "
            "to be."
        ),
        remediation="Set `run_as_non_root = true`.",
    ),
    "read_only_root_filesystem": Control(
        family="WRITABLE_ROOT",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A read-only root filesystem",
        consequence=(
            "A writable root filesystem lets anything that executes in the container "
            "persist a payload for the life of the pod, where an image scan will not "
            "see it."
        ),
        remediation="Set `read_only_root_filesystem = true` and mount a volume for what needs writing.",
    ),
    "allow_privilege_escalation": Control(
        family="PRIVILEGE_ESCALATION",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="The container may gain more privileges than it started with",
        consequence=(
            "A setuid binary or a file capability inside the image can raise the "
            "container's privileges at runtime, past whatever the manifest granted."
        ),
        remediation="Set `allow_privilege_escalation = false`.",
    ),
    "host_network": Control(
        family="HOST_NAMESPACE",
        kind="forbid_true",
        severity="high",
        confidence="high",
        category="suspicious",
        subject="The pod shares the node's network namespace",
        consequence=(
            "The pod sees and can bind every interface on the node and reaches "
            "services that trust the node's address. Network policy does not apply."
        ),
        remediation="Remove `host_network`.",
    ),
    "host_pid": Control(
        family="HOST_NAMESPACE",
        kind="forbid_true",
        severity="high",
        confidence="high",
        category="suspicious",
        subject="The pod shares the node's process namespace",
        consequence=(
            "The container sees every process on the node and can read their memory "
            "and environment, which is where credentials live."
        ),
        remediation="Remove `host_pid`.",
    ),
    "host_ipc": Control(
        family="HOST_NAMESPACE",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="The pod shares the node's IPC namespace",
        consequence="Shared memory belonging to other workloads on the node is readable.",
        remediation="Remove `host_ipc`.",
    ),
    "automount_service_account_token": Control(
        family="AUTOMOUNT_TOKEN",
        kind="forbid_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="The service account token is mounted into the pod",
        consequence=(
            "Anything that executes in the pod can read the token and call the API "
            "server as the service account, which is the first step in most "
            "cluster-level escalations."
        ),
        remediation="Set `automount_service_account_token = false` for workloads that do not call the API.",
    ),
    "enable_key_rotation": Control(
        family="KEY_ROTATION",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Automatic key rotation",
        consequence=(
            "One key protects every object encrypted with it for the life of the "
            "account, so a compromised key stays useful for as long as the data does."
        ),
        remediation="Set `enable_key_rotation = true`.",
    ),
    "skip_final_snapshot": Control(
        family="BACKUP",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="No snapshot is taken when the database is destroyed",
        consequence=(
            "A destroy leaves nothing behind. The one moment a backup is certain to "
            "matter is the moment this setting removes it."
        ),
        remediation="Leave `skip_final_snapshot` false, and name a final snapshot identifier.",
    ),
    "enable_logging": Control(
        family="LOGGING",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Logging",
        consequence=(
            "Nothing records what happened here, so an incident involving this "
            "resource cannot be reconstructed afterwards."
        ),
        remediation="Set `enable_logging = true`.",
    ),
    "retention_in_days": Control(
        family="RETENTION",
        kind="require_set",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A retention period",
        consequence=(
            "Logs are kept for however long the default says, which is either forever "
            "-- a cost and a privacy problem -- or long enough to lose the records an "
            "investigation needs."
        ),
        remediation="Set `retention_in_days` deliberately.",
        types=("number",),
        sample_value="90",
    ),
    "min_tls_version": Control(
        family="WEAK_TLS",
        kind="forbid_values",
        severity="medium",
        confidence="high",
        category="policy",
        subject="An obsolete TLS version is accepted",
        consequence=(
            "TLS 1.0 and 1.1 are withdrawn and have practical attacks against them. A "
            "client that negotiates one gets a connection that looks encrypted in "
            "every log while not being worth the label."
        ),
        remediation="Require TLS 1.2 or later.",
        types=("string",),
        values=("TLS1_0", "TLS1_1", "1.0", "1.1", "TLSv1", "TLSv1.1", "TLS_1_0", "TLS_1_1"),
        sample_value="TLS1_2",
    ),
    "minimum_tls_version": Control(
        family="WEAK_TLS",
        kind="forbid_values",
        severity="medium",
        confidence="high",
        category="policy",
        subject="An obsolete TLS version is accepted",
        consequence=("TLS 1.0 and 1.1 are withdrawn and have practical attacks against them."),
        remediation="Require TLS 1.2 or later.",
        types=("string",),
        values=("TLS1_0", "TLS1_1", "1.0", "1.1", "TLSv1", "TLSv1.1", "TLS_1_0", "TLS_1_1"),
        sample_value="1.2",
    ),
    "enable_secure_boot": Control(
        family="BOOT_INTEGRITY",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Secure boot",
        consequence=(
            "The instance boots whatever is on its disk, so a modified bootloader or "
            "kernel starts without anything noticing."
        ),
        remediation="Set `enable_secure_boot = true`.",
    ),
    "secure_boot_enabled": Control(
        family="BOOT_INTEGRITY",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Secure boot",
        consequence="The instance boots whatever is on its disk, modified or not.",
        remediation="Set `secure_boot_enabled = true`.",
    ),
    "enable_integrity_monitoring": Control(
        family="BOOT_INTEGRITY",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Boot integrity monitoring",
        consequence=(
            "Nothing compares the boot measurements against a baseline, so a change to "
            "the boot chain is neither reported nor recorded."
        ),
        remediation="Set `enable_integrity_monitoring = true`.",
    ),
    "enable_vtpm": Control(
        family="BOOT_INTEGRITY",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A virtual TPM",
        consequence=(
            "There is nowhere to root a measured boot or to seal a key to the instance's identity."
        ),
        remediation="Set `enable_vtpm = true`.",
    ),
    "vtpm_enabled": Control(
        family="BOOT_INTEGRITY",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A virtual TPM",
        consequence="There is nowhere to root a measured boot for this instance.",
        remediation="Set `vtpm_enabled = true`.",
    ),
    "auto_minor_version_upgrade": Control(
        family="PATCHING",
        kind="require_true",
        severity="medium",
        confidence="medium",
        category="policy",
        subject="Automatic minor version upgrades",
        consequence=(
            "The engine stays on the version it was created with, so a published fix "
            "for it is applied whenever somebody remembers rather than when it ships."
        ),
        remediation="Set `auto_minor_version_upgrade = true`.",
    ),
    "require_https": Control(
        family="ENCRYPT_IN_TRANSIT",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="HTTPS",
        consequence=(
            "The endpoint answers plain HTTP, so everything it carries is readable and "
            "modifiable on the path."
        ),
        remediation="Set `require_https = true`.",
    ),
    "require_authentication": Control(
        family="NO_AUTH",
        kind="require_true",
        severity="high",
        confidence="medium",
        category="suspicious",
        subject="Authentication",
        consequence=(
            "The endpoint answers unauthenticated callers, so whatever it reaches is "
            "reachable by anyone who finds the address."
        ),
        remediation="Set `require_authentication = true`.",
    ),
    "keep_at_least_one_backup": Control(
        family="BACKUP",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Keeping a backup",
        consequence=("A retention sweep can remove the last copy, which is the one that mattered."),
        remediation="Set `keep_at_least_one_backup = true`.",
    ),
    "enable_stackdriver_logging": Control(
        family="LOGGING",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Logging",
        consequence=(
            "Nothing records what happened here, so an incident involving this "
            "resource cannot be reconstructed."
        ),
        remediation="Set `enable_stackdriver_logging = true`.",
    ),
    "associate_public_ip_address": Control(
        family="PUBLIC_IP",
        kind="forbid_true",
        severity="low",
        confidence="high",
        category="policy",
        subject="A public IP address",
        consequence=(
            "The instance answers on the internet, where its security group is the "
            "only control and where it is scanned continuously."
        ),
        remediation="Leave it off and reach the instance through a bastion or a session manager.",
    ),
    "assign_public_ip": Control(
        family="PUBLIC_IP",
        kind="forbid_true",
        severity="low",
        confidence="high",
        category="policy",
        subject="A public IP address",
        consequence=(
            "The workload answers on the internet, so its security group is the only "
            "thing in front of whatever it serves."
        ),
        remediation="Set `assign_public_ip = false` and put it behind a load balancer.",
    ),
    "map_public_ip_on_launch": Control(
        family="PUBLIC_IP",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Every instance in the subnet gets a public address",
        consequence=(
            "The subnet's default makes each instance internet-facing whether or not "
            "its own configuration asked for that."
        ),
        remediation="Set `map_public_ip_on_launch = false` and assign addresses deliberately.",
    ),
    "http_tokens": Control(
        family="IMDSV1",
        kind="forbid_values",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="Instance metadata is reachable without a token",
        consequence=(
            "IMDSv1 stays enabled, so any process on the instance -- and any "
            "server-side request forgery in an application on it -- can read the "
            "instance profile's credentials with a plain GET."
        ),
        remediation='Set `http_tokens = "required"`.',
        types=("string",),
        values=("optional",),
        sample_value="required",
    ),
    "purge_protection_enabled": Control(
        family="DELETION_PROTECTION",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="Purge protection",
        consequence=(
            "A deleted vault or key can be purged immediately, so an attacker who can "
            "delete can also destroy the recovery path, and so can a mistake."
        ),
        remediation="Set `purge_protection_enabled = true`.",
    ),
    "mfa_delete": Control(
        family="MFA",
        kind="require_true",
        severity="medium",
        confidence="high",
        category="policy",
        subject="MFA for deletion",
        consequence=(
            "A stolen credential alone is enough to delete versions permanently, which "
            "is the step that turns a compromise into an unrecoverable one."
        ),
        remediation="Set `mfa_delete = true`.",
    ),
    "delete_on_termination": Control(
        family="ORPHANED_DATA",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Deleting the volume with the instance",
        consequence=(
            "The volume outlives the instance it belonged to, so its data stays in the "
            "account with nothing attached to it and nobody looking at it."
        ),
        remediation="Set `delete_on_termination = true`, or record why the volume is kept.",
    ),
    "multi_az": Control(
        family="RESILIENCE",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="A standby in another availability zone",
        consequence=(
            "The database has one copy in one zone. Availability is a security property "
            "when the alternative is restoring from a backup nobody has tested."
        ),
        remediation="Set `multi_az = true` for anything whose loss would be an incident.",
    ),
    "copy_tags_to_snapshot": Control(
        family="GOVERNANCE",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Tags on snapshots",
        consequence=(
            "Snapshots lose the ownership and classification tags of the thing they "
            "came from, so a copy of sensitive data becomes unattributable."
        ),
        remediation="Set `copy_tags_to_snapshot = true`.",
    ),
    "iam_database_authentication_enabled": Control(
        family="SHARED_KEY_AUTH",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="IAM database authentication",
        consequence=(
            "Access is by database password: a long-lived shared credential that no "
            "session expires and that cannot be revoked centrally."
        ),
        remediation="Set `iam_database_authentication_enabled = true`.",
    ),
    "performance_insights_enabled": Control(
        family="LOGGING",
        kind="require_true",
        severity="low",
        confidence="medium",
        category="policy",
        subject="Performance insights",
        consequence=(
            "There is no record of what the database was doing, which is what an "
            "investigation into an exfiltration through it would need."
        ),
        remediation="Set `performance_insights_enabled = true`.",
    ),
    "admin_enabled": Control(
        family="SHARED_KEY_AUTH",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="A shared admin account",
        consequence=(
            "The admin account is one username and password for the whole resource. It "
            "cannot be scoped, it is not attributable to a person, and it is the "
            "credential that ends up in a pipeline variable."
        ),
        remediation="Leave the admin account off and authenticate with an identity.",
    ),
    "nfsv3_enabled": Control(
        family="NO_AUTH",
        kind="forbid_true",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="NFSv3 is enabled",
        consequence=(
            "NFSv3 authenticates by client-asserted uid: any host that can reach the "
            "share can claim to be any user on it."
        ),
        remediation="Use a protocol that authenticates, or restrict the network to the clients that need it.",
    ),
    "tls_min_version": Control(
        family="WEAK_TLS",
        kind="forbid_values",
        severity="medium",
        confidence="high",
        category="policy",
        subject="An obsolete TLS version is accepted",
        consequence="TLS 1.0 and 1.1 are withdrawn and have practical attacks against them.",
        remediation="Require TLS 1.2 or later.",
        types=("string",),
        values=("TLS_1_0", "TLS_1_1", "1.0", "1.1", "TLSV1", "TLSV1_1"),
        sample_value="TLS_1_2",
    ),
    "public_network_access": Control(
        family="PUBLIC_ACCESS",
        kind="forbid_values",
        severity="medium",
        confidence="high",
        category="suspicious",
        subject="Reachable from the public internet",
        consequence=(
            "The service answers on a public endpoint, so its own authentication is "
            "the only control in front of the data."
        ),
        remediation='Set `public_network_access = "Disabled"` and use a private endpoint.',
        types=("string",),
        values=("Enabled", "ENABLED", "enabled"),
        sample_value="Disabled",
    ),
}

#: Resources where a control is not the control it looks like. Kept small and
#: specific: each entry is a case where the attribute name is shared and the
#: meaning is not.
EXCLUSIONS: dict[str, tuple[str, ...]] = {
    # A log group's own retention is the control; a Lambda's `retention_in_days`
    # on its log configuration is the same decision made in a second place, and
    # reporting both means two findings for one setting.
    "retention_in_days": ("aws_lambda_function", "aws_cloudwatch_event_bus"),
    # `encrypted` on a data source or a key pair means "is the material
    # encrypted", not "should it be".
    "encrypted": ("aws_key_pair", "aws_secretsmanager_secret_version"),
    # A storage bucket that exists to be a public website.
    "public_network_access_enabled": ("azurerm_static_site",),
}


def _type_name(schema_type: Any) -> str:
    """The primitive name of a schema type, or its container kind."""
    if isinstance(schema_type, str):
        return schema_type
    if isinstance(schema_type, list) and schema_type:
        return str(schema_type[0])
    return "unknown"


def _walk(block: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every settable attribute in a resource, including nested blocks.

    Flattened by name rather than by path, because a policy matches the text of
    a resource block and a nested attribute is inside it. Where two nested
    blocks use the same name, the first wins; they are the same control either
    way.
    """
    found: dict[str, dict[str, Any]] = {}
    for name, attribute in (block.get("attributes") or {}).items():
        if not (attribute.get("optional") or attribute.get("required")):
            continue  # computed-only: nothing a configuration can set
        found.setdefault(name, attribute)
    for nested in (block.get("block_types") or {}).values():
        for name, attribute in _walk(nested.get("block") or {}).items():
            found.setdefault(name, attribute)
    return found


def _write(dialect: str) -> str:
    """How this dialect writes an assignment in a sample."""
    return ": " if dialect == "cfn" else " = "


def _identifier(control: Control, resource: str) -> str:
    prefix = "SUSPECT" if control.category == "suspicious" else "POLICY"
    # `CFN` for a template, `IAC` for everything else: an identifier that does
    # not say which format it is about sends a reader to the wrong file.
    domain = "CFN" if resource.startswith("cfn:") else "IAC"
    slug = (
        resource.removeprefix("cfn:").replace("::", "_").replace("-", "_").replace(".", "_").upper()
    )
    return f"{prefix}.{domain}.{control.family}.{slug}.001"


def _policy(
    control: Control, resource: str, attribute: str, dialect: str = "hcl"
) -> dict[str, Any]:
    """One policy, with the samples that prove it works.

    The dialect is the difference between the two formats this generates for.
    HCL writes `attribute = value` inside a `resource` block; CloudFormation
    writes `Property: value` under `Properties:`. The patterns and the samples
    both follow it, so a generated policy is proved against a block shaped the
    way the real file is shaped.
    """
    if dialect == "cfn":
        # `"?` before the colon: a JSON template writes `"Encrypted": true` and
        # a YAML one writes `Encrypted: true`, and both are the same property.
        assign = r"\"?\s*:\s*"
        indent = "      "
        base = f"    Type: {resource.removeprefix('cfn:')}\n    Properties:\n      Name: example\n"
    else:
        assign = r"\s*=\s*"
        indent = "  "
        base = '  name = "example"\n'
    policy: dict[str, Any] = {
        "id": _identifier(control, resource),
        "title": f"{resource}: {control.subject.lower()}",
        "message": control.consequence,
        "remediation": control.remediation,
        "severity": control.severity,
        "confidence": control.confidence,
        "category": control.category,
        "resources": [resource],
    }

    if control.kind == "require_true":
        policy["require"] = [rf"{attribute}{assign}true"]
        policy["bad"] = base
        policy["good"] = f"{base}{indent}{attribute}{_write(dialect)}true\n"
    elif control.kind == "require_false":
        policy["require"] = [rf"{attribute}{assign}false"]
        policy["bad"] = base
        policy["good"] = f"{base}{indent}{attribute}{_write(dialect)}false\n"
    elif control.kind == "require_set":
        policy["require"] = [rf"{attribute}{assign.rstrip('a-z')}"]
        policy["bad"] = base
        policy["good"] = f"{base}{indent}{attribute}{_write(dialect)}{control.sample_value}\n"
    elif control.kind == "forbid_true":
        policy["forbid"] = [rf"{attribute}{assign}true"]
        policy["bad"] = f"{base}{indent}{attribute}{_write(dialect)}true\n"
        policy["good"] = f"{base}{indent}{attribute}{_write(dialect)}false\n"
    elif control.kind == "forbid_values":
        alternatives = "|".join(value.replace(".", r"\.") for value in control.values)
        # Quoted in HCL, quoted or bare in a template.
        policy["forbid"] = [rf"{attribute}{assign}\"?(?:{alternatives})\"?"]
        written = _write(dialect)
        policy["bad"] = f'{base}{indent}{attribute}{written}"{control.values[0]}"\n'
        policy["good"] = f'{base}{indent}{attribute}{written}"{control.sample_value}"\n'
    else:  # pragma: no cover - a control kind with no generator is a bug here
        raise SystemExit(f"unknown control kind {control.kind!r} for {attribute}")
    return policy


def _covered(policies: Any) -> set[tuple[str, str]]:
    """The (control family, resource) pairs a hand-written policy already covers.

    Matching on the identifier alone was not enough: the curated table writes
    `POLICY.IAC.DELETION_PROTECTION.AWS_DB_INSTANCE_DELETION_PROTECTION.001`
    where this generator writes `...AWS_DB_INSTANCE.001`, so both shipped and
    one `aws_db_instance` reported the same missing setting twice. Two findings
    for one decision is how a report stops being read.
    """
    pairs: set[tuple[str, str]] = set()
    for policy in policies:
        parts = policy.id.split(".")
        if len(parts) < 4:
            continue
        family = parts[2]
        for resource in policy.resources:
            pairs.add((family, resource))
    return pairs


def generate(
    schema: dict[str, Any], known: set[str], covered: set[tuple[str, str]] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every policy the schema supports, and what it was built from."""
    policies: list[dict[str, Any]] = []
    seen: set[str] = set(known)
    already = covered or set()
    providers: dict[str, str] = {}
    counted: dict[str, int] = {}

    for provider, body in sorted((schema.get("provider_schemas") or {}).items()):
        providers[provider] = str(body.get("provider", {}).get("version", "") or "")
        for resource, entry in sorted((body.get("resource_schemas") or {}).items()):
            attributes = _walk(entry.get("block") or {})
            for attribute, control in CONTROLS.items():
                if attribute not in attributes:
                    continue
                if resource in EXCLUSIONS.get(attribute, ()):
                    continue
                if any(
                    resource == skip or (skip.endswith("*") and resource.startswith(skip[:-1]))
                    for skip in control.skip_resources
                ):
                    continue
                if _type_name(attributes[attribute].get("type")) not in control.types:
                    continue
                if (control.family, resource) in already:
                    continue  # a hand-written policy says this already
                policy = _policy(control, resource, attribute)
                # One policy per family per resource: a resource with both
                # `kms_key_id` and `kms_key_arn` is one decision, not two
                # findings.
                if policy["id"] in seen:
                    continue
                seen.add(policy["id"])
                already.add((control.family, resource))
                policies.append(policy)
                counted[control.family] = counted.get(control.family, 0) + 1

    meta = {
        "providers": providers,
        "policy_count": len(policies),
        "by_family": dict(sorted(counted.items())),
        "controls": len(CONTROLS),
    }
    return policies, meta


#: The same controls, in CloudFormation's spelling. A template says
#: `StorageEncrypted: true` where Terraform says `storage_encrypted = true`, and
#: the two describe overlapping but different subsets of the same services, so
#: the mapping is written out rather than derived by case conversion, which
#: would invent property names that do not exist.
CFN_CONTROLS: dict[str, Control] = {
    "StorageEncrypted": CONTROLS["storage_encrypted"],
    "Encrypted": CONTROLS["encrypted"],
    "KmsKeyId": CONTROLS["kms_key_id"],
    "KmsMasterKeyId": CONTROLS["kms_key_id"],
    "KmsKeyArn": CONTROLS["kms_key_arn"],
    "PubliclyAccessible": CONTROLS["publicly_accessible"],
    "DeletionProtection": CONTROLS["deletion_protection"],
    "DeletionProtectionEnabled": CONTROLS["deletion_protection_enabled"],
    "EnableKeyRotation": CONTROLS["enable_key_rotation"],
    "MultiAZ": CONTROLS["multi_az"],
    "AutoMinorVersionUpgrade": CONTROLS["auto_minor_version_upgrade"],
    "Privileged": CONTROLS["privileged"],
    "ReadonlyRootFilesystem": CONTROLS["read_only_root_filesystem"],
    "AssociatePublicIpAddress": CONTROLS["associate_public_ip_address"],
    "MapPublicIpOnLaunch": CONTROLS["map_public_ip_on_launch"],
    "CopyTagsToSnapshot": CONTROLS["copy_tags_to_snapshot"],
    "EnableIAMDatabaseAuthentication": CONTROLS["iam_database_authentication_enabled"],
    "EnablePerformanceInsights": CONTROLS["performance_insights_enabled"],
    "HttpTokens": CONTROLS["http_tokens"],
    "MinimumTlsVersion": CONTROLS["minimum_tls_version"],
    "MinimumProtocolVersion": CONTROLS["min_tls_version"],
}

#: CloudFormation's primitive names, in the vocabulary a control declares.
CFN_TYPES = {"Boolean": "bool", "String": "string", "Integer": "number", "Double": "number"}


def _cfn_properties(
    spec: dict[str, Any],
    entry: dict[str, Any],
    owner: str,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Every property of a resource type, including the nested ones.

    Flattened by name, for the reason the Terraform walk is: a policy matches
    the text of the resource's block and a nested property sits inside it.
    Bounded by depth and by a visited set, because property types in this
    specification reference each other and a few reference themselves.
    """
    found: dict[str, str] = {}
    if depth > 3:
        return found
    for name, definition in (entry.get("Properties") or {}).items():
        primitive = definition.get("PrimitiveType") or definition.get("PrimitiveItemType")
        if primitive:
            found.setdefault(name, CFN_TYPES.get(str(primitive), "unknown"))
            continue
        nested_name = definition.get("Type") or definition.get("ItemType")
        if not nested_name or nested_name in {"List", "Map", "Tag"}:
            continue
        qualified = f"{owner}.{nested_name}"
        nested = (spec.get("PropertyTypes") or {}).get(qualified)
        if nested is None or qualified in seen:
            continue
        for child, kind in _cfn_properties(
            spec, nested, owner, depth + 1, seen | {qualified}
        ).items():
            found.setdefault(child, kind)
    return found


def generate_cfn(
    spec: dict[str, Any], known: set[str], covered: set[tuple[str, str]] | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every policy the CloudFormation specification supports."""
    policies: list[dict[str, Any]] = []
    seen = set(known)
    already = covered or set()
    counted: dict[str, int] = {}

    for resource, entry in sorted((spec.get("ResourceTypes") or {}).items()):
        properties = _cfn_properties(spec, entry, resource)
        for name, control in CFN_CONTROLS.items():
            if properties.get(name) not in control.types:
                continue
            if (control.family, f"cfn:{resource}") in already:
                continue
            policy = _policy(control, f"cfn:{resource}", name, dialect="cfn")
            if policy["id"] in seen:
                continue
            seen.add(policy["id"])
            policies.append(policy)
            counted[control.family] = counted.get(control.family, 0) + 1

    meta = {
        "specification_version": spec.get("ResourceSpecificationVersion", ""),
        "policy_count": len(policies),
        "by_family": dict(sorted(counted.items())),
    }
    return policies, meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema", required=True, type=Path, help="terraform providers schema -json"
    )
    parser.add_argument(
        "--cfn-spec", type=Path, help="AWS CloudFormationResourceSpecification.json"
    )
    parser.add_argument(
        "--versions",
        type=Path,
        help=(
            "`terraform version -json`, for the provider versions. The schema "
            "output does not carry them, and a generated policy whose provenance "
            "stops at the provider name cannot be checked against anything."
        ),
    )
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args()

    schema = json.loads(args.schema.read_text(encoding="utf-8"))

    # The hand-written policies win: they carry a message written for one
    # resource rather than a template, and several of them say something the
    # schema cannot (an alternative spelling, a mitigating block).
    sys.path.insert(0, str(ROOT / "src"))
    from cordon_scanner.detect.iac_policies import CURATED

    covered = _covered(CURATED)
    policies, meta = generate(schema, {policy.id for policy in CURATED}, covered)

    if args.versions:
        selections = json.loads(args.versions.read_text(encoding="utf-8"))
        chosen = selections.get("provider_selections") or {}
        meta["providers"] = {name: str(chosen.get(name, "")) for name in meta["providers"]}
        meta["terraform_version"] = str(selections.get("terraform_version", ""))

    if args.cfn_spec:
        spec = json.loads(args.cfn_spec.read_text(encoding="utf-8"))
        known = {policy.id for policy in CURATED} | {row["id"] for row in policies}
        cfn_policies, cfn_meta = generate_cfn(spec, known, covered)
        policies.extend(cfn_policies)
        meta["cloudformation"] = cfn_meta
        meta["policy_count"] = len(policies)
        for family, count in cfn_meta["by_family"].items():
            meta["by_family"][family] = meta["by_family"].get(family, 0) + count

    args.out.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(policies, indent=1, sort_keys=True) + "\n"
    # `mtime=0` so two builds of the same policy set are byte-identical and the
    # digest below identifies the content rather than the moment it was written.
    with gzip.GzipFile(args.out / OUTPUT_NAME, "wb", mtime=0) as handle:
        handle.write(payload.encode("utf-8"))

    # When, so a scan can say how old the set is. A policy set that never
    # changes goes stale the day after it ships, the same way an advisory
    # snapshot does, and neither says so unless something records the date.
    meta["built_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    (args.out / META_NAME).write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Last, and over everything already written including the metadata. The
    # manifest is what lets the load path refuse a file that was edited after it
    # was built: the policy set decides what a scan reports, so an edit that
    # quietly removes a control must not leave a green scan and a healthy count.
    # What makes it worth having is the wheel's own signature -- the release is
    # cosign-signed with SLSA provenance, so changing a data file after the fact
    # means also changing a manifest inside a signed artefact.
    digests = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(args.out.glob("iac-policies*"))
        if path.name != DIGESTS_NAME
    }
    (args.out / DIGESTS_NAME).write_text(
        json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"{len(policies)} policies from {len(meta['providers'])} providers")
    for family, count in meta["by_family"].items():
        print(f"  {count:5}  {family}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
