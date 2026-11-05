"""The data-protection policies: encryption at rest and in transit, public access, logging, backups,
deletion protection, open storage and weak TLS, by resource type.
"""

from __future__ import annotations

from typing import Any

from cordon_scanner.detect.infra.policy_terms import HIGH, LOW, MEDIUM, PresenceGate
from cordon_scanner.foundation.models import Severity

AT_REST: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "storage_encrypted", HIGH),
    ("aws_rds_cluster", "storage_encrypted", HIGH),
    ("aws_rds_global_cluster", "storage_encrypted", MEDIUM),
    ("aws_docdb_cluster", "storage_encrypted", HIGH),
    ("aws_neptune_cluster", "storage_encrypted", HIGH),
    ("aws_ebs_volume", "encrypted", HIGH),
    ("aws_efs_file_system", "encrypted", HIGH),
    ("aws_fsx_lustre_file_system", "kms_key_id", MEDIUM),
    ("aws_elasticache_replication_group", "at_rest_encryption_enabled", MEDIUM),
    ("aws_redshift_cluster", "encrypted", HIGH),
    ("aws_dax_cluster", "server_side_encryption", MEDIUM),
    ("aws_qldb_ledger", "kms_key", LOW),
    ("aws_timestreamwrite_database", "kms_key_id", LOW),
    ("aws_codebuild_project", "encryption_key", LOW),
    ("aws_sagemaker_endpoint_configuration", "kms_key_arn", MEDIUM),
    ("aws_sagemaker_notebook_instance", "kms_key_id", MEDIUM),
    ("aws_workspaces_workspace", "root_volume_encryption_enabled", MEDIUM),
    ("aws_ecr_repository", "encryption_configuration", LOW),
    ("aws_backup_vault", "kms_key_arn", MEDIUM),
    ("aws_eks_cluster", "encryption_config", MEDIUM),
    ("google_sql_database_instance", "encryption_key_name", LOW),
    ("google_bigquery_dataset", "default_encryption_configuration", LOW),
    ("google_dataproc_cluster", "encryption_config", LOW),
    ("azurerm_managed_disk", "encryption_settings", MEDIUM),
    ("azurerm_mysql_server", "infrastructure_encryption_enabled", MEDIUM),
    ("azurerm_postgresql_server", "infrastructure_encryption_enabled", MEDIUM),
)

# The attribute is a key reference rather than a boolean for several of these,
# and "absent" is still the question -- so the required pattern is the attribute
# being set to anything at all.
AT_REST_NON_BOOLEAN = frozenset(
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

IN_TRANSIT: tuple[tuple[str, str, Severity], ...] = (
    ("aws_elasticache_replication_group", "transit_encryption_enabled", HIGH),
    ("aws_dms_endpoint", "ssl_mode", MEDIUM),
    ("aws_efs_file_system_policy", "policy", LOW),
    ("azurerm_storage_account", "enable_https_traffic_only", HIGH),
    ("azurerm_postgresql_server", "ssl_enforcement_enabled", HIGH),
    ("azurerm_mysql_server", "ssl_enforcement_enabled", HIGH),
    ("azurerm_mariadb_server", "ssl_enforcement_enabled", HIGH),
    ("azurerm_app_service", "https_only", MEDIUM),
    ("azurerm_linux_web_app", "https_only", MEDIUM),
    ("azurerm_windows_web_app", "https_only", MEDIUM),
    ("azurerm_function_app", "https_only", MEDIUM),
    ("azurerm_linux_function_app", "https_only", MEDIUM),
    ("azurerm_windows_function_app", "https_only", MEDIUM),
)

PUBLIC_TRUE: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "publicly_accessible", HIGH),
    ("aws_rds_cluster_instance", "publicly_accessible", HIGH),
    ("aws_redshift_cluster", "publicly_accessible", HIGH),
    ("aws_docdb_cluster_instance", "publicly_accessible", HIGH),
    ("aws_dms_replication_instance", "publicly_accessible", MEDIUM),
    ("aws_sagemaker_notebook_instance", "direct_internet_access", MEDIUM),
    ("azurerm_mssql_server", "public_network_access_enabled", MEDIUM),
    ("azurerm_postgresql_server", "public_network_access_enabled", MEDIUM),
    ("azurerm_mysql_server", "public_network_access_enabled", MEDIUM),
    ("azurerm_cosmosdb_account", "public_network_access_enabled", MEDIUM),
    ("azurerm_key_vault", "public_network_access_enabled", MEDIUM),
    ("azurerm_container_registry", "public_network_access_enabled", LOW),
    ("azurerm_storage_account", "public_network_access_enabled", MEDIUM),
    ("azurerm_redis_cache", "public_network_access_enabled", MEDIUM),
)

LOGGING: tuple[tuple[str, str, Severity], ...] = (
    ("aws_cloudtrail", "enable_log_file_validation", MEDIUM),
    ("aws_cloudtrail", "is_multi_region_trail", MEDIUM),
    ("aws_redshift_cluster", "logging", LOW),
    ("aws_elasticsearch_domain", "log_publishing_options", LOW),
    ("aws_opensearch_domain", "log_publishing_options", LOW),
    ("aws_api_gateway_stage", "xray_tracing_enabled", LOW),
    ("aws_docdb_cluster", "enabled_cloudwatch_logs_exports", LOW),
    ("aws_neptune_cluster", "enable_cloudwatch_logs_exports", LOW),
    ("aws_msk_cluster", "logging_info", LOW),
    ("google_container_cluster", "logging_service", LOW),
    ("google_storage_bucket", "logging", LOW),
    ("azurerm_mssql_server", "extended_auditing_policy", MEDIUM),
)

BACKUP: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "backup_retention_period", MEDIUM),
    ("aws_rds_cluster", "backup_retention_period", MEDIUM),
    ("aws_docdb_cluster", "backup_retention_period", LOW),
    ("aws_neptune_cluster", "backup_retention_period", LOW),
    ("aws_redshift_cluster", "automated_snapshot_retention_period", LOW),
    ("azurerm_postgresql_server", "backup_retention_days", LOW),
    ("azurerm_mysql_server", "backup_retention_days", LOW),
)

DELETION_PROTECTION: tuple[tuple[str, str, Severity], ...] = (
    ("aws_db_instance", "deletion_protection", LOW),
    ("aws_rds_cluster", "deletion_protection", LOW),
    ("aws_docdb_cluster", "deletion_protection", LOW),
    ("aws_neptune_cluster", "deletion_protection", LOW),
    ("aws_lb", "enable_deletion_protection", LOW),
    ("aws_alb", "enable_deletion_protection", LOW),
    ("aws_dynamodb_table", "deletion_protection_enabled", LOW),
    ("azurerm_key_vault", "purge_protection_enabled", MEDIUM),
)

OPEN_STORAGE: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "aws_s3_bucket",
        "acl",
        r"acl\s*=\s*\"public-read(-write)?\"",
        HIGH,
        '  bucket = "example"\n  acl = "public-read"\n',
        '  bucket = "example"\n  acl = "private"\n',
    ),
    (
        "aws_s3_bucket_acl",
        "acl",
        r"acl\s*=\s*\"public-read(-write)?\"",
        HIGH,
        '  bucket = aws_s3_bucket.b.id\n  acl = "public-read-write"\n',
        '  bucket = aws_s3_bucket.b.id\n  acl = "private"\n',
    ),
    (
        "azurerm_storage_container",
        "container_access_type",
        r"container_access_type\s*=\s*\"(?:blob|container)\"",
        HIGH,
        '  name = "example"\n  container_access_type = "container"\n',
        '  name = "example"\n  container_access_type = "private"\n',
    ),
    (
        "azurerm_storage_account",
        "allow_nested_items_to_be_public",
        r"allow_nested_items_to_be_public\s*=\s*true",
        MEDIUM,
        '  name = "example"\n  allow_nested_items_to_be_public = true\n',
        '  name = "example"\n  allow_nested_items_to_be_public = false\n',
    ),
    (
        "google_storage_bucket_iam_member",
        "member",
        r"member\s*=\s*\"all(?:Users|AuthenticatedUsers)\"",
        HIGH,
        '  bucket = "example"\n  member = "allUsers"\n',
        '  bucket = "example"\n  member = "user:someone@example.com"\n',
    ),
    (
        "google_storage_bucket_iam_binding",
        "members",
        r"\"all(?:Users|AuthenticatedUsers)\"",
        HIGH,
        '  bucket = "example"\n  members = ["allUsers"]\n',
        '  bucket = "example"\n  members = ["group:team@example.com"]\n',
    ),
    (
        "google_storage_bucket_access_control",
        "entity",
        r"entity\s*=\s*\"allUsers\"",
        HIGH,
        '  bucket = "example"\n  entity = "allUsers"\n',
        '  bucket = "example"\n  entity = "user-someone@example.com"\n',
    ),
)

PUBLIC_ACCESS_BLOCK = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

WEAK_TLS: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "azurerm_storage_account",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"TLS1_[01]\"",
        MEDIUM,
        '  name = "example"\n  min_tls_version = "TLS1_0"\n',
        '  name = "example"\n  min_tls_version = "TLS1_2"\n',
    ),
    (
        "azurerm_mssql_server",
        "minimum_tls_version",
        r"minimum_tls_version\s*=\s*\"1\.[01]\"",
        MEDIUM,
        '  name = "example"\n  minimum_tls_version = "1.0"\n',
        '  name = "example"\n  minimum_tls_version = "1.2"\n',
    ),
    (
        "azurerm_app_service",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"1\.[01]\"",
        MEDIUM,
        '  name = "example"\n  site_config {\n    min_tls_version = "1.0"\n  }\n',
        '  name = "example"\n  site_config {\n    min_tls_version = "1.2"\n  }\n',
    ),
    (
        "azurerm_redis_cache",
        "minimum_tls_version",
        r"minimum_tls_version\s*=\s*\"1\.[01]\"",
        MEDIUM,
        '  name = "example"\n  minimum_tls_version = "1.0"\n',
        '  name = "example"\n  minimum_tls_version = "1.2"\n',
    ),
    (
        "aws_lb_listener",
        "ssl_policy",
        r"ssl_policy\s*=\s*\"[^\"]*TLS-1-[01][^\"]*\"",
        MEDIUM,
        '  port = 443\n  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"\n',
        '  port = 443\n  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n',
    ),
    (
        "aws_api_gateway_domain_name",
        "security_policy",
        r"security_policy\s*=\s*\"TLS_1_0\"",
        MEDIUM,
        '  domain_name = "api.example.com"\n  security_policy = "TLS_1_0"\n',
        '  domain_name = "api.example.com"\n  security_policy = "TLS_1_2"\n',
    ),
    (
        "google_compute_ssl_policy",
        "min_tls_version",
        r"min_tls_version\s*=\s*\"TLS_1_0\"",
        MEDIUM,
        '  name = "example"\n  min_tls_version = "TLS_1_0"\n',
        '  name = "example"\n  min_tls_version = "TLS_1_2"\n',
    ),
)

AT_REST_EXTRA: tuple[tuple[str, str, Severity] | tuple[str, str, Severity, Any], ...] = (
    ("aws_sqs_queue", "kms_master_key_id", MEDIUM),
    ("aws_sns_topic", "kms_master_key_id", MEDIUM),
    ("aws_cloudwatch_log_group", "kms_key_id", LOW),
    ("aws_kinesis_stream", "encryption_type", MEDIUM),
    ("aws_kinesis_firehose_delivery_stream", "server_side_encryption", MEDIUM),
    ("aws_athena_workgroup", "encryption_configuration", MEDIUM),
    ("aws_athena_database", "encryption_configuration", MEDIUM),
    ("aws_glue_catalog_database", "target_database", LOW),
    ("aws_secretsmanager_secret", "kms_key_id", LOW),
    (
        "aws_ssm_parameter",
        "key_id",
        MEDIUM,
        PresenceGate(
            when=(r'type\s*=\s*"SecureString"',),
            sample='type = "SecureString"',
            qualifier="It holds a `SecureString`, so it is encrypted with the "
            "account's default key rather than one you control.",
        ),
    ),
    ("aws_lambda_function", "kms_key_arn", LOW),
    ("aws_cloudtrail", "kms_key_id", MEDIUM),
    ("aws_elasticsearch_domain", "encrypt_at_rest", HIGH),
    ("aws_opensearch_domain", "encrypt_at_rest", HIGH),
    ("aws_memorydb_cluster", "kms_key_arn", MEDIUM),
    ("aws_mq_broker", "encryption_options", MEDIUM),
    ("aws_transfer_server", "post_authentication_login_banner", LOW),
    ("google_pubsub_topic", "kms_key_name", LOW),
    ("google_spanner_database", "encryption_config", LOW),
    ("google_bigtable_instance", "cluster", LOW),
    ("google_container_cluster", "database_encryption", MEDIUM),
    ("azurerm_mssql_database", "transparent_data_encryption_enabled", HIGH),
    ("azurerm_cosmosdb_account", "key_vault_key_id", LOW),
    ("azurerm_eventhub_namespace", "local_authentication_enabled", LOW),
    ("azurerm_storage_account", "infrastructure_encryption_enabled", LOW),
)

LOGGING_EXTRA: tuple[tuple[str, str, Severity], ...] = (
    ("aws_s3_bucket_logging", "target_bucket", LOW),
    ("aws_cloudfront_distribution", "logging_config", LOW),
    ("aws_lb", "access_logs", LOW),
    ("aws_alb", "access_logs", LOW),
    ("aws_api_gateway_stage", "access_log_settings", LOW),
    ("aws_apigatewayv2_stage", "access_log_settings", LOW),
    ("aws_eks_cluster", "enabled_cluster_log_types", MEDIUM),
    ("aws_mq_broker", "logs", LOW),
    ("aws_globalaccelerator_accelerator", "attributes", LOW),
    ("aws_lambda_function", "tracing_config", LOW),
    ("aws_vpc", "enable_dns_hostnames", LOW),
    ("google_compute_subnetwork", "log_config", LOW),
    ("google_container_cluster", "monitoring_service", LOW),
    ("google_sql_database_instance", "backup_configuration", MEDIUM),
    ("azurerm_kubernetes_cluster", "oms_agent", LOW),
    ("azurerm_key_vault", "soft_delete_retention_days", LOW),
)


__all__ = [
    "AT_REST",
    "AT_REST_EXTRA",
    "AT_REST_NON_BOOLEAN",
    "BACKUP",
    "DELETION_PROTECTION",
    "IN_TRANSIT",
    "LOGGING",
    "LOGGING_EXTRA",
    "OPEN_STORAGE",
    "PUBLIC_ACCESS_BLOCK",
    "PUBLIC_TRUE",
    "WEAK_TLS",
]
