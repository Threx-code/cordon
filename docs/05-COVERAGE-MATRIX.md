# Coverage matrix

What Cordon detects, by threat domain, with the rule that implements each check.

**Generated from the shipped rules, not written alongside them.** A hand-kept
matrix drifts, and a drifted matrix is worse than none: it reports coverage that
is not there, which is the same failure mode as a scan reporting clean on a file
it never read. `tests/unit/test_coverage_matrix.py` regenerates this content and
fails if it disagrees with what the tool actually ships, so a new rule that is
absent here fails the build.

Regenerate after adding a rule:

```bash
python tests/matrix.py > docs/05-COVERAGE-MATRIX.md
```

## How to read it

The fourteen domains are the taxonomy the threat model is organised around; see
`docs/02-THREAT-MODEL.md`. A rule's **attack category** says what is being
attempted rather than where -- typosquatting and dependency confusion share a
domain and are different attacks, and a vulnerability is a liability rather than
somebody attacking you.

Capability primitives (`CAP.*`) are not listed. They are labels that composite
rules reason over, not findings: a file that decodes something is not a finding,
and a file that decodes and executes is. The composites are what appear here.

## What is not covered

Stated because a coverage matrix that lists only what exists is an advertisement
rather than a document.

- **Runtime behaviour.** Cordon does not execute the code it scans, so behaviour
  that exists only at runtime -- a target decoded from a network response, logic
  gated on a fetched value -- is outside it by construction. What such code
  cannot avoid is looking like it is hiding something, which is what the
  obfuscation domain reports. Observing the behaviour itself requires an
  isolated sandbox, which is a separate opt-in component.
- **Cryptographic signature verification** (domain 13) is available as the
  opt-in `[attest]` extra. The base checks provenance against what the registry
  publishes -- npm's `dist.attestations`, PyPI's `provenance`, and the lockfile
  hash against the registry's -- and reconciles an SBOM against the resolved
  graph. With `[attest]` installed, the provenance detector verifies the
  sigstore bundle itself: the Fulcio certificate, the Rekor inclusion proof, the
  DSSE signature over the pinned digest, and the signing identity against the
  declared source repository. That verification needs a cryptographic library
  the core will not take, which is why it is an extra; without it, provenance
  stays at the presence check and the unverifiable case is reported, never
  passed.
- **Reachability** -- whether a vulnerable or malicious symbol is actually
  called -- is modelled at its import tier, behind `--reachability`: a vulnerable
  transitive dependency that first-party code does not import is lowered and
  tagged rather than dropped. The precise call-graph tier, whether the vulnerable
  symbol is on a path a caller reaches, is not yet built.
- **Operating-system and container-image packages.** Cordon reads source,
  manifests, lockfiles, CI and IaC. It does not scan `dpkg`/`rpm`/`apk`
  databases or image layers for base-image CVEs, which is a distinct product
  from supply-chain analysis of a source tree.
- **Languages without a capability pack** inherit no behavioural rules. Packs
  ship for Python, JavaScript and TypeScript, shell and PowerShell, Make, the
  JVM build languages, CMake, MSBuild, Rust, and the compiled-language set.
  A language outside those is read by the language-agnostic rules only --
  obfuscation, secrets, and anything matched on path or content shape.
- **Online checks** (withdrawal, version distance, registry hash verification,
  and provenance/attestation verification) require `--online` and do not run by
  default.

---


### Domain 1 — Source and VCS identity

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.VCS.BINARY_ADDED.001` | low | `vcs` | policy |
| `SUSPECT.POLYGLOT.MISMATCH.001` | high | `binary` | obfuscation |
| `SUSPECT.SUBMODULE.UNTRUSTED.001` | medium | `config` | integrity |
| `SUSPECT.VCS.HOOKS_PATH.001` | medium | `config` | integrity |
| `SUSPECT.VCS.HOOK_ADDED.001` | medium | `vcs` | integrity |

### Domain 2 — Dependencies

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.DEPENDENCY.KNOWN.001` | critical | `advisory` | malicious_code |
| `POLICY.DEPENDENCY.DOWNGRADE.001` | low | `registry` | policy |
| `POLICY.DEPENDENCY.INTEGRITY.001` | medium | `dependency` | policy |
| `POLICY.DEPENDENCY.SOURCE.001` | low | `dependency` | policy |
| `POLICY.LICENSE.COPYLEFT.001` | medium | `license` | policy |
| `POLICY.LICENSE.NETWORK_COPYLEFT.001` | medium | `license` | policy |
| `POLICY.LICENSE.WEAK_COPYLEFT.001` | low | `license` | policy |
| `POLICY.LOCKFILE.INTEGRITY.001` | medium | `lockfile` | integrity |
| `SUSPECT.DEPENDENCY.CONFUSION.001` | high | `dependency` | dependency_confusion |
| `SUSPECT.DEPENDENCY.SOURCE.001` | medium | `dependency` | policy |
| `SUSPECT.DEPENDENCY.TYPOSQUAT.001` | high | `dependency` | policy |
| `SUSPECT.DEPENDENCY.YANKED.001` | high | `registry` | policy |
| `SUSPECT.LOCKFILE.SOURCE.001` | medium | `lockfile` | integrity |
| `VULNERABLE.DEPENDENCY.KNOWN.001` | high | `advisory` | vulnerability |
| `VULNERABLE.PROVENANCE.INVALID.001` | critical | `provenance` | vulnerability |

### Domain 3 — Registries

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `SUSPECT.PACKAGE.PROVENANCE.001` | medium | `registry` | integrity |
| `SUSPECT.PACKAGE.REPOSITORY.001` | medium | `registry` | integrity |

### Domain 4 — Build systems

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.BUILD.UNPINNED_DEPENDENCY.001` | medium | `config` | policy |
| `SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001` | medium | `config` | integrity |
| `SUSPECT.BUILD.MAKE_FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001` | high | `config` | misconfiguration |

### Domain 5 — CI/CD

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.CI.SECRET_EXFIL.001` | critical | `config` | exfiltration |
| `POLICY.CI.UNPINNED_ACTION.001` | medium | `config` | policy |
| `POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001` | medium | `config` | policy |
| `POLICY.CI.WRITE_ALL_PERMISSIONS.001` | medium | `config` | policy |
| `SUSPECT.CI.ARTIFACT_POISONING.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.AZURE_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.CACHE_POISONING.001` | medium | `config` | misconfiguration |
| `SUSPECT.CI.CIRCLE_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.EXPRESSION_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.GITLAB_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.JENKINS_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.PR_TARGET.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.SECRET_EGRESS.001` | medium | `config` | misconfiguration |
| `SUSPECT.CI.SELF_HOSTED_FORK.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001` | high | `config` | misconfiguration |

### Domain 6 — Install and execution malware

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.ANTI_ANALYSIS.001` | critical | `composites` | malicious_code |
| `MALWARE.CRYPTOMINER.001` | critical | `composites` | cryptomining |
| `MALWARE.DROPPER.001` | critical | `composites` | dropper |
| `MALWARE.INSTALL.CONSUMER_CODE.001` | critical | `composites` | install_hook |
| `MALWARE.INSTALL.FETCH_EXEC.001` | critical | `manifest` | install_hook |
| `MALWARE.REVERSE_SHELL.001` | critical | `composites` | malicious_code |
| `SUSPECT.CRYPTOMINER.001` | high | `composites` | cryptomining |
| `SUSPECT.DECODE_CHAIN.001` | critical | `composites` | malicious_code |
| `SUSPECT.DOCKERFILE.ADD_REMOTE.001` | medium | `iac` | malicious_code |
| `SUSPECT.DOCKERFILE.SECRET_ARG.001` | high | `iac` | malicious_code |
| `SUSPECT.DROPPER.001` | high | `composites` | dropper |
| `SUSPECT.INSTALL.SCRIPT.001` | high | `manifest` | install_hook |
| `SUSPECT.PERSIST.001` | high | `composites` | persistence |
| `SUSPECT.REGISTRY.SELF_PUBLISH.001` | high | `composites` | malicious_code |

### Domain 7 — Obfuscation and evasion

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.DYNAMIC_DISPATCH.001` | critical | `composites` | obfuscation |
| `SUSPECT.ANTI_ANALYSIS.001` | high | `composites` | anti_analysis |
| `SUSPECT.DECODE_EXEC.001` | high | `composites` | obfuscation |
| `SUSPECT.DYNAMIC_DISPATCH.001` | high | `composites` | obfuscation |
| `SUSPECT.OBFUSCATION.BIDI.001` | high | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.ENCODED.001` | medium | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.LONGLINE.001` | low | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.PACKED.001` | medium | `obfuscation` | obfuscation |

### Domain 8 — Credentials and secret stores

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `SECRET.AIRTABLE.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.ALIBABA.ACCESS_KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.ANTHROPIC.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.ATLASSIAN.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.AWS.ACCESS_KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.AZURE.STORAGE_KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.DATABRICKS.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.DIGITALOCEAN.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.DISCORD.WEBHOOK.001` | high | `secrets` | secret_exposure |
| `SECRET.DOCKERHUB.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.DOPPLER.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.DROPBOX.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.FIGMA.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.FLYIO.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.GENERIC.ASSIGNMENT.001` | high | `secrets` | secret_exposure |
| `SECRET.GITHUB.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.GITLAB.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.GOOGLE.API_KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.GOOGLE.OAUTH_TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.GRAFANA.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.GROQ.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.HUGGINGFACE.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.JFROG.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.JWT.001` | medium | `secrets` | secret_exposure |
| `SECRET.LANGCHAIN.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.LINEAR.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.MAILGUN.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.MICROSOFT.TEAMS_WEBHOOK.001` | medium | `secrets` | secret_exposure |
| `SECRET.NETLIFY.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.NEWRELIC.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.NOTION.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.NPM.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.NUGET.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.OPENAI.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.PAGERDUTY.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.PAYPAL.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.PLANETSCALE.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.PRIVATE_KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.PYPI.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.REPLICATE.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.RESEND.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.RUBYGEMS.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.SENDGRID.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.SENTRY.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.SHOPIFY.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.SLACK.APP_TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.SLACK.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.SLACK.WEBHOOK.001` | medium | `secrets` | secret_exposure |
| `SECRET.SONAR.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.SQUARE.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.STRIPE.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.STRIPE.WEBHOOK_SECRET.001` | high | `secrets` | secret_exposure |
| `SECRET.SUPABASE.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.TELEGRAM.BOT_TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.TENCENT.SECRET_ID.001` | high | `secrets` | secret_exposure |
| `SECRET.TERRAFORM.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.TWILIO.KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.URL.CREDENTIAL.001` | high | `secrets` | secret_exposure |
| `SECRET.VAULT.TOKEN.001` | critical | `secrets` | secret_exposure |

### Domain 9 — Exfiltration channels

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.EXFIL.001` | critical | `composites` | exfiltration |
| `MALWARE.EXFIL.BEACON.001` | critical | `composites` | exfiltration |
| `MALWARE.EXFIL.CREDENTIAL_STORE.001` | critical | `composites` | exfiltration |
| `MALWARE.EXFIL.DROP_POINT.001` | critical | `composites` | exfiltration |
| `SUSPECT.EXFIL.001` | medium | `composites` | exfiltration |
| `SUSPECT.EXFIL.CREDENTIAL_STORE.001` | high | `composites` | exfiltration |
| `SUSPECT.EXFIL.DNS.001` | high | `composites` | exfiltration |
| `SUSPECT.EXFIL.DROP_POINT.001` | high | `composites` | exfiltration |

### Domain 10 — Containers and orchestration

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.CONTAINER.UNPINNED_BASE.001` | low | `config` | misconfiguration |
| `POLICY.K8S.AUTOMOUNT_TOKEN.001` | low | `iac` | policy |
| `POLICY.K8S.DEFAULT_SERVICE_ACCOUNT.001` | low | `iac` | policy |
| `POLICY.K8S.LATEST_TAG.001` | medium | `iac` | policy |
| `POLICY.K8S.NET_ADMIN.001` | medium | `config` | policy |
| `POLICY.K8S.NO_RESOURCE_LIMITS.001` | low | `iac` | policy |
| `POLICY.K8S.NO_RUN_AS_NON_ROOT.001` | medium | `iac` | policy |
| `POLICY.K8S.NO_SECCOMP.001` | low | `iac` | policy |
| `POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001` | low | `config` | policy |
| `POLICY.K8S.WRITABLE_ROOT.001` | low | `iac` | policy |
| `SUSPECT.COMPOSE.DANGEROUS_CAPABILITY.001` | high | `iac` | misconfiguration |
| `SUSPECT.COMPOSE.HOST_NETWORK.001` | medium | `iac` | misconfiguration |
| `SUSPECT.CONTAINER.BUILD_SECRET.001` | high | `config` | misconfiguration |
| `SUSPECT.CONTAINER.FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.HELM.UNTRUSTED_REPOSITORY.001` | medium | `config` | misconfiguration |
| `SUSPECT.K8S.CAPABILITIES.001` | high | `config` | misconfiguration |
| `SUSPECT.K8S.DANGEROUS_CAPABILITY.001` | high | `iac` | misconfiguration |
| `SUSPECT.K8S.HOST_IPC.001` | medium | `iac` | misconfiguration |
| `SUSPECT.K8S.HOST_NETWORK.001` | high | `iac` | misconfiguration |
| `SUSPECT.K8S.HOST_PID.001` | high | `iac` | misconfiguration |
| `SUSPECT.K8S.HOST_PORT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.K8S.PRIVILEGE_ESCALATION.001` | medium | `iac` | misconfiguration |
| `SUSPECT.K8S.RBAC_WILDCARD.001` | high | `config` | misconfiguration |
| `SUSPECT.K8S.RUN_AS_ROOT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.K8S.SECRET_ENV_VALUE.001` | high | `iac` | misconfiguration |

### Domain 11 — Infrastructure as code

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.CFN.ENCRYPT_AT_REST.DBINSTANCE.001` | high | `iac` | policy |
| `POLICY.CFN.ENCRYPT_AT_REST.FILESYSTEM.001` | medium | `iac` | policy |
| `POLICY.IAC.BACKUP.AWS_DB_INSTANCE_BACKUP_RETENTION_PERIOD.001` | medium | `iac` | policy |
| `POLICY.IAC.BACKUP.AWS_DOCDB_CLUSTER_BACKUP_RETENTION_PERIOD.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP.AWS_NEPTUNE_CLUSTER_BACKUP_RETENTION_PERIOD.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP.AWS_RDS_CLUSTER_BACKUP_RETENTION_PERIOD.001` | medium | `iac` | policy |
| `POLICY.IAC.BACKUP.AWS_REDSHIFT_CLUSTER_AUTOMATED_SNAPSHOT_RETENTION_PERIOD.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP.AZURERM_MYSQL_SERVER_BACKUP_RETENTION_DAYS.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP.AZURERM_POSTGRESQL_SERVER_BACKUP_RETENTION_DAYS.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AWS_DB_INSTANCE.001` | medium | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AWS_DOCDB_CLUSTER.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AWS_NEPTUNE_CLUSTER.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AWS_RDS_CLUSTER.001` | medium | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AWS_REDSHIFT_CLUSTER.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AZURERM_MYSQL_SERVER.001` | low | `iac` | policy |
| `POLICY.IAC.BACKUP_DISABLED.AZURERM_POSTGRESQL_SERVER.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_ALB_ENABLE_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DB_INSTANCE_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DOCDB_CLUSTER_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DYNAMODB_TABLE_DELETION_PROTECTION_ENABLED.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_LB_ENABLE_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_NEPTUNE_CLUSTER_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AWS_RDS_CLUSTER_DELETION_PROTECTION.001` | low | `iac` | policy |
| `POLICY.IAC.DELETION_PROTECTION.AZURERM_KEY_VAULT_PURGE_PROTECTION_ENABLED.001` | medium | `iac` | policy |
| `POLICY.IAC.DEPRECATED_RUNTIME.AWS_ELASTIC_BEANSTALK_ENVIRONMENT.001` | medium | `iac` | policy |
| `POLICY.IAC.DEPRECATED_RUNTIME.AWS_LAMBDA_FUNCTION.001` | medium | `iac` | policy |
| `POLICY.IAC.DEPRECATED_RUNTIME.AZURERM_LINUX_FUNCTION_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.DEPRECATED_RUNTIME.GOOGLE_CLOUDFUNCTIONS_FUNCTION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ATHENA_DATABASE_ENCRYPTION_CONFIGURATION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ATHENA_WORKGROUP_ENCRYPTION_CONFIGURATION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_BACKUP_VAULT.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CLOUDTRAIL_KMS_KEY_ID.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CLOUDWATCH_LOG_GROUP_KMS_KEY_ID.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CODEBUILD_PROJECT.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DAX_CLUSTER.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DB_INSTANCE.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DOCDB_CLUSTER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_VOLUME.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ECR_REPOSITORY.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EFS_FILE_SYSTEM.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EKS_CLUSTER.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ELASTICACHE_REPLICATION_GROUP.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ELASTICSEARCH_DOMAIN_ENCRYPT_AT_REST.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_FSX_LUSTRE_FILE_SYSTEM.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_GLUE_CATALOG_DATABASE_TARGET_DATABASE.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_KINESIS_FIREHOSE_DELIVERY_STREAM_SERVER_SIDE_ENCRYPTION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_KINESIS_STREAM_ENCRYPTION_TYPE.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_LAMBDA_FUNCTION_KMS_KEY_ARN.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_MEMORYDB_CLUSTER_KMS_KEY_ARN.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_MQ_BROKER_ENCRYPTION_OPTIONS.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_NEPTUNE_CLUSTER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPENSEARCH_DOMAIN_ENCRYPT_AT_REST.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_QLDB_LEDGER.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_RDS_CLUSTER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_RDS_GLOBAL_CLUSTER.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_REDSHIFT_CLUSTER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SAGEMAKER_ENDPOINT_CONFIGURATION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SECRETSMANAGER_SECRET_KMS_KEY_ID.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SNS_TOPIC_KMS_MASTER_KEY_ID.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SQS_QUEUE_KMS_MASTER_KEY_ID.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SSM_PARAMETER_KEY_ID.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_TIMESTREAMWRITE_DATABASE.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_TRANSFER_SERVER_POST_AUTHENTICATION_LOGIN_BANNER.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_WORKSPACES_WORKSPACE.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_COSMOSDB_ACCOUNT_KEY_VAULT_KEY_ID.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_EVENTHUB_NAMESPACE_LOCAL_AUTHENTICATION_ENABLED.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MANAGED_DISK.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MSSQL_DATABASE_TRANSPARENT_DATA_ENCRYPTION_ENABLED.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MYSQL_SERVER.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_POSTGRESQL_SERVER.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_STORAGE_ACCOUNT_INFRASTRUCTURE_ENCRYPTION_ENABLED.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_BIGQUERY_DATASET.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_BIGTABLE_INSTANCE_CLUSTER.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_CONTAINER_CLUSTER_DATABASE_ENCRYPTION.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_DATAPROC_CLUSTER.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_PUBSUB_TOPIC_KMS_KEY_NAME.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_SPANNER_DATABASE_ENCRYPTION_CONFIG.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_SQL_DATABASE_INSTANCE.001` | low | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_ELASTICACHE_REPLICATION_GROUP.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_APP_SERVICE.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_FUNCTION_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_FUNCTION_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_WEB_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_MARIADB_SERVER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_MYSQL_SERVER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_POSTGRESQL_SERVER.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_STORAGE_ACCOUNT.001` | high | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_FUNCTION_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_WEB_APP.001` | medium | `iac` | policy |
| `POLICY.IAC.KEY_ROTATION.AWS_KMS_KEY.001` | medium | `iac` | policy |
| `POLICY.IAC.KEY_ROTATION.GOOGLE_KMS_CRYPTO_KEY.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_ALB_ACCESS_LOGS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_APIGATEWAYV2_STAGE_ACCESS_LOG_SETTINGS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_API_GATEWAY_STAGE_ACCESS_LOG_SETTINGS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_API_GATEWAY_STAGE_XRAY_TRACING_ENABLED.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_CLOUDFRONT_DISTRIBUTION_LOGGING_CONFIG.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_CLOUDTRAIL_ENABLE_LOG_FILE_VALIDATION.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_CLOUDTRAIL_IS_MULTI_REGION_TRAIL.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_DOCDB_CLUSTER_ENABLED_CLOUDWATCH_LOGS_EXPORTS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_EKS_CLUSTER_ENABLED_CLUSTER_LOG_TYPES.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_ELASTICSEARCH_DOMAIN_LOG_PUBLISHING_OPTIONS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_GLOBALACCELERATOR_ACCELERATOR_ATTRIBUTES.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_LAMBDA_FUNCTION_TRACING_CONFIG.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_LB_ACCESS_LOGS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_MQ_BROKER_LOGS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_MSK_CLUSTER_LOGGING_INFO.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_NEPTUNE_CLUSTER_ENABLE_CLOUDWATCH_LOGS_EXPORTS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_OPENSEARCH_DOMAIN_LOG_PUBLISHING_OPTIONS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_REDSHIFT_CLUSTER_LOGGING.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_S3_BUCKET_LOGGING_TARGET_BUCKET.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AWS_VPC_ENABLE_DNS_HOSTNAMES.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AZURERM_KEY_VAULT_SOFT_DELETE_RETENTION_DAYS.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AZURERM_KUBERNETES_CLUSTER_OMS_AGENT.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.AZURERM_MSSQL_SERVER_EXTENDED_AUDITING_POLICY.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_SUBNETWORK_LOG_CONFIG.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.GOOGLE_CONTAINER_CLUSTER_LOGGING_SERVICE.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.GOOGLE_CONTAINER_CLUSTER_MONITORING_SERVICE.001` | low | `iac` | policy |
| `POLICY.IAC.LOGGING.GOOGLE_SQL_DATABASE_INSTANCE_BACKUP_CONFIGURATION.001` | medium | `iac` | policy |
| `POLICY.IAC.LOGGING.GOOGLE_STORAGE_BUCKET_LOGGING.001` | low | `iac` | policy |
| `POLICY.IAC.MUTABLE_TAGS.AWS_ECR_REPOSITORY.001` | medium | `iac` | policy |
| `POLICY.IAC.NO_MFA.AWS_IAM_USER.001` | low | `iac` | policy |
| `POLICY.IAC.SCAN_ON_PUSH.AWS_ECR_REPOSITORY.001` | low | `iac` | policy |
| `POLICY.IAC.SQL_REQUIRE_SSL.GOOGLE_SQL_DATABASE_INSTANCE.001` | medium | `iac` | policy |
| `POLICY.IAC.UNENCRYPTED_STATE.TERRAFORM.001` | high | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AWS_API_GATEWAY_DOMAIN_NAME.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AWS_LB_LISTENER.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AZURERM_APP_SERVICE.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AZURERM_MSSQL_SERVER.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AZURERM_REDIS_CACHE.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.AZURERM_STORAGE_ACCOUNT.001` | medium | `iac` | policy |
| `POLICY.IAC.WEAK_TLS.GOOGLE_COMPUTE_SSL_POLICY.001` | medium | `iac` | policy |
| `SUSPECT.CFN.IAM_WILDCARD.POLICY.001` | high | `iac` | misconfiguration |
| `SUSPECT.CFN.OPEN_INGRESS.SECURITYGROUP.001` | high | `iac` | misconfiguration |
| `SUSPECT.CFN.PLAINTEXT.LISTENER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.CFN.PUBLIC_ACCESS.DBINSTANCE.001` | high | `iac` | misconfiguration |
| `SUSPECT.CFN.PUBLIC_STORAGE.BUCKET.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.ADMIN_ENABLED.AZURERM_CONTAINER_REGISTRY.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.CREDENTIALS_INLINE.TERRAFORM.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.HOST_MOUNT.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.IAM_WILDCARD.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.IMDSV1.AWS_INSTANCE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.LEGACY_ABAC.GOOGLE_CONTAINER_CLUSTER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.LOCAL_EXEC.TERRAFORM.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.NO_AUTH.AWS_API_GATEWAY_METHOD.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.OWNER_ROLE.AZURERM_ROLE_ASSIGNMENT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.OWNER_ROLE.GOOGLE_PROJECT_IAM_MEMBER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PASSWORD_AUTH.AZURERM_LINUX_VIRTUAL_MACHINE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PLAINTEXT.AWS_LB_LISTENER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PLAINTEXT.AWS_MSK_CLUSTER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PLAINTEXT.AZURERM_REDIS_CACHE.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PRIVILEGED.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.PRIVILEGED_BUILD.AWS_CODEBUILD_PROJECT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DB_INSTANCE.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DMS_REPLICATION_INSTANCE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DOCDB_CLUSTER_INSTANCE.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_RDS_CLUSTER_INSTANCE.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_REDSHIFT_CLUSTER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_CONTAINER_REGISTRY.001` | low | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_COSMOSDB_ACCOUNT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_KEY_VAULT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MSSQL_SERVER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MYSQL_SERVER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_POSTGRESQL_SERVER.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_REDIS_CACHE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_STORAGE_ACCOUNT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.BLOCK_PUBLIC_ACLS.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.BLOCK_PUBLIC_POLICY.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.IGNORE_PUBLIC_ACLS.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.RESTRICT_PUBLIC_BUCKETS.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_IAM.GOOGLE_PROJECT_IAM_MEMBER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_INGRESS.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_SQL.GOOGLE_SQL_DATABASE_INSTANCE.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.AWS_S3_BUCKET.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.AWS_S3_BUCKET_ACL.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.AZURERM_STORAGE_ACCOUNT.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.AZURERM_STORAGE_CONTAINER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_ACCESS_CONTROL.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_IAM_BINDING.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_IAM_MEMBER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.RBAC_DISABLED.AZURERM_KUBERNETES_CLUSTER.001` | high | `iac` | misconfiguration |
| `SUSPECT.IAC.ROOT_ACCESS.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.SERIAL_PORT.GOOGLE_COMPUTE_INSTANCE.001` | medium | `iac` | misconfiguration |
| `SUSPECT.IAC.WILDCARD_PRINCIPAL.AWS_IAM_POLICY.001` | high | `iac` | misconfiguration |

### Domain 12 — Binaries and artefacts

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.BINARY.COMMITTED.001` | low | `binary` | policy |
| `SUSPECT.BINARY.EXECUTABLE_PATH.001` | high | `binary` | integrity |
| `SUSPECT.BINARY.PACKED.001` | medium | `binary` | integrity |
| `SUSPECT.BINARY.STRINGS.001` | medium | `binary` | integrity |

### Domain 13 — Provenance and integrity

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.PROVENANCE.UNVERIFIED.001` | low | `provenance` | integrity |
| `POLICY.RELEASE.NO_PROVENANCE.001` | low | `attestation` | integrity |
| `SUSPECT.PROVENANCE.MISMATCH.001` | critical | `registry` | integrity |
| `SUSPECT.SBOM.DRIFT.001` | medium | `sbom` | integrity |

### Domain 14 — The scanner itself

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `OPERATIONAL.PROVENANCE.NOT_CHECKED.001` | low | `provenance` | coverage |
| `OPERATIONAL.REGISTRY.NOT_ASKED.001` | low | `registry` | coverage |
| `OPERATIONAL.REGISTRY.NO_SOURCE.001` | low | `registry` | coverage |
| `OPERATIONAL.REGISTRY.UNREACHABLE.001` | low | `registry` | coverage |
| `OPERATIONAL.SBOM.UNREADABLE.001` | low | `sbom` | coverage |
| `OPERATIONAL.VCS.UNREADABLE.001` | low | `vcs` | coverage |
| `POLICY.DOCKERFILE.NO_HEALTHCHECK.001` | low | `iac` | policy |
| `POLICY.DOCKERFILE.ROOT_USER.001` | medium | `iac` | policy |
| `POLICY.DOCKERFILE.SUDO.001` | low | `iac` | policy |
