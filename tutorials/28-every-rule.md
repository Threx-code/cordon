# 28 · Every rule

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

All 1,385 detection rules Cordon defines itself, grouped by what they watch, with the
severity each reports at, and after them every Agent Threat Rule it carries. Rendered from the detectors and rule packs themselves. `cordon-scanner rules
show <id>` prints one in full, with its remediation and references; `rules test` runs every
rule's own samples.

```
   MALWARE.*       evidence of intent to harm: fails the build by default
   SUSPECT.*       a behaviour or shape attackers use: worth a look
   VULNERABLE.*    a known vulnerability in what you ship
   SECRET.*        a credential in the code or its history
   POLICY.*        a choice the project made about itself
   OPERATIONAL.*   what the scan could not do, said out loud
```


## AI agents

32 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.AGENT.AUTORUN.001` | critical | A command an editor or agent runs on its own attacks the machine |
| `MALWARE.AGENT.HOOK_EXFIL.001` | critical | An agent hook that sends credentials away or opens a remote shell |
| `MALWARE.AGENT.HOOK_FETCH_EXEC.001` | critical | An agent hook that fetches and executes remote code |
| `POLICY.AGENT.AUTO_APPROVE.001` | high | Agent confirmations switched off in committed settings |
| `POLICY.AGENT.MCP_BROAD_SCOPE.001` | medium | A filesystem MCP server given the whole disk or home directory |
| `POLICY.AGENT.WIDE_DIRECTORY.001` | medium | Agent given the whole disk or home directory to work in |
| `POLICY.AGENT.WILDCARD_PERMISSION.001` | medium | Agent permissions allow any shell command |
| `SUSPECT.AGENT.API_REDIRECT.001` | high | Agent API traffic redirected to a host that is not the provider |
| `SUSPECT.AGENT.ATR.AGENT_MANIPULATION.001` | medium | Text that impersonates an agent or hijacks the agent's task |
| `SUSPECT.AGENT.ATR.CONTEXT_EXFILTRATION.001` | medium | Text that asks an agent to move secrets or context off the machine |
| `SUSPECT.AGENT.ATR.DATA_POISONING.001` | medium | Text that plants triggers or false facts for an agent |
| `SUSPECT.AGENT.ATR.EXCESSIVE_AUTONOMY.001` | medium | Text that asks an agent to act without the user's confirmation |
| `SUSPECT.AGENT.ATR.MODEL_ABUSE.001` | medium | Text that turns an agent toward abuse of the model |
| `SUSPECT.AGENT.ATR.MODEL_SECURITY.001` | medium | Text that targets the model's weights or safety |
| `SUSPECT.AGENT.ATR.PRIVILEGE_ESCALATION.001` | medium | Text that asks an agent to widen its own permissions |
| `SUSPECT.AGENT.ATR.PROMPT_INJECTION.001` | medium | Text that tries to override an agent's instructions |
| `SUSPECT.AGENT.ATR.SKILL_COMPROMISE.001` | medium | A skill or plugin shaped like a known compromise |
| `SUSPECT.AGENT.ATR.TOOL_POISONING.001` | medium | Text that turns a tool into a channel for steering the agent |
| `SUSPECT.AGENT.CI_PROMPT_INJECTION.001` | high | Untrusted event text passed straight into an agent's prompt |
| `SUSPECT.AGENT.CI_UNTRUSTED_TRIGGER.001` | high | An AI agent in CI reads text an outsider can write |
| `SUSPECT.AGENT.CREDENTIAL_EXFIL.001` | critical | Agent instructions that move credentials somewhere |
| `SUSPECT.AGENT.FETCH_EXEC.001` | high | Agent instructions that fetch and execute remote code |
| `SUSPECT.AGENT.HIDDEN_TEXT.001` | high | Hidden characters in an agent instruction file |
| `SUSPECT.AGENT.HOOK.001` | medium | An agent hook committed to the repository |
| `SUSPECT.AGENT.INJECTION_TEXT.001` | medium | Instruction-like text aimed at a coding agent |
| `SUSPECT.AGENT.INTENT.001` | high | Text that tells the agent to act against its user |
| `SUSPECT.AGENT.INTENT_CHAINED.001` | high | Agent instructions that send the agent to a file that acts against its user |
| `SUSPECT.AGENT.JUDGED.001` | medium | A language model judges agent-facing text to be subverting the agent |
| `SUSPECT.AGENT.PLUGIN_SOURCE.001` | high | Agent plugins installed from an unverified source |
| `SUSPECT.AGENT.REMOTE_INSTRUCTIONS.001` | medium | An agent instruction file tells the agent to fetch and follow remote text |
| `SUSPECT.AGENT.SENSITIVE_IMPORT.001` | high | An agent instruction file imports a credential file |
| `VULNERABLE.AGENT.ACTION_VERSION.001` | high | An AI agent action below its security fix |

## Anti Analysis

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.ANTI_ANALYSIS.001` | critical | Install-time code that checks whether it is being watched |
| `SUSPECT.ANTI_ANALYSIS.001` | high | Behaviour gated on whether it is being observed |

## Archive

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.ARCHIVE.NESTING.001` | high | Archives nested past the depth the scan opens |
| `SUSPECT.ARCHIVE.PATH_ESCAPE.001` | high | Archive member named to write outside the archive |
| `SUSPECT.ARCHIVE.POLYGLOT.001` | high | Archive that is a tarball and a zip at once |

## Azure

16 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.AZURE.DELETION_PROTECTION.KEYVAULT_VAULTS_ENABLEPURGEPROTECTION.001` | medium | Microsoft.KeyVault/vaults: a deleted vault can be purged immediately |
| `POLICY.AZURE.DELETION_PROTECTION.KEYVAULT_VAULTS_ENABLESOFTDELETE.001` | medium | Microsoft.KeyVault/vaults: a deleted secret is gone immediately |
| `POLICY.AZURE.RBAC.KEYVAULT_VAULTS_ENABLERBACAUTHORIZATION.001` | low | Microsoft.KeyVault/vaults: access is governed by vault access policies rather than RBAC |
| `POLICY.AZURE.SHARED_KEY_AUTH.ANY_DISABLELOCALAUTH.001` | medium | Microsoft.*: shared-key authentication is enabled |
| `POLICY.AZURE.SHARED_KEY_AUTH.STORAGE_STORAGEACCOUNTS_ALLOWSHAREDKEYACCESS.001` | medium | Microsoft.Storage/storageAccounts: the account key authenticates callers |
| `POLICY.AZURE.WEAK_TLS.STORAGE_STORAGEACCOUNTS_MINIMUMTLSVERSION.001` | medium | Microsoft.Storage/storageAccounts: an obsolete TLS version is accepted |
| `SUSPECT.AZURE.NETWORK_DEFAULT_ALLOW.ANY_DEFAULTACTION.001` | medium | Microsoft.*: the network rules default to allowing everything |
| `SUSPECT.AZURE.NO_AUTH.CONTAINERREGISTRY_REGISTRIES_ANONYMOUSPULLENABLED.001` | high | Microsoft.ContainerRegistry/registries: anyone may pull images from the registry |
| `SUSPECT.AZURE.OPEN_INGRESS.NETWORK_NETWORKSECURITYGROUPS_SOURCEADDRESSPREFIX.001` | high | Microsoft.Network/networkSecurityGroups: an administrative port is open to the whole internet |
| `SUSPECT.AZURE.PASSWORD_AUTH.COMPUTE_VIRTUALMACHINES_DISABLEPASSWORDAUTHENTICATION.001` | medium | Microsoft.Compute/virtualMachines: SSH password authentication is enabled |
| `SUSPECT.AZURE.PLAINTEXT.STORAGE_STORAGEACCOUNTS_SUPPORTSHTTPSTRAFFICONLY.001` | high | Microsoft.Storage/storageAccounts: the storage account accepts plain HTTP |
| `SUSPECT.AZURE.PLAINTEXT.WEB_SITES_FTPSSTATE.001` | medium | Microsoft.Web/sites: deployment over plain FTP is allowed |
| `SUSPECT.AZURE.PLAINTEXT.WEB_SITES_HTTPSONLY.001` | medium | Microsoft.Web/sites: the site answers plain HTTP |
| `SUSPECT.AZURE.PUBLIC_ACCESS.ANY_PUBLICNETWORKACCESS.001` | medium | Microsoft.*: the resource answers on a public endpoint |
| `SUSPECT.AZURE.PUBLIC_STORAGE.STORAGE_STORAGEACCOUNTS_ALLOWBLOBPUBLICACCESS.001` | high | Microsoft.Storage/storageAccounts: containers may be made public |
| `SUSPECT.AZURE.SHARED_KEY_AUTH.CONTAINERREGISTRY_REGISTRIES_ADMINUSERENABLED.001` | medium | Microsoft.ContainerRegistry/registries: the shared admin account is enabled |

## Binary

10 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.BINARY.COMMITTED.001` | low | Executable committed to a source repository |
| `SUSPECT.BINARY.CREDENTIAL_THEFT.001` | high | Committed binary imports credential-store and network calls |
| `SUSPECT.BINARY.EXECUTABLE_PATH.001` | high | Executable committed where a lifecycle step will run it |
| `SUSPECT.BINARY.HIDDEN_IMPORTS.001` | medium | Committed binary resolves its imports at run time |
| `SUSPECT.BINARY.IMPLANT.001` | high | Committed binary imports download-and-run calls |
| `SUSPECT.BINARY.KEYLOGGER.001` | medium | Committed binary imports keyboard-capture and network calls |
| `SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001` | high | A pure-Python wheel loads a native library it carries |
| `SUSPECT.BINARY.PACKED.001` | medium | Committed binary is packed |
| `SUSPECT.BINARY.PROCESS_INJECTION.001` | high | Committed binary imports process-injection calls |
| `SUSPECT.BINARY.STRINGS.001` | medium | Committed binary contains a URL, command or credential path |

## Build

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.BUILD.UNPINNED_DEPENDENCY.001` | medium | Build dependency resolves to whatever is newest, not a fixed version |
| `POLICY.BUILD.WRAPPER_UNVERIFIED.001` | low | Build wrapper downloads its tool without a checksum |
| `SUSPECT.BUILD.CMAKE_FETCH_UNVERIFIED.001` | medium | CMake fetches a URL with nothing verifying what it downloaded |
| `SUSPECT.BUILD.MAKE_FETCH_EXEC.001` | high | Makefile recipe fetches and executes remote content |
| `SUSPECT.BUILD.MSBUILD_FETCH_EXEC.001` | high | MSBuild target fetches and executes remote content |

## CI/CD pipelines

19 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.CI.SECRET_EXFIL.001` | critical | CI workflow serialises its secret context |
| `POLICY.CI.UNPINNED_ACTION.001` | medium | Action referenced by a mutable tag |
| `POLICY.CI.UNPINNED_REUSABLE_WORKFLOW.001` | medium | Reusable workflow called by a mutable ref |
| `POLICY.CI.WRITE_ALL_PERMISSIONS.001` | medium | Workflow token is granted every write scope |
| `SUSPECT.CI.ARTIFACT_POISONING.001` | high | Untrusted build uploads or restores a cache it can control |
| `SUSPECT.CI.AZURE_INJECTION.001` | high | Azure Pipelines script interpolates a contributor-controlled value |
| `SUSPECT.CI.BITBUCKET_INJECTION.001` | high | Bitbucket Pipelines step re-parses a contributor-controlled branch name |
| `SUSPECT.CI.BUILDKITE_INJECTION.001` | high | Buildkite pipeline interpolates a contributor-controlled value at upload |
| `SUSPECT.CI.CACHE_POISONING.001` | medium | A publishing workflow restores a cache an untrusted run can write |
| `SUSPECT.CI.CIRCLE_INJECTION.001` | high | CircleCI step interpolates a contributor-controlled pipeline value |
| `SUSPECT.CI.EXPRESSION_INJECTION.001` | high | Untrusted pipeline input interpolated into a shell command |
| `SUSPECT.CI.FETCH_EXEC.001` | high | CI step fetches and executes remote content |
| `SUSPECT.CI.GITLAB_INJECTION.001` | high | GitLab job interpolates a contributor-controlled variable into a script |
| `SUSPECT.CI.JENKINS_INJECTION.001` | high | Jenkins shell step interpolates a contributor-controlled value |
| `SUSPECT.CI.PR_TARGET.001` | high | Workflow uses pull_request_target and checks out the pull request head |
| `SUSPECT.CI.SECRET_EGRESS.001` | medium | Pipeline step reads a secret and sends data off the runner |
| `SUSPECT.CI.SECRET_OVERPROVISION.001` | high | CI workflow hands another workflow every secret it has |
| `SUSPECT.CI.SELF_HOSTED_FORK.001` | high | A fork's pull request runs on a self-hosted runner |
| `SUSPECT.CI.WORKFLOW_RUN_CHECKOUT.001` | high | workflow_run checks out the commit that triggered it |

## ClamAV

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.CLAMAV.SIGNATURE.001` | critical | ClamAV recognises the file as malware |
| `OPERATIONAL.CLAMAV.STATUS` | info | ClamAV examined the scan's files |
| `OPERATIONAL.CLAMAV.UNAVAILABLE` | info | ClamAV was asked for and could not be used |

## CloudFormation

232 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.CFN.CMEK.AWS_AIOPS_INVESTIGATIONGROUP.001` | low | cfn:AWS::AIOps::InvestigationGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_AMAZONMQ_BROKER.001` | low | cfn:AWS::AmazonMQ::Broker: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_APS_WORKSPACE.001` | low | cfn:AWS::APS::Workspace: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BACKUPGATEWAY_HYPERVISOR.001` | low | cfn:AWS::BackupGateway::Hypervisor: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCKAGENTCORE_CAPACITYPROVIDER.001` | low | cfn:AWS::BedrockAgentCore::CapacityProvider: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCKAGENTCORE_CONFIGURATIONBUNDLE.001` | low | cfn:AWS::BedrockAgentCore::ConfigurationBundle: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCKAGENTCORE_DATASET.001` | low | cfn:AWS::BedrockAgentCore::Dataset: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCKAGENTCORE_EVALUATOR.001` | low | cfn:AWS::BedrockAgentCore::Evaluator: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCKAGENTCORE_GATEWAY.001` | low | cfn:AWS::BedrockAgentCore::Gateway: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_AUTOMATEDREASONINGPOLICY.001` | low | cfn:AWS::Bedrock::AutomatedReasoningPolicy: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_BLUEPRINT.001` | low | cfn:AWS::Bedrock::Blueprint: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_DATAAUTOMATIONLIBRARY.001` | low | cfn:AWS::Bedrock::DataAutomationLibrary: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_DATAAUTOMATIONPROJECT.001` | low | cfn:AWS::Bedrock::DataAutomationProject: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_DATASOURCE.001` | low | cfn:AWS::Bedrock::DataSource: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_GUARDRAIL.001` | low | cfn:AWS::Bedrock::Guardrail: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_BEDROCK_KNOWLEDGEBASE.001` | low | cfn:AWS::Bedrock::KnowledgeBase: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_CLEANROOMSML_CONFIGUREDMODELALGORITHM.001` | low | cfn:AWS::CleanRoomsML::ConfiguredModelAlgorithm: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_CLEANROOMS_IDMAPPINGTABLE.001` | low | cfn:AWS::CleanRooms::IdMappingTable: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_CLEANROOMS_INTERMEDIATETABLE.001` | low | cfn:AWS::CleanRooms::IntermediateTable: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_CLOUDTRAIL_EVENTDATASTORE.001` | low | cfn:AWS::CloudTrail::EventDataStore: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_CODECOMMIT_REPOSITORY.001` | low | cfn:AWS::CodeCommit::Repository: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_COGNITO_USERPOOL.001` | low | cfn:AWS::Cognito::UserPool: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_COMPREHEND_DOCUMENTCLASSIFIER.001` | low | cfn:AWS::Comprehend::DocumentClassifier: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATAEXCHANGE_EVENTACTION.001` | low | cfn:AWS::DataExchange::EventAction: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONAZUREBLOB.001` | low | cfn:AWS::DataSync::LocationAzureBlob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONFSXONTAP.001` | low | cfn:AWS::DataSync::LocationFSxONTAP: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONFSXWINDOWS.001` | low | cfn:AWS::DataSync::LocationFSxWindows: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONHDFS.001` | low | cfn:AWS::DataSync::LocationHDFS: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONOBJECTSTORAGE.001` | low | cfn:AWS::DataSync::LocationObjectStorage: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DATASYNC_LOCATIONSMB.001` | low | cfn:AWS::DataSync::LocationSMB: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DEADLINE_FARM.001` | low | cfn:AWS::Deadline::Farm: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DEVOPSAGENT_AGENTSPACE.001` | low | cfn:AWS::DevOpsAgent::AgentSpace: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DEVOPSAGENT_SERVICE.001` | low | cfn:AWS::DevOpsAgent::Service: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DMS_ENDPOINT.001` | low | cfn:AWS::DMS::Endpoint: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DMS_INSTANCEPROFILE.001` | low | cfn:AWS::DMS::InstanceProfile: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DMS_REPLICATIONCONFIG.001` | low | cfn:AWS::DMS::ReplicationConfig: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DMS_REPLICATIONINSTANCE.001` | low | cfn:AWS::DMS::ReplicationInstance: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DOCDBELASTIC_CLUSTER.001` | low | cfn:AWS::DocDBElastic::Cluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_DOCDB_DBCLUSTER.001` | low | cfn:AWS::DocDB::DBCluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EC2_VERIFIEDACCESSENDPOINT.001` | low | cfn:AWS::EC2::VerifiedAccessEndpoint: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EC2_VERIFIEDACCESSGROUP.001` | low | cfn:AWS::EC2::VerifiedAccessGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EC2_VERIFIEDACCESSTRUSTPROVIDER.001` | low | cfn:AWS::EC2::VerifiedAccessTrustProvider: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EC2_VOLUME.001` | low | cfn:AWS::EC2::Volume: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_ECS_CLUSTER.001` | low | cfn:AWS::ECS::Cluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EFS_FILESYSTEM.001` | low | cfn:AWS::EFS::FileSystem: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_ELASTICACHE_REPLICATIONGROUP.001` | low | cfn:AWS::ElastiCache::ReplicationGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_ELASTICACHE_SERVERLESSCACHE.001` | low | cfn:AWS::ElastiCache::ServerlessCache: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_ELASTICACHE_SERVERLESSCACHESNAPSHOT.001` | low | cfn:AWS::ElastiCache::ServerlessCacheSnapshot: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_ELASTICSEARCH_DOMAIN.001` | low | cfn:AWS::Elasticsearch::Domain: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_EVS_ENVIRONMENT.001` | low | cfn:AWS::EVS::Environment: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_FINSPACE_ENVIRONMENT.001` | low | cfn:AWS::FinSpace::Environment: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_FORECAST_DATASET.001` | low | cfn:AWS::Forecast::Dataset: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_FSX_FILECACHE.001` | low | cfn:AWS::FSx::FileCache: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_FSX_FILESYSTEM.001` | low | cfn:AWS::FSx::FileSystem: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GLUE_CONNECTION.001` | low | cfn:AWS::Glue::Connection: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GLUE_DATACATALOGENCRYPTIONSETTINGS.001` | low | cfn:AWS::Glue::DataCatalogEncryptionSettings: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GLUE_INTEGRATION.001` | low | cfn:AWS::Glue::Integration: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GLUE_MLTRANSFORM.001` | low | cfn:AWS::Glue::MLTransform: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GLUE_SECURITYCONFIGURATION.001` | low | cfn:AWS::Glue::SecurityConfiguration: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GROUNDSTATION_MISSIONPROFILE.001` | low | cfn:AWS::GroundStation::MissionProfile: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_GUARDDUTY_PUBLISHINGDESTINATION.001` | low | cfn:AWS::GuardDuty::PublishingDestination: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_HEALTHIMAGING_DATASTORE.001` | low | cfn:AWS::HealthImaging::Datastore: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_HEALTHLAKE_DATATRANSFORMATIONPROFILE.001` | low | cfn:AWS::HealthLake::DataTransformationProfile: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_HEALTHLAKE_FHIRDATASTORE.001` | low | cfn:AWS::HealthLake::FHIRDatastore: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_IMAGEBUILDER_COMPONENT.001` | low | cfn:AWS::ImageBuilder::Component: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_IMAGEBUILDER_CONTAINERRECIPE.001` | low | cfn:AWS::ImageBuilder::ContainerRecipe: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_IMAGEBUILDER_WORKFLOW.001` | low | cfn:AWS::ImageBuilder::Workflow: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_IOTSITEWISE_WORKSPACE.001` | low | cfn:AWS::IoTSiteWise::Workspace: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_IOT_ENCRYPTIONCONFIGURATION.001` | low | cfn:AWS::IoT::EncryptionConfiguration: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_KENDRA_INDEX.001` | low | cfn:AWS::Kendra::Index: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_KINESISVIDEO_STREAM.001` | low | cfn:AWS::KinesisVideo::Stream: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LAMBDA_CAPACITYPROVIDER.001` | low | cfn:AWS::Lambda::CapacityProvider: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LAMBDA_EVENTSOURCEMAPPING.001` | low | cfn:AWS::Lambda::EventSourceMapping: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LAMBDA_FUNCTION.001` | low | cfn:AWS::Lambda::Function: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOCATION_GEOFENCECOLLECTION.001` | low | cfn:AWS::Location::GeofenceCollection: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOCATION_TRACKER.001` | low | cfn:AWS::Location::Tracker: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOGS_INTEGRATION.001` | low | cfn:AWS::Logs::Integration: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOGS_LOGANOMALYDETECTOR.001` | low | cfn:AWS::Logs::LogAnomalyDetector: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOGS_LOGGROUP.001` | low | cfn:AWS::Logs::LogGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_LOOKOUTEQUIPMENT_INFERENCESCHEDULER.001` | low | cfn:AWS::LookoutEquipment::InferenceScheduler: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_M2_APPLICATION.001` | low | cfn:AWS::M2::Application: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_M2_ENVIRONMENT.001` | low | cfn:AWS::M2::Environment: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_MEMORYDB_CLUSTER.001` | low | cfn:AWS::MemoryDB::Cluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_MEMORYDB_SNAPSHOT.001` | low | cfn:AWS::MemoryDB::Snapshot: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_MSK_CHANNEL.001` | low | cfn:AWS::MSK::Channel: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_MWAASERVERLESS_WORKFLOW.001` | low | cfn:AWS::MWAAServerless::Workflow: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_NEPTUNE_DBCLUSTER.001` | low | cfn:AWS::Neptune::DBCluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OBSERVABILITYADMIN_ORGANIZATIONTELEMETRYRULE.001` | low | cfn:AWS::ObservabilityAdmin::OrganizationTelemetryRule: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OBSERVABILITYADMIN_S3TABLEINTEGRATION.001` | low | cfn:AWS::ObservabilityAdmin::S3TableIntegration: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OBSERVABILITYADMIN_TELEMETRYRULE.001` | low | cfn:AWS::ObservabilityAdmin::TelemetryRule: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OPENSEARCHSERVERLESS_COLLECTION.001` | low | cfn:AWS::OpenSearchServerless::Collection: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OPENSEARCHSERVICE_APPLICATION.001` | low | cfn:AWS::OpenSearchService::Application: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OPENSEARCHSERVICE_DOMAIN.001` | low | cfn:AWS::OpenSearchService::Domain: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_OSIS_PIPELINE.001` | low | cfn:AWS::OSIS::Pipeline: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_PERSONALIZE_DATASETEXPORTJOB.001` | low | cfn:AWS::Personalize::DatasetExportJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_PERSONALIZE_DATASETGROUP.001` | low | cfn:AWS::Personalize::DatasetGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_PERSONALIZE_METRICATTRIBUTION.001` | low | cfn:AWS::Personalize::MetricAttribution: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_QBUSINESS_APPLICATION.001` | low | cfn:AWS::QBusiness::Application: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_RDS_DBCLUSTER.001` | low | cfn:AWS::RDS::DBCluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_REDSHIFTSERVERLESS_NAMESPACE.001` | low | cfn:AWS::RedshiftServerless::Namespace: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_REDSHIFT_CLUSTER.001` | low | cfn:AWS::Redshift::Cluster: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_REDSHIFT_SNAPSHOTCOPYGRANT.001` | low | cfn:AWS::Redshift::SnapshotCopyGrant: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_REKOGNITION_STREAMPROCESSOR.001` | low | cfn:AWS::Rekognition::StreamProcessor: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_RESILIENCEHUBV2_POLICY.001` | low | cfn:AWS::ResilienceHubV2::Policy: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_RESILIENCEHUBV2_SERVICE.001` | low | cfn:AWS::ResilienceHubV2::Service: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_RESILIENCEHUBV2_SYSTEM.001` | low | cfn:AWS::ResilienceHubV2::System: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_S3FILES_FILESYSTEM.001` | low | cfn:AWS::S3Files::FileSystem: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_S3VECTORS_INDEX.001` | low | cfn:AWS::S3Vectors::Index: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_S3VECTORS_VECTORBUCKET.001` | low | cfn:AWS::S3Vectors::VectorBucket: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_S3_BUCKET.001` | low | cfn:AWS::S3::Bucket: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_AUTOMLJOB.001` | low | cfn:AWS::SageMaker::AutoMLJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_DATAQUALITYJOBDEFINITION.001` | low | cfn:AWS::SageMaker::DataQualityJobDefinition: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_DEVICEFLEET.001` | low | cfn:AWS::SageMaker::DeviceFleet: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_DOMAIN.001` | low | cfn:AWS::SageMaker::Domain: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_ENDPOINTCONFIG.001` | low | cfn:AWS::SageMaker::EndpointConfig: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_FEATUREGROUP.001` | low | cfn:AWS::SageMaker::FeatureGroup: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_HYPERPARAMETERTUNINGJOB.001` | low | cfn:AWS::SageMaker::HyperParameterTuningJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MODELBIASJOBDEFINITION.001` | low | cfn:AWS::SageMaker::ModelBiasJobDefinition: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MODELCARD.001` | low | cfn:AWS::SageMaker::ModelCard: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MODELEXPLAINABILITYJOBDEFINITION.001` | low | cfn:AWS::SageMaker::ModelExplainabilityJobDefinition: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MODELPACKAGE.001` | low | cfn:AWS::SageMaker::ModelPackage: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MODELQUALITYJOBDEFINITION.001` | low | cfn:AWS::SageMaker::ModelQualityJobDefinition: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_MONITORINGSCHEDULE.001` | low | cfn:AWS::SageMaker::MonitoringSchedule: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_NOTEBOOKINSTANCE.001` | low | cfn:AWS::SageMaker::NotebookInstance: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_OPTIMIZATIONJOB.001` | low | cfn:AWS::SageMaker::OptimizationJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_PARTNERAPP.001` | low | cfn:AWS::SageMaker::PartnerApp: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_PROCESSINGJOB.001` | low | cfn:AWS::SageMaker::ProcessingJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_TRAININGJOB.001` | low | cfn:AWS::SageMaker::TrainingJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SAGEMAKER_TRANSFORMJOB.001` | low | cfn:AWS::SageMaker::TransformJob: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SCHEDULER_SCHEDULE.001` | low | cfn:AWS::Scheduler::Schedule: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECRETSMANAGER_ROTATIONSCHEDULE.001` | low | cfn:AWS::SecretsManager::RotationSchedule: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECRETSMANAGER_SECRET.001` | low | cfn:AWS::SecretsManager::Secret: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECURITYAGENT_AGENTSPACE.001` | low | cfn:AWS::SecurityAgent::AgentSpace: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECURITYAGENT_SECURITYREQUIREMENTPACK.001` | low | cfn:AWS::SecurityAgent::SecurityRequirementPack: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECURITYHUB_CONNECTORV2.001` | low | cfn:AWS::SecurityHub::ConnectorV2: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SECURITYLAKE_DATALAKE.001` | low | cfn:AWS::SecurityLake::DataLake: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SES_MAILMANAGERARCHIVE.001` | low | cfn:AWS::SES::MailManagerArchive: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SES_MAILMANAGERINGRESSPOINT.001` | low | cfn:AWS::SES::MailManagerIngressPoint: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SNS_TOPIC.001` | low | cfn:AWS::SNS::Topic: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SQS_QUEUE.001` | low | cfn:AWS::SQS::Queue: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_STEPFUNCTIONS_ACTIVITY.001` | low | cfn:AWS::StepFunctions::Activity: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_STEPFUNCTIONS_STATEMACHINE.001` | low | cfn:AWS::StepFunctions::StateMachine: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_SYNTHETICS_CANARY.001` | low | cfn:AWS::Synthetics::Canary: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_TIMESTREAM_DATABASE.001` | low | cfn:AWS::Timestream::Database: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_TIMESTREAM_SCHEDULEDQUERY.001` | low | cfn:AWS::Timestream::ScheduledQuery: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_TIMESTREAM_TABLE.001` | low | cfn:AWS::Timestream::Table: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_VOICEID_DOMAIN.001` | low | cfn:AWS::VoiceID::Domain: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_WISDOM_ASSISTANT.001` | low | cfn:AWS::Wisdom::Assistant: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_WISDOM_KNOWLEDGEBASE.001` | low | cfn:AWS::Wisdom::KnowledgeBase: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_WORKSPACESINSTANCES_VOLUME.001` | low | cfn:AWS::WorkspacesInstances::Volume: a customer-managed key |
| `POLICY.CFN.CMEK.AWS_WORKSPACESTHINCLIENT_ENVIRONMENT.001` | low | cfn:AWS::WorkSpacesThinClient::Environment: a customer-managed key |
| `POLICY.CFN.DELETION_PROTECTION.AWS_DOCDB_DBCLUSTER.001` | low | cfn:AWS::DocDB::DBCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_DOCDB_GLOBALCLUSTER.001` | low | cfn:AWS::DocDB::GlobalCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_DSQL_CLUSTER.001` | low | cfn:AWS::DSQL::Cluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_DYNAMODB_TABLE.001` | low | cfn:AWS::DynamoDB::Table: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_EKS_CLUSTER.001` | low | cfn:AWS::EKS::Cluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_LOGS_LOGGROUP.001` | low | cfn:AWS::Logs::LogGroup: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_NEPTUNEGRAPH_GRAPH.001` | low | cfn:AWS::NeptuneGraph::Graph: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_NEPTUNE_DBCLUSTER.001` | low | cfn:AWS::Neptune::DBCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_NEPTUNE_GLOBALCLUSTER.001` | low | cfn:AWS::Neptune::GlobalCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_QLDB_LEDGER.001` | low | cfn:AWS::QLDB::Ledger: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_RDS_DBCLUSTER.001` | low | cfn:AWS::RDS::DBCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_RDS_GLOBALCLUSTER.001` | low | cfn:AWS::RDS::GlobalCluster: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_SMSVOICE_PHONENUMBER.001` | low | cfn:AWS::SMSVOICE::PhoneNumber: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_SMSVOICE_POOL.001` | low | cfn:AWS::SMSVOICE::Pool: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_SMSVOICE_PROTECTCONFIGURATION.001` | low | cfn:AWS::SMSVOICE::ProtectConfiguration: deletion protection |
| `POLICY.CFN.DELETION_PROTECTION.AWS_SMSVOICE_SENDERID.001` | low | cfn:AWS::SMSVOICE::SenderId: deletion protection |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_BEDROCKAGENTCORE_CAPACITYPROVIDER.001` | high | cfn:AWS::BedrockAgentCore::CapacityProvider: encryption at rest |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_DOCDB_DBCLUSTER.001` | high | cfn:AWS::DocDB::DBCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_DOCDB_GLOBALCLUSTER.001` | high | cfn:AWS::DocDB::GlobalCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_EC2_VOLUME.001` | high | cfn:AWS::EC2::Volume: encryption at rest |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_NEPTUNE_DBCLUSTER.001` | high | cfn:AWS::Neptune::DBCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_NEPTUNE_GLOBALCLUSTER.001` | high | cfn:AWS::Neptune::GlobalCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_RDS_DBCLUSTER.001` | high | cfn:AWS::RDS::DBCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_RDS_DBCLUSTERAUTOMATEDBACKUP.001` | high | cfn:AWS::RDS::DBClusterAutomatedBackup: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_RDS_DBINSTANCEAUTOMATEDBACKUP.001` | high | cfn:AWS::RDS::DBInstanceAutomatedBackup: encryption at rest |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_RDS_GLOBALCLUSTER.001` | high | cfn:AWS::RDS::GlobalCluster: storage encryption |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_REDSHIFT_CLUSTER.001` | high | cfn:AWS::Redshift::Cluster: encryption at rest |
| `POLICY.CFN.ENCRYPT_AT_REST.AWS_WORKSPACESINSTANCES_VOLUME.001` | high | cfn:AWS::WorkspacesInstances::Volume: encryption at rest |
| `POLICY.CFN.ENCRYPT_AT_REST.DBINSTANCE.001` | high | AWS::RDS::DBInstance: storage encryption is switched off |
| `POLICY.CFN.ENCRYPT_AT_REST.FILESYSTEM.001` | medium | AWS::EFS::FileSystem: the file system is not encrypted |
| `POLICY.CFN.GOVERNANCE.AWS_DOCDB_DBCLUSTER.001` | low | cfn:AWS::DocDB::DBCluster: tags on snapshots |
| `POLICY.CFN.GOVERNANCE.AWS_NEPTUNE_DBCLUSTER.001` | low | cfn:AWS::Neptune::DBCluster: tags on snapshots |
| `POLICY.CFN.GOVERNANCE.AWS_RDS_DBCLUSTER.001` | low | cfn:AWS::RDS::DBCluster: tags on snapshots |
| `POLICY.CFN.GOVERNANCE.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: tags on snapshots |
| `POLICY.CFN.KEY_ROTATION.AWS_KMS_KEY.001` | medium | cfn:AWS::KMS::Key: automatic key rotation |
| `POLICY.CFN.LOGGING.AWS_DOCDB_DBINSTANCE.001` | low | cfn:AWS::DocDB::DBInstance: performance insights |
| `POLICY.CFN.LOGGING.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: performance insights |
| `POLICY.CFN.PATCHING.AWS_AMAZONMQ_BROKER.001` | medium | cfn:AWS::AmazonMQ::Broker: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_DMS_REPLICATIONINSTANCE.001` | medium | cfn:AWS::DMS::ReplicationInstance: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_DOCDB_DBINSTANCE.001` | medium | cfn:AWS::DocDB::DBInstance: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_ELASTICACHE_CACHECLUSTER.001` | medium | cfn:AWS::ElastiCache::CacheCluster: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_ELASTICACHE_REPLICATIONGROUP.001` | medium | cfn:AWS::ElastiCache::ReplicationGroup: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_MEMORYDB_CLUSTER.001` | medium | cfn:AWS::MemoryDB::Cluster: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_NEPTUNE_DBINSTANCE.001` | medium | cfn:AWS::Neptune::DBInstance: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_RDS_DBCLUSTER.001` | medium | cfn:AWS::RDS::DBCluster: automatic minor version upgrades |
| `POLICY.CFN.PATCHING.AWS_RDS_DBINSTANCE.001` | medium | cfn:AWS::RDS::DBInstance: automatic minor version upgrades |
| `POLICY.CFN.PUBLIC_IP.AWS_AUTOSCALING_LAUNCHCONFIGURATION.001` | low | cfn:AWS::AutoScaling::LaunchConfiguration: a public ip address |
| `POLICY.CFN.PUBLIC_IP.AWS_EC2_SUBNET.001` | low | cfn:AWS::EC2::Subnet: every instance in the subnet gets a public address |
| `POLICY.CFN.RESILIENCE.AWS_DMS_REPLICATIONCONFIG.001` | low | cfn:AWS::DMS::ReplicationConfig: a standby in another availability zone |
| `POLICY.CFN.RESILIENCE.AWS_DMS_REPLICATIONINSTANCE.001` | low | cfn:AWS::DMS::ReplicationInstance: a standby in another availability zone |
| `POLICY.CFN.RESILIENCE.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: a standby in another availability zone |
| `POLICY.CFN.RESILIENCE.AWS_REDSHIFT_CLUSTER.001` | low | cfn:AWS::Redshift::Cluster: a standby in another availability zone |
| `POLICY.CFN.SHARED_KEY_AUTH.AWS_RDS_DBCLUSTER.001` | low | cfn:AWS::RDS::DBCluster: iam database authentication |
| `POLICY.CFN.SHARED_KEY_AUTH.AWS_RDS_DBINSTANCE.001` | low | cfn:AWS::RDS::DBInstance: iam database authentication |
| `POLICY.CFN.WEAK_TLS.AWS_CLOUDFRONT_DISTRIBUTION.001` | medium | cfn:AWS::CloudFront::Distribution: an obsolete tls version is accepted |
| `POLICY.CFN.WRITABLE_ROOT.AWS_BATCH_JOBDEFINITION.001` | low | cfn:AWS::Batch::JobDefinition: a read-only root filesystem |
| `SUSPECT.CFN.IAM_WILDCARD.POLICY.001` | high | AWS::IAM::Policy: the policy grants every action |
| `SUSPECT.CFN.IMDSV1.AWS_AUTOSCALING_LAUNCHCONFIGURATION.001` | medium | cfn:AWS::AutoScaling::LaunchConfiguration: instance metadata is reachable without a token |
| `SUSPECT.CFN.IMDSV1.AWS_EC2_INSTANCE.001` | medium | cfn:AWS::EC2::Instance: instance metadata is reachable without a token |
| `SUSPECT.CFN.IMDSV1.AWS_EC2_LAUNCHTEMPLATE.001` | medium | cfn:AWS::EC2::LaunchTemplate: instance metadata is reachable without a token |
| `SUSPECT.CFN.IMDSV1.AWS_IMAGEBUILDER_INFRASTRUCTURECONFIGURATION.001` | medium | cfn:AWS::ImageBuilder::InfrastructureConfiguration: instance metadata is reachable without a token |
| `SUSPECT.CFN.IMDSV1.AWS_WORKSPACESINSTANCES_WORKSPACEINSTANCE.001` | medium | cfn:AWS::WorkspacesInstances::WorkspaceInstance: instance metadata is reachable without a token |
| `SUSPECT.CFN.OPEN_INGRESS.SECURITYGROUP.001` | high | AWS::EC2::SecurityGroup: a security group admits the whole internet |
| `SUSPECT.CFN.PLAINTEXT.LISTENER.001` | medium | AWS::ElasticLoadBalancingV2::Listener: the listener serves plain HTTP |
| `SUSPECT.CFN.PRIVILEGED.AWS_BATCH_JOBDEFINITION.001` | high | cfn:AWS::Batch::JobDefinition: the container runs privileged |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_AMAZONMQ_BROKER.001` | high | cfn:AWS::AmazonMQ::Broker: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_DMS_INSTANCEPROFILE.001` | high | cfn:AWS::DMS::InstanceProfile: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_DMS_REPLICATIONINSTANCE.001` | high | cfn:AWS::DMS::ReplicationInstance: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_LIGHTSAIL_DATABASE.001` | high | cfn:AWS::Lightsail::Database: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_M2_ENVIRONMENT.001` | high | cfn:AWS::M2::Environment: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_NEPTUNE_DBINSTANCE.001` | high | cfn:AWS::Neptune::DBInstance: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_RDS_DBCLUSTER.001` | high | cfn:AWS::RDS::DBCluster: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_RDS_DBSHARDGROUP.001` | high | cfn:AWS::RDS::DBShardGroup: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_REDSHIFTSERVERLESS_WORKGROUP.001` | high | cfn:AWS::RedshiftServerless::Workgroup: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_REDSHIFT_CLUSTER.001` | high | cfn:AWS::Redshift::Cluster: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_TIMESTREAM_INFLUXDBCLUSTER.001` | high | cfn:AWS::Timestream::InfluxDBCluster: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.AWS_TIMESTREAM_INFLUXDBINSTANCE.001` | high | cfn:AWS::Timestream::InfluxDBInstance: reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_ACCESS.DBINSTANCE.001` | high | AWS::RDS::DBInstance: the database is reachable from the public internet |
| `SUSPECT.CFN.PUBLIC_STORAGE.BUCKET.001` | high | AWS::S3::Bucket: the bucket is readable by anyone |

## Compose files

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.COMPOSE.DANGEROUS_CAPABILITY.001` | high | Compose service: the service is granted a capability that defeats isolation |
| `SUSPECT.COMPOSE.HOST_NETWORK.001` | medium | Compose service: the service shares the host network namespace |

## Containers

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.CONTAINER.UNPINNED_BASE.001` | low | Base image referenced by tag rather than digest |
| `POLICY.CONTAINER.UNPINNED_WORKLOAD_IMAGE.001` | low | Kubernetes workload runs an image by tag rather than digest |
| `POLICY.CONTAINER.UNSIGNED_IMAGE.001` | low | An image this project runs carries no signature or build attestation |
| `SUSPECT.CONTAINER.BUILD_SECRET.001` | high | Secret passed as a build argument |
| `SUSPECT.CONTAINER.FETCH_EXEC.001` | high | Image build fetches and executes remote content |

## Cryptominer

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.CRYPTOMINER.001` | critical | Install-time cryptocurrency mining |
| `SUSPECT.CRYPTOMINER.001` | high | Cryptocurrency mining |

## Decode Chain

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DECODE_CHAIN.001` | critical | A payload decoded in several stages, then executed |

## Decode Exec

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DECODE_EXEC.001` | high | Encoded data decoded and executed in the same file |

## Dependencies

21 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DEPENDENCY.KNOWN.001` | critical | Dependency is a known-malicious release |
| `POLICY.DEPENDENCY.ABANDONED.001` | medium | Dependency is abandoned by its maintainer |
| `POLICY.DEPENDENCY.CLEARTEXT_SOURCE.001` | medium | Package source over plain HTTP |
| `POLICY.DEPENDENCY.DEPRECATED.001` | medium | Dependency pins a version its publisher deprecated |
| `POLICY.DEPENDENCY.DOWNGRADE.001` | low | Dependency pins a version far behind the current release |
| `POLICY.DEPENDENCY.INTEGRITY.001` | medium | Dependency has no integrity hash |
| `POLICY.DEPENDENCY.MUTABLE_REF.001` | medium | Git dependency on a reference that can move |
| `POLICY.DEPENDENCY.SECURITY_PLACEHOLDER.001` | medium | Dependency pins npm's security placeholder |
| `POLICY.DEPENDENCY.SOURCE.001` | low | Dependency declared from a non-registry source |
| `POLICY.DEPENDENCY.UNMAINTAINED.001` | low | Dependency has had no release in five years |
| `SUSPECT.DEPENDENCY.CONFUSION.001` | high | Internal package name resolved from a public registry |
| `SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001` | high | Dependency pins a version its publisher deprecated for a security reason |
| `SUSPECT.DEPENDENCY.HALLUCINATED.001` | high | A dependency's name is a documented AI hallucination |
| `SUSPECT.DEPENDENCY.SOURCE.001` | medium | Dependency resolved from outside the registry |
| `SUSPECT.DEPENDENCY.SOURCE_PRIORITY.001` | medium | A private package index merged with a public one |
| `SUSPECT.DEPENDENCY.TYPOSQUAT.001` | high | Dependency name is one edit from a popular package |
| `SUSPECT.DEPENDENCY.UNREGISTERED.001` | high | A dependency does not exist on its public registry |
| `SUSPECT.DEPENDENCY.UNVETTED.001` | medium | A dependency is new, sourceless and unknown: the shape of a slopsquatted package |
| `SUSPECT.DEPENDENCY.YANKED.001` | high | Dependency pins a version its publisher withdrew |
| `VULNERABLE.DEPENDENCY.EXPLOITED.001` | critical | Dependency has a vulnerability that is exploited in the wild |
| `VULNERABLE.DEPENDENCY.KNOWN.001` | high | Dependency has a known vulnerability |

## Destroy

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DESTROY.HOME_OR_ROOT.001` | high | Deletes the home directory or the filesystem root |

## Dockerfiles

6 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.DOCKERFILE.NO_HEALTHCHECK.001` | low | Dockerfile: the image serves a port and declares no health check |
| `POLICY.DOCKERFILE.ROOT_USER.001` | medium | Dockerfile: the image runs as root |
| `POLICY.DOCKERFILE.SECRET_ARG_DECLARED.001` | medium | Dockerfile: a credential is passed as a build argument |
| `POLICY.DOCKERFILE.SUDO.001` | low | Dockerfile: the build uses sudo |
| `SUSPECT.DOCKERFILE.ADD_REMOTE.001` | medium | Dockerfile: the build downloads a URL with ADD |
| `SUSPECT.DOCKERFILE.SECRET_ARG.001` | high | Dockerfile: a credential is baked into the image |

## Document

10 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.DOCUMENT.AUTO_EXEC.001` | high | A macro runs by itself on open and starts a program or fetches from the network |
| `SUSPECT.DOCUMENT.DDE.001` | high | A document contains a DDE field |
| `SUSPECT.DOCUMENT.MACRO.001` | medium | An office document carries macros |
| `SUSPECT.DOCUMENT.PDF_AUTO_ACTION.001` | high | A PDF runs JavaScript when it is opened |
| `SUSPECT.DOCUMENT.PDF_EMBEDDED_EXECUTABLE.001` | high | A PDF embeds a file with an executable name |
| `SUSPECT.DOCUMENT.PDF_JAVASCRIPT.001` | medium | A PDF carries JavaScript |
| `SUSPECT.DOCUMENT.PDF_LAUNCH.001` | high | A PDF asks the viewer to launch a program |
| `SUSPECT.DOCUMENT.PDF_RISKY_URI.001` | medium | A PDF link opens a script, a local file or a download that runs |
| `SUSPECT.DOCUMENT.REMOTE_OBJECT.001` | high | A document loads a template or object from elsewhere when opened |
| `SUSPECT.DOCUMENT.RTF_OBJECT.001` | high | An RTF document embeds an object that loads itself |

## Dropper

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DROPPER.001` | critical | Install script fetches and executes remote content |
| `SUSPECT.DROPPER.001` | high | Content fetched from the network and executed |

## Dynamic Dispatch

2 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.DYNAMIC_DISPATCH.001` | critical | Install-time code reaches a function by a computed name |
| `SUSPECT.DYNAMIC_DISPATCH.001` | high | A function is reached by a name computed at runtime |

## Exfiltration

13 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.EXFIL.001` | critical | Install script reads credentials and transmits them |
| `MALWARE.EXFIL.BEACON.001` | critical | Install script reports the machine it is installing on |
| `MALWARE.EXFIL.CREDENTIAL_STORE.001` | critical | Install-time code reads a credential store and reaches the network |
| `MALWARE.EXFIL.DROP_POINT.001` | critical | Install-time code sends data to a drop point |
| `MALWARE.EXFIL.INSTALL_CALLBACK.001` | critical | Install script calls back to a drop point |
| `SUSPECT.EXFIL.001` | medium | Credential access combined with network egress and execution |
| `SUSPECT.EXFIL.BEACON.001` | high | Code reports the machine it runs on |
| `SUSPECT.EXFIL.CALLBACK.001` | high | Code calls an out-of-band interaction service |
| `SUSPECT.EXFIL.CREDENTIAL_STORE.001` | high | A credential store is read and the file reaches the network |
| `SUSPECT.EXFIL.DNS.001` | high | Credential access and a hostname assembled for resolution |
| `SUSPECT.EXFIL.DROP_POINT.001` | high | Credential or machine identity, and a request to a drop point |
| `SUSPECT.EXFIL.ENVIRONMENT.001` | high | Code sends the whole environment over the network |
| `SUSPECT.EXFIL.NAMED_SECRET.001` | high | Code sends a named credential to a host outside its service |

## Extension

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.EXTENSION.KNOWN.001` | critical | An editor extension is a recorded malicious release |
| `MALWARE.EXTENSION.REMOVED.001` | critical | A recommended or vendored editor extension was removed from the Marketplace as malware |
| `SUSPECT.EXTENSION.LOOKALIKE.001` | medium | A recommended editor extension imitates a popular one |
| `SUSPECT.EXTENSION.MALICIOUS_VERSIONS.001` | low | A named editor extension has had malicious releases |
| `SUSPECT.EXTENSION.REMOVED.001` | high | A recommended or vendored editor extension was removed from the Marketplace |

## Format

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.FORMAT.UNREADABLE` | info | A model, document or image could not be read |

## Helm

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.HELM.UNTRUSTED_REPOSITORY.001` | medium | Chart depends on a chart from an unpinned or plain-HTTP repository |

## Image

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.IMAGE.UNMATCHED` | info | An image's packages were not all matched against advisories |
| `VULNERABLE.IMAGE.EXPLOITED.001` | critical | An image's operating-system package has a vulnerability exploited in the wild |
| `VULNERABLE.IMAGE.PACKAGE.001` | high | An image's operating-system package has a known vulnerability |

## Infrastructure as code

819 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.IAC.ANSIBLE_TLS_UNVERIFIED.001` | medium | Task turns off TLS certificate verification |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_CRON_JOB.001` | low | kubernetes_cron_job: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_CRON_JOB_V1.001` | low | kubernetes_cron_job_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DAEMONSET.001` | low | kubernetes_daemonset: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DAEMON_SET_V1.001` | low | kubernetes_daemon_set_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DEFAULT_SERVICE_ACCOUNT.001` | low | kubernetes_default_service_account: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DEFAULT_SERVICE_ACCOUNT_V1.001` | low | kubernetes_default_service_account_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DEPLOYMENT.001` | low | kubernetes_deployment: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_DEPLOYMENT_V1.001` | low | kubernetes_deployment_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_JOB.001` | low | kubernetes_job: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_JOB_V1.001` | low | kubernetes_job_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_POD.001` | low | kubernetes_pod: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_POD_V1.001` | low | kubernetes_pod_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_REPLICATION_CONTROLLER.001` | low | kubernetes_replication_controller: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | low | kubernetes_replication_controller_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_SERVICE_ACCOUNT.001` | low | kubernetes_service_account: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_SERVICE_ACCOUNT_V1.001` | low | kubernetes_service_account_v1: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_STATEFUL_SET.001` | low | kubernetes_stateful_set: the service account token is mounted into the pod |
| `POLICY.IAC.AUTOMOUNT_TOKEN.KUBERNETES_STATEFUL_SET_V1.001` | low | kubernetes_stateful_set_v1: the service account token is mounted into the pod |
| `POLICY.IAC.BACKUP.AWS_DB_INSTANCE_BACKUP_RETENTION_PERIOD.001` | medium | aws_db_instance: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AWS_DOCDB_CLUSTER_BACKUP_RETENTION_PERIOD.001` | low | aws_docdb_cluster: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AWS_LIGHTSAIL_DATABASE.001` | medium | aws_lightsail_database: no snapshot is taken when the database is destroyed |
| `POLICY.IAC.BACKUP.AWS_NEPTUNE_CLUSTER_BACKUP_RETENTION_PERIOD.001` | low | aws_neptune_cluster: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AWS_NEPTUNE_CLUSTER_INSTANCE.001` | medium | aws_neptune_cluster_instance: no snapshot is taken when the database is destroyed |
| `POLICY.IAC.BACKUP.AWS_RDS_CLUSTER_BACKUP_RETENTION_PERIOD.001` | medium | aws_rds_cluster: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AWS_REDSHIFT_CLUSTER_AUTOMATED_SNAPSHOT_RETENTION_PERIOD.001` | low | aws_redshift_cluster: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AZURERM_APP_SERVICE.001` | low | azurerm_app_service: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_LINUX_FUNCTION_APP.001` | low | azurerm_linux_function_app: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_LINUX_FUNCTION_APP_SLOT.001` | low | azurerm_linux_function_app_slot: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_LINUX_WEB_APP.001` | low | azurerm_linux_web_app: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_LINUX_WEB_APP_SLOT.001` | low | azurerm_linux_web_app_slot: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_MYSQL_SERVER_BACKUP_RETENTION_DAYS.001` | low | azurerm_mysql_server: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AZURERM_POSTGRESQL_SERVER_BACKUP_RETENTION_DAYS.001` | low | azurerm_postgresql_server: a backup retention period is not configured |
| `POLICY.IAC.BACKUP.AZURERM_WINDOWS_FUNCTION_APP.001` | low | azurerm_windows_function_app: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_WINDOWS_FUNCTION_APP_SLOT.001` | low | azurerm_windows_function_app_slot: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_WINDOWS_WEB_APP.001` | low | azurerm_windows_web_app: keeping a backup |
| `POLICY.IAC.BACKUP.AZURERM_WINDOWS_WEB_APP_SLOT.001` | low | azurerm_windows_web_app_slot: keeping a backup |
| `POLICY.IAC.BACKUP_DISABLED.AWS_DB_INSTANCE.001` | medium | aws_db_instance: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AWS_DOCDB_CLUSTER.001` | low | aws_docdb_cluster: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AWS_NEPTUNE_CLUSTER.001` | low | aws_neptune_cluster: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AWS_RDS_CLUSTER.001` | medium | aws_rds_cluster: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AWS_REDSHIFT_CLUSTER.001` | low | aws_redshift_cluster: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AZURERM_MYSQL_SERVER.001` | low | azurerm_mysql_server: backups are switched off |
| `POLICY.IAC.BACKUP_DISABLED.AZURERM_POSTGRESQL_SERVER.001` | low | azurerm_postgresql_server: backups are switched off |
| `POLICY.IAC.BOOT_INTEGRITY.AZURERM_BATCH_POOL.001` | low | azurerm_batch_pool: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.AZURERM_LINUX_VIRTUAL_MACHINE.001` | low | azurerm_linux_virtual_machine: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.AZURERM_LINUX_VIRTUAL_MACHINE_SCALE_SET.001` | low | azurerm_linux_virtual_machine_scale_set: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.AZURERM_WINDOWS_VIRTUAL_MACHINE.001` | low | azurerm_windows_virtual_machine: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.AZURERM_WINDOWS_VIRTUAL_MACHINE_SCALE_SET.001` | low | azurerm_windows_virtual_machine_scale_set: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_COLAB_RUNTIME_TEMPLATE.001` | low | google_colab_runtime_template: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_COMPUTE_INSTANCE.001` | low | google_compute_instance: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_COMPUTE_INSTANCE_FROM_TEMPLATE.001` | low | google_compute_instance_from_template: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_COMPUTE_INSTANCE_TEMPLATE.001` | low | google_compute_instance_template: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_COMPUTE_REGION_INSTANCE_TEMPLATE.001` | low | google_compute_region_instance_template: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_CONTAINER_CLUSTER.001` | low | google_container_cluster: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_CONTAINER_NODE_POOL.001` | low | google_container_node_pool: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_DATAPROC_CLUSTER.001` | low | google_dataproc_cluster: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_DATAPROC_WORKFLOW_TEMPLATE.001` | low | google_dataproc_workflow_template: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_NOTEBOOKS_INSTANCE.001` | low | google_notebooks_instance: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_NOTEBOOKS_RUNTIME.001` | low | google_notebooks_runtime: secure boot |
| `POLICY.IAC.BOOT_INTEGRITY.GOOGLE_WORKBENCH_INSTANCE.001` | low | google_workbench_instance: secure boot |
| `POLICY.IAC.CMEK.AWS_AMI_COPY.001` | low | aws_ami_copy: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ATHENA_WORKGROUP.001` | low | aws_athena_workgroup: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_BACKUP_VAULT.001` | low | aws_backup_vault: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_BEDROCKAGENT_DATA_SOURCE.001` | low | aws_bedrockagent_data_source: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_BEDROCK_GUARDRAIL.001` | low | aws_bedrock_guardrail: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CHIMESDKVOICE_VOICE_PROFILE_DOMAIN.001` | low | aws_chimesdkvoice_voice_profile_domain: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CLOUDTRAIL.001` | low | aws_cloudtrail: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CLOUDTRAIL_EVENT_DATA_STORE.001` | low | aws_cloudtrail_event_data_store: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CLOUDWATCH_LOG_ANOMALY_DETECTOR.001` | low | aws_cloudwatch_log_anomaly_detector: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CODECOMMIT_REPOSITORY.001` | low | aws_codecommit_repository: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_CODEGURUREVIEWER_REPOSITORY_ASSOCIATION.001` | low | aws_codegurureviewer_repository_association: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_COGNITO_USER_POOL.001` | low | aws_cognito_user_pool: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_COMPREHEND_DOCUMENT_CLASSIFIER.001` | low | aws_comprehend_document_classifier: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DATAEXCHANGE_EVENT_ACTION.001` | low | aws_dataexchange_event_action: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DATAEXCHANGE_REVISION_ASSETS.001` | low | aws_dataexchange_revision_assets: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DB_INSTANCE.001` | low | aws_db_instance: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DB_INSTANCE_AUTOMATED_BACKUPS_REPLICATION.001` | low | aws_db_instance_automated_backups_replication: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DB_SNAPSHOT_COPY.001` | low | aws_db_snapshot_copy: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DEVOPSGURU_SERVICE_INTEGRATION.001` | low | aws_devopsguru_service_integration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DMS_ENDPOINT.001` | low | aws_dms_endpoint: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DMS_REPLICATION_CONFIG.001` | low | aws_dms_replication_config: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DMS_REPLICATION_INSTANCE.001` | low | aws_dms_replication_instance: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DMS_S3_ENDPOINT.001` | low | aws_dms_s3_endpoint: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DOCDBELASTIC_CLUSTER.001` | low | aws_docdbelastic_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DOCDB_CLUSTER.001` | low | aws_docdb_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DYNAMODB_TABLE.001` | low | aws_dynamodb_table: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_DYNAMODB_TABLE_REPLICA.001` | low | aws_dynamodb_table_replica: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EBS_SNAPSHOT_COPY.001` | low | aws_ebs_snapshot_copy: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EBS_SNAPSHOT_IMPORT.001` | low | aws_ebs_snapshot_import: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EBS_VOLUME.001` | low | aws_ebs_volume: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ECS_CLUSTER.001` | low | aws_ecs_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ECS_SERVICE.001` | low | aws_ecs_service: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EFS_FILE_SYSTEM.001` | low | aws_efs_file_system: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EFS_REPLICATION_CONFIGURATION.001` | low | aws_efs_replication_configuration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ELASTICACHE_REPLICATION_GROUP.001` | low | aws_elasticache_replication_group: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ELASTICACHE_SERVERLESS_CACHE.001` | low | aws_elasticache_serverless_cache: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_ELASTICSEARCH_DOMAIN.001` | low | aws_elasticsearch_domain: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_EMRCONTAINERS_JOB_TEMPLATE.001` | low | aws_emrcontainers_job_template: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FINSPACE_KX_ENVIRONMENT.001` | low | aws_finspace_kx_environment: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FSX_FILE_CACHE.001` | low | aws_fsx_file_cache: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FSX_LUSTRE_FILE_SYSTEM.001` | low | aws_fsx_lustre_file_system: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FSX_ONTAP_FILE_SYSTEM.001` | low | aws_fsx_ontap_file_system: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FSX_OPENZFS_FILE_SYSTEM.001` | low | aws_fsx_openzfs_file_system: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_FSX_WINDOWS_FILE_SYSTEM.001` | low | aws_fsx_windows_file_system: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_GLUE_SECURITY_CONFIGURATION.001` | low | aws_glue_security_configuration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_GUARDDUTY_PUBLISHING_DESTINATION.001` | low | aws_guardduty_publishing_destination: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_IMAGEBUILDER_COMPONENT.001` | low | aws_imagebuilder_component: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_IMAGEBUILDER_CONTAINER_RECIPE.001` | low | aws_imagebuilder_container_recipe: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_IMAGEBUILDER_DISTRIBUTION_CONFIGURATION.001` | low | aws_imagebuilder_distribution_configuration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_IMAGEBUILDER_IMAGE_RECIPE.001` | low | aws_imagebuilder_image_recipe: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_IMAGEBUILDER_WORKFLOW.001` | low | aws_imagebuilder_workflow: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_INSTANCE.001` | low | aws_instance: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_KENDRA_INDEX.001` | low | aws_kendra_index: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_KINESIS_FIREHOSE_DELIVERY_STREAM.001` | low | aws_kinesis_firehose_delivery_stream: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_KINESIS_STREAM.001` | low | aws_kinesis_stream: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_KINESIS_VIDEO_STREAM.001` | low | aws_kinesis_video_stream: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LAMBDA_EVENT_SOURCE_MAPPING.001` | low | aws_lambda_event_source_mapping: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LAMBDA_FUNCTION.001` | low | aws_lambda_function: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LAUNCH_TEMPLATE.001` | low | aws_launch_template: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LEXV2MODELS_SLOT_TYPE.001` | low | aws_lexv2models_slot_type: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LEX_BOT_ALIAS.001` | low | aws_lex_bot_alias: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LOCATION_GEOFENCE_COLLECTION.001` | low | aws_location_geofence_collection: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_LOCATION_TRACKER.001` | low | aws_location_tracker: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_M2_APPLICATION.001` | low | aws_m2_application: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_M2_ENVIRONMENT.001` | low | aws_m2_environment: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_MACIE2_CLASSIFICATION_EXPORT_CONFIGURATION.001` | low | aws_macie2_classification_export_configuration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_MEMORYDB_CLUSTER.001` | low | aws_memorydb_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_MEMORYDB_SNAPSHOT.001` | low | aws_memorydb_snapshot: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_MQ_BROKER.001` | low | aws_mq_broker: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_NEPTUNE_CLUSTER.001` | low | aws_neptune_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_OPENSEARCH_DOMAIN.001` | low | aws_opensearch_domain: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_OSIS_PIPELINE.001` | low | aws_osis_pipeline: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_PROMETHEUS_WORKSPACE.001` | low | aws_prometheus_workspace: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_QBUSINESS_APPLICATION.001` | low | aws_qbusiness_application: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_CLUSTER.001` | low | aws_rds_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_CLUSTER_ACTIVITY_STREAM.001` | low | aws_rds_cluster_activity_stream: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_CLUSTER_SNAPSHOT_COPY.001` | low | aws_rds_cluster_snapshot_copy: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_CUSTOM_DB_ENGINE_VERSION.001` | low | aws_rds_custom_db_engine_version: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_EXPORT_TASK.001` | low | aws_rds_export_task: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_RDS_INTEGRATION.001` | low | aws_rds_integration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_REDSHIFTSERVERLESS_NAMESPACE.001` | low | aws_redshiftserverless_namespace: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_REDSHIFT_CLUSTER.001` | low | aws_redshift_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_REDSHIFT_INTEGRATION.001` | low | aws_redshift_integration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_REDSHIFT_SNAPSHOT_COPY_GRANT.001` | low | aws_redshift_snapshot_copy_grant: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_REKOGNITION_STREAM_PROCESSOR.001` | low | aws_rekognition_stream_processor: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_S3_BUCKET_OBJECT.001` | low | aws_s3_bucket_object: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_S3_OBJECT.001` | low | aws_s3_object: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_S3_OBJECT_COPY.001` | low | aws_s3_object_copy: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_DATA_QUALITY_JOB_DEFINITION.001` | low | aws_sagemaker_data_quality_job_definition: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_DEVICE_FLEET.001` | low | aws_sagemaker_device_fleet: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_DOMAIN.001` | low | aws_sagemaker_domain: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_ENDPOINT_CONFIGURATION.001` | low | aws_sagemaker_endpoint_configuration: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_FEATURE_GROUP.001` | low | aws_sagemaker_feature_group: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_FLOW_DEFINITION.001` | low | aws_sagemaker_flow_definition: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | low | aws_sagemaker_notebook_instance: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SCHEDULER_SCHEDULE.001` | low | aws_scheduler_schedule: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SECRETSMANAGER_SECRET.001` | low | aws_secretsmanager_secret: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SES_RECEIPT_RULE.001` | low | aws_ses_receipt_rule: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SFN_ACTIVITY.001` | low | aws_sfn_activity: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SFN_STATE_MACHINE.001` | low | aws_sfn_state_machine: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SPOT_FLEET_REQUEST.001` | low | aws_spot_fleet_request: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SPOT_INSTANCE_REQUEST.001` | low | aws_spot_instance_request: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SSMINCIDENTS_REPLICATION_SET.001` | low | aws_ssmincidents_replication_set: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SSM_RESOURCE_DATA_SYNC.001` | low | aws_ssm_resource_data_sync: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_STORAGEGATEWAY_NFS_FILE_SHARE.001` | low | aws_storagegateway_nfs_file_share: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_STORAGEGATEWAY_SMB_FILE_SHARE.001` | low | aws_storagegateway_smb_file_share: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_SYNTHETICS_CANARY.001` | low | aws_synthetics_canary: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_TIMESTREAMQUERY_SCHEDULED_QUERY.001` | low | aws_timestreamquery_scheduled_query: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_TIMESTREAMWRITE_DATABASE.001` | low | aws_timestreamwrite_database: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_TIMESTREAMWRITE_TABLE.001` | low | aws_timestreamwrite_table: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_VERIFIEDACCESS_ENDPOINT.001` | low | aws_verifiedaccess_endpoint: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_VERIFIEDACCESS_GROUP.001` | low | aws_verifiedaccess_group: a customer-managed key |
| `POLICY.IAC.CMEK.AWS_VERIFIEDACCESS_TRUST_PROVIDER.001` | low | aws_verifiedaccess_trust_provider: a customer-managed key |
| `POLICY.IAC.CMEK.AZURERM_IMAGE.001` | low | azurerm_image: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_KUBERNETES_CLUSTER.001` | low | azurerm_kubernetes_cluster: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_LINUX_VIRTUAL_MACHINE.001` | low | azurerm_linux_virtual_machine: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_LINUX_VIRTUAL_MACHINE_SCALE_SET.001` | low | azurerm_linux_virtual_machine_scale_set: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_MANAGED_DISK.001` | low | azurerm_managed_disk: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_ORCHESTRATED_VIRTUAL_MACHINE_SCALE_SET.001` | low | azurerm_orchestrated_virtual_machine_scale_set: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_REDHAT_OPENSHIFT_CLUSTER.001` | low | azurerm_redhat_openshift_cluster: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_SHARED_IMAGE_VERSION.001` | low | azurerm_shared_image_version: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_WINDOWS_VIRTUAL_MACHINE.001` | low | azurerm_windows_virtual_machine: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.AZURERM_WINDOWS_VIRTUAL_MACHINE_SCALE_SET.001` | low | azurerm_windows_virtual_machine_scale_set: a customer-managed disk encryption set |
| `POLICY.IAC.CMEK.GOOGLE_ALLOYDB_BACKUP.001` | low | google_alloydb_backup: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_ALLOYDB_CLUSTER.001` | low | google_alloydb_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_ARTIFACT_REGISTRY_REPOSITORY.001` | low | google_artifact_registry_repository: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGQUERY_CONNECTION.001` | low | google_bigquery_connection: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGQUERY_DATASET.001` | low | google_bigquery_dataset: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGQUERY_DATA_TRANSFER_CONFIG.001` | low | google_bigquery_data_transfer_config: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGQUERY_JOB.001` | low | google_bigquery_job: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGQUERY_TABLE.001` | low | google_bigquery_table: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_BIGTABLE_INSTANCE.001` | low | google_bigtable_instance: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_CLOUDBUILD_TRIGGER.001` | low | google_cloudbuild_trigger: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_CLOUDFUNCTIONS2_FUNCTION.001` | low | google_cloudfunctions2_function: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_CLOUDFUNCTIONS_FUNCTION.001` | low | google_cloudfunctions_function: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_COLAB_RUNTIME_TEMPLATE.001` | low | google_colab_runtime_template: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_COMPOSER_ENVIRONMENT.001` | low | google_composer_environment: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_COMPUTE_REGION_DISK.001` | low | google_compute_region_disk: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_CONTAINER_AWS_CLUSTER.001` | low | google_container_aws_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_CONTAINER_AWS_NODE_POOL.001` | low | google_container_aws_node_pool: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DATAFLOW_JOB.001` | low | google_dataflow_job: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DATAPROC_CLUSTER.001` | low | google_dataproc_cluster: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DATASTREAM_STREAM.001` | low | google_datastream_stream: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DATA_PIPELINE_PIPELINE.001` | low | google_data_pipeline_pipeline: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DISCOVERY_ENGINE_DATA_STORE.001` | low | google_discovery_engine_data_store: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_DOCUMENT_AI_PROCESSOR.001` | low | google_document_ai_processor: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_FILESTORE_INSTANCE.001` | low | google_filestore_instance: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_FIRESTORE_DATABASE.001` | low | google_firestore_database: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_HEALTHCARE_DATASET.001` | low | google_healthcare_dataset: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_INTEGRATION_CONNECTORS_CONNECTION.001` | low | google_integration_connectors_connection: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_BILLING_ACCOUNT_BUCKET_CONFIG.001` | low | google_logging_billing_account_bucket_config: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_FOLDER_BUCKET_CONFIG.001` | low | google_logging_folder_bucket_config: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_FOLDER_SETTINGS.001` | low | google_logging_folder_settings: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_ORGANIZATION_BUCKET_CONFIG.001` | low | google_logging_organization_bucket_config: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_ORGANIZATION_SETTINGS.001` | low | google_logging_organization_settings: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOGGING_PROJECT_BUCKET_CONFIG.001` | low | google_logging_project_bucket_config: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_LOOKER_INSTANCE.001` | low | google_looker_instance: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_PUBSUB_TOPIC.001` | low | google_pubsub_topic: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_SECRET_MANAGER_REGIONAL_SECRET.001` | low | google_secret_manager_regional_secret: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_SECRET_MANAGER_SECRET.001` | low | google_secret_manager_secret: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_SPANNER_BACKUP_SCHEDULE.001` | low | google_spanner_backup_schedule: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_SPANNER_DATABASE.001` | low | google_spanner_database: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_STORAGE_BUCKET_OBJECT.001` | low | google_storage_bucket_object: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_VERTEX_AI_DATASET.001` | low | google_vertex_ai_dataset: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_VERTEX_AI_ENDPOINT.001` | low | google_vertex_ai_endpoint: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_VERTEX_AI_FEATURESTORE.001` | low | google_vertex_ai_featurestore: a customer-managed key |
| `POLICY.IAC.CMEK.GOOGLE_VERTEX_AI_TENSORBOARD.001` | low | google_vertex_ai_tensorboard: a customer-managed key |
| `POLICY.IAC.DELETION_PROTECTION.AWS_ALB_ENABLE_DELETION_PROTECTION.001` | low | aws_alb: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DB_INSTANCE_DELETION_PROTECTION.001` | low | aws_db_instance: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DOCDB_CLUSTER_DELETION_PROTECTION.001` | low | aws_docdb_cluster: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DOCDB_GLOBAL_CLUSTER.001` | low | aws_docdb_global_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DSQL_CLUSTER.001` | low | aws_dsql_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DYNAMODB_TABLE_DELETION_PROTECTION_ENABLED.001` | low | aws_dynamodb_table: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_DYNAMODB_TABLE_REPLICA.001` | low | aws_dynamodb_table_replica: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_LB_ENABLE_DELETION_PROTECTION.001` | low | aws_lb: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_NEPTUNEGRAPH_GRAPH.001` | low | aws_neptunegraph_graph: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_NEPTUNE_CLUSTER_DELETION_PROTECTION.001` | low | aws_neptune_cluster: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_NEPTUNE_GLOBAL_CLUSTER.001` | low | aws_neptune_global_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_PINPOINTSMSVOICEV2_PHONE_NUMBER.001` | low | aws_pinpointsmsvoicev2_phone_number: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_QLDB_LEDGER.001` | low | aws_qldb_ledger: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AWS_RDS_CLUSTER_DELETION_PROTECTION.001` | low | aws_rds_cluster: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.AWS_RDS_GLOBAL_CLUSTER.001` | low | aws_rds_global_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.AZURERM_APP_CONFIGURATION.001` | medium | azurerm_app_configuration: purge protection |
| `POLICY.IAC.DELETION_PROTECTION.AZURERM_KEY_VAULT_MANAGED_HARDWARE_SECURITY_MODULE.001` | medium | azurerm_key_vault_managed_hardware_security_module: purge protection |
| `POLICY.IAC.DELETION_PROTECTION.AZURERM_KEY_VAULT_PURGE_PROTECTION_ENABLED.001` | medium | azurerm_key_vault: deletion protection is not configured |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ACTIVE_DIRECTORY_DOMAIN.001` | low | google_active_directory_domain: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_BIGQUERY_TABLE.001` | low | google_bigquery_table: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_BIGTABLE_INSTANCE.001` | low | google_bigtable_instance: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_BIGTABLE_LOGICAL_VIEW.001` | low | google_bigtable_logical_view: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_BIGTABLE_MATERIALIZED_VIEW.001` | low | google_bigtable_materialized_view: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_CLOUD_RUN_V2_JOB.001` | low | google_cloud_run_v2_job: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_CLOUD_RUN_V2_SERVICE.001` | low | google_cloud_run_v2_service: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_CLOUD_RUN_V2_WORKER_POOL.001` | low | google_cloud_run_v2_worker_pool: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_COMPUTE_INSTANCE.001` | low | google_compute_instance: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_COMPUTE_INSTANCE_FROM_TEMPLATE.001` | low | google_compute_instance_from_template: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_COMPUTE_STORAGE_POOL.001` | low | google_compute_storage_pool: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_CONTAINER_CLUSTER.001` | low | google_container_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_DATAPROC_METASTORE_FEDERATION.001` | low | google_dataproc_metastore_federation: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_DATAPROC_METASTORE_SERVICE.001` | low | google_dataproc_metastore_service: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_FILESTORE_INSTANCE.001` | low | google_filestore_instance: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_FOLDER.001` | low | google_folder: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_MEMORYSTORE_INSTANCE.001` | low | google_memorystore_instance: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ORACLE_DATABASE_AUTONOMOUS_DATABASE.001` | low | google_oracle_database_autonomous_database: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ORACLE_DATABASE_CLOUD_EXADATA_INFRASTRUCTURE.001` | low | google_oracle_database_cloud_exadata_infrastructure: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ORACLE_DATABASE_CLOUD_VM_CLUSTER.001` | low | google_oracle_database_cloud_vm_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ORACLE_DATABASE_ODB_NETWORK.001` | low | google_oracle_database_odb_network: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_ORACLE_DATABASE_ODB_SUBNET.001` | low | google_oracle_database_odb_subnet: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_PRIVATECA_CERTIFICATE_AUTHORITY.001` | low | google_privateca_certificate_authority: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_REDIS_CLUSTER.001` | low | google_redis_cluster: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_SECRET_MANAGER_REGIONAL_SECRET.001` | low | google_secret_manager_regional_secret: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_SECRET_MANAGER_SECRET.001` | low | google_secret_manager_secret: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_SPANNER_DATABASE.001` | low | google_spanner_database: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_SQL_DATABASE_INSTANCE.001` | low | google_sql_database_instance: deletion protection |
| `POLICY.IAC.DELETION_PROTECTION.GOOGLE_WORKFLOWS_WORKFLOW.001` | low | google_workflows_workflow: deletion protection |
| `POLICY.IAC.DEPRECATED_RUNTIME.AWS_ELASTIC_BEANSTALK_ENVIRONMENT.001` | medium | aws_elastic_beanstalk_environment: the runtime is out of support |
| `POLICY.IAC.DEPRECATED_RUNTIME.AWS_LAMBDA_FUNCTION.001` | medium | aws_lambda_function: the runtime is out of support |
| `POLICY.IAC.DEPRECATED_RUNTIME.AZURERM_LINUX_FUNCTION_APP.001` | medium | azurerm_linux_function_app: the runtime is out of support |
| `POLICY.IAC.DEPRECATED_RUNTIME.GOOGLE_CLOUDFUNCTIONS_FUNCTION.001` | medium | google_cloudfunctions_function: the runtime is out of support |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_AMI.001` | high | aws_ami: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_AMI_COPY.001` | high | aws_ami_copy: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_APPSYNC_API_CACHE.001` | medium | aws_appsync_api_cache: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ATHENA_DATABASE_ENCRYPTION_CONFIGURATION.001` | medium | aws_athena_database: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ATHENA_WORKGROUP_ENCRYPTION_CONFIGURATION.001` | medium | aws_athena_workgroup: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_BACKUP_VAULT.001` | medium | aws_backup_vault: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CLOUDTRAIL_KMS_KEY_ID.001` | medium | aws_cloudtrail: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CLOUDWATCH_LOG_GROUP_KMS_KEY_ID.001` | low | aws_cloudwatch_log_group: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_CODEBUILD_PROJECT.001` | low | aws_codebuild_project: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DAX_CLUSTER.001` | medium | aws_dax_cluster: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DB_INSTANCE.001` | high | aws_db_instance: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DLM_LIFECYCLE_POLICY.001` | high | aws_dlm_lifecycle_policy: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DOCDB_CLUSTER.001` | high | aws_docdb_cluster: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_DOCDB_GLOBAL_CLUSTER.001` | high | aws_docdb_global_cluster: storage encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_SNAPSHOT_COPY.001` | high | aws_ebs_snapshot_copy: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_SNAPSHOT_IMPORT.001` | high | aws_ebs_snapshot_import: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EBS_VOLUME.001` | high | aws_ebs_volume: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ECR_REPOSITORY.001` | low | aws_ecr_repository: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ECS_SERVICE.001` | high | aws_ecs_service: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EFS_FILE_SYSTEM.001` | high | aws_efs_file_system: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_EKS_CLUSTER.001` | medium | aws_eks_cluster: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ELASTICACHE_REPLICATION_GROUP.001` | medium | aws_elasticache_replication_group: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_ELASTICSEARCH_DOMAIN_ENCRYPT_AT_REST.001` | high | aws_elasticsearch_domain: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_FSX_LUSTRE_FILE_SYSTEM.001` | medium | aws_fsx_lustre_file_system: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_GLUE_CATALOG_DATABASE_TARGET_DATABASE.001` | low | aws_glue_catalog_database: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_INSTANCE.001` | high | aws_instance: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_KINESIS_FIREHOSE_DELIVERY_STREAM_SERVER_SIDE_ENCRYPTION.001` | medium | aws_kinesis_firehose_delivery_stream: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_KINESIS_STREAM_ENCRYPTION_TYPE.001` | medium | aws_kinesis_stream: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_LAMBDA_FUNCTION_KMS_KEY_ARN.001` | low | aws_lambda_function: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_LAUNCH_CONFIGURATION.001` | high | aws_launch_configuration: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_MEMORYDB_CLUSTER_KMS_KEY_ARN.001` | medium | aws_memorydb_cluster: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_MQ_BROKER_ENCRYPTION_OPTIONS.001` | medium | aws_mq_broker: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_NEPTUNE_CLUSTER.001` | high | aws_neptune_cluster: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_NEPTUNE_GLOBAL_CLUSTER.001` | high | aws_neptune_global_cluster: storage encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPENSEARCH_DOMAIN_ENCRYPT_AT_REST.001` | high | aws_opensearch_domain: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_CUSTOM_LAYER.001` | high | aws_opsworks_custom_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_ECS_CLUSTER_LAYER.001` | high | aws_opsworks_ecs_cluster_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_GANGLIA_LAYER.001` | high | aws_opsworks_ganglia_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_HAPROXY_LAYER.001` | high | aws_opsworks_haproxy_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_JAVA_APP_LAYER.001` | high | aws_opsworks_java_app_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_MEMCACHED_LAYER.001` | high | aws_opsworks_memcached_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_MYSQL_LAYER.001` | high | aws_opsworks_mysql_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_NODEJS_APP_LAYER.001` | high | aws_opsworks_nodejs_app_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_PHP_APP_LAYER.001` | high | aws_opsworks_php_app_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_RAILS_APP_LAYER.001` | high | aws_opsworks_rails_app_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_OPSWORKS_STATIC_WEB_LAYER.001` | high | aws_opsworks_static_web_layer: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_QLDB_LEDGER.001` | low | aws_qldb_ledger: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_RDS_CLUSTER.001` | high | aws_rds_cluster: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_RDS_GLOBAL_CLUSTER.001` | medium | aws_rds_global_cluster: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_REDSHIFT_CLUSTER.001` | high | aws_redshift_cluster: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SAGEMAKER_ENDPOINT_CONFIGURATION.001` | medium | aws_sagemaker_endpoint_configuration: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | aws_sagemaker_notebook_instance: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SECRETSMANAGER_SECRET_KMS_KEY_ID.001` | low | aws_secretsmanager_secret: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SNS_TOPIC_KMS_MASTER_KEY_ID.001` | medium | aws_sns_topic: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SPOT_FLEET_REQUEST.001` | high | aws_spot_fleet_request: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SPOT_INSTANCE_REQUEST.001` | high | aws_spot_instance_request: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SQS_QUEUE_KMS_MASTER_KEY_ID.001` | medium | aws_sqs_queue: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_SSM_PARAMETER_KEY_ID.001` | medium | aws_ssm_parameter: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_TIMESTREAMWRITE_DATABASE.001` | low | aws_timestreamwrite_database: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_TRANSFER_SERVER_POST_AUTHENTICATION_LOGIN_BANNER.001` | low | aws_transfer_server: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AWS_WORKSPACES_WORKSPACE.001` | medium | aws_workspaces_workspace: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_AUTOMATION_VARIABLE_BOOL.001` | high | azurerm_automation_variable_bool: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_AUTOMATION_VARIABLE_DATETIME.001` | high | azurerm_automation_variable_datetime: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_AUTOMATION_VARIABLE_INT.001` | high | azurerm_automation_variable_int: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_AUTOMATION_VARIABLE_OBJECT.001` | high | azurerm_automation_variable_object: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_AUTOMATION_VARIABLE_STRING.001` | high | azurerm_automation_variable_string: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_COSMOSDB_ACCOUNT_KEY_VAULT_KEY_ID.001` | low | azurerm_cosmosdb_account: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_DATABRICKS_WORKSPACE.001` | medium | azurerm_databricks_workspace: infrastructure encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_EVENTHUB_NAMESPACE_CUSTOMER_MANAGED_KEY.001` | medium | azurerm_eventhub_namespace_customer_managed_key: infrastructure encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_EVENTHUB_NAMESPACE_LOCAL_AUTHENTICATION_ENABLED.001` | low | azurerm_eventhub_namespace: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HDINSIGHT_HADOOP_CLUSTER.001` | medium | azurerm_hdinsight_hadoop_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HDINSIGHT_HBASE_CLUSTER.001` | medium | azurerm_hdinsight_hbase_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HDINSIGHT_INTERACTIVE_QUERY_CLUSTER.001` | medium | azurerm_hdinsight_interactive_query_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HDINSIGHT_KAFKA_CLUSTER.001` | medium | azurerm_hdinsight_kafka_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HDINSIGHT_SPARK_CLUSTER.001` | medium | azurerm_hdinsight_spark_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_HPC_CACHE.001` | high | azurerm_hpc_cache: encryption at rest |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_LINUX_VIRTUAL_MACHINE.001` | medium | azurerm_linux_virtual_machine: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_LINUX_VIRTUAL_MACHINE_SCALE_SET.001` | medium | azurerm_linux_virtual_machine_scale_set: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MANAGED_DISK.001` | medium | azurerm_managed_disk: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MSSQL_DATABASE_TRANSPARENT_DATA_ENCRYPTION_ENABLED.001` | high | azurerm_mssql_database: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_MYSQL_SERVER.001` | medium | azurerm_mysql_server: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_ORCHESTRATED_VIRTUAL_MACHINE_SCALE_SET.001` | medium | azurerm_orchestrated_virtual_machine_scale_set: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_POSTGRESQL_SERVER.001` | medium | azurerm_postgresql_server: Encryption at rest is not enabled |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_RECOVERY_SERVICES_VAULT.001` | medium | azurerm_recovery_services_vault: infrastructure encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_REDHAT_OPENSHIFT_CLUSTER.001` | medium | azurerm_redhat_openshift_cluster: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_SERVICEBUS_NAMESPACE.001` | medium | azurerm_servicebus_namespace: infrastructure encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_SERVICEBUS_NAMESPACE_CUSTOMER_MANAGED_KEY.001` | medium | azurerm_servicebus_namespace_customer_managed_key: infrastructure encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_STORAGE_ACCOUNT_INFRASTRUCTURE_ENCRYPTION_ENABLED.001` | low | azurerm_storage_account: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_WINDOWS_VIRTUAL_MACHINE.001` | medium | azurerm_windows_virtual_machine: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.AZURERM_WINDOWS_VIRTUAL_MACHINE_SCALE_SET.001` | medium | azurerm_windows_virtual_machine_scale_set: host-level encryption |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_BIGQUERY_DATASET.001` | low | google_bigquery_dataset: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_BIGTABLE_INSTANCE_CLUSTER.001` | low | google_bigtable_instance: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_CONTAINER_CLUSTER_DATABASE_ENCRYPTION.001` | medium | google_container_cluster: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_DATAPROC_CLUSTER.001` | low | google_dataproc_cluster: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_PUBSUB_TOPIC_KMS_KEY_NAME.001` | low | google_pubsub_topic: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_SPANNER_DATABASE_ENCRYPTION_CONFIG.001` | low | google_spanner_database: a customer-managed key is not configured |
| `POLICY.IAC.ENCRYPT_AT_REST.GOOGLE_SQL_DATABASE_INSTANCE.001` | low | google_sql_database_instance: encryption at rest is not configured |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_APPSYNC_API_CACHE.001` | high | aws_appsync_api_cache: encryption in transit |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_CLOUDSEARCH_DOMAIN.001` | high | aws_cloudsearch_domain: https enforcement |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_ELASTICACHE_CLUSTER.001` | high | aws_elasticache_cluster: encryption in transit |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_ELASTICACHE_REPLICATION_GROUP.001` | high | aws_elasticache_replication_group: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_ELASTICSEARCH_DOMAIN.001` | high | aws_elasticsearch_domain: https enforcement |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AWS_OPENSEARCH_DOMAIN.001` | high | aws_opensearch_domain: https enforcement |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_APP_SERVICE.001` | medium | azurerm_app_service: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_APP_SERVICE_SLOT.001` | medium | azurerm_app_service_slot: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_FUNCTION_APP.001` | medium | azurerm_function_app: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_FUNCTION_APP_FLEX_CONSUMPTION.001` | medium | azurerm_function_app_flex_consumption: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_FUNCTION_APP_SLOT.001` | medium | azurerm_function_app_slot: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_FUNCTION_APP.001` | medium | azurerm_linux_function_app: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_FUNCTION_APP_SLOT.001` | medium | azurerm_linux_function_app_slot: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_WEB_APP.001` | medium | azurerm_linux_web_app: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LINUX_WEB_APP_SLOT.001` | medium | azurerm_linux_web_app_slot: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_LOGIC_APP_STANDARD.001` | medium | azurerm_logic_app_standard: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_MARIADB_SERVER.001` | high | azurerm_mariadb_server: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_MYSQL_SERVER.001` | high | azurerm_mysql_server: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_POSTGRESQL_SERVER.001` | high | azurerm_postgresql_server: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_SPRING_CLOUD_APP.001` | medium | azurerm_spring_cloud_app: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_SPRING_CLOUD_GATEWAY.001` | medium | azurerm_spring_cloud_gateway: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_STORAGE_ACCOUNT.001` | high | azurerm_storage_account: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_FUNCTION_APP.001` | medium | azurerm_windows_function_app: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_FUNCTION_APP_SLOT.001` | medium | azurerm_windows_function_app_slot: https-only traffic |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_WEB_APP.001` | medium | azurerm_windows_web_app: Encryption in transit is not enabled |
| `POLICY.IAC.ENCRYPT_IN_TRANSIT.AZURERM_WINDOWS_WEB_APP_SLOT.001` | medium | azurerm_windows_web_app_slot: https-only traffic |
| `POLICY.IAC.FORCE_DESTROY.AWS_ATHENA_DATABASE.001` | low | aws_athena_database: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_ATHENA_WORKGROUP.001` | low | aws_athena_workgroup: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_BACKUP_VAULT.001` | low | aws_backup_vault: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_CLOUDWATCH_EVENT_RULE.001` | low | aws_cloudwatch_event_rule: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_CLOUDWATCH_EVENT_TARGET.001` | low | aws_cloudwatch_event_target: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_DATAEXCHANGE_REVISION_ASSETS.001` | low | aws_dataexchange_revision_assets: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_DEFAULT_SUBNET.001` | low | aws_default_subnet: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_DEFAULT_VPC.001` | low | aws_default_vpc: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_DX_LAG.001` | low | aws_dx_lag: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_ECRPUBLIC_REPOSITORY.001` | low | aws_ecrpublic_repository: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_IAM_USER.001` | low | aws_iam_user: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_RDS_CLUSTER_INSTANCE.001` | low | aws_rds_cluster_instance: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_RDS_GLOBAL_CLUSTER.001` | low | aws_rds_global_cluster: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_REDSHIFT_SNAPSHOT_SCHEDULE.001` | low | aws_redshift_snapshot_schedule: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_ROUTE53_ZONE.001` | low | aws_route53_zone: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_S3_BUCKET.001` | low | aws_s3_bucket: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_S3_BUCKET_OBJECT.001` | low | aws_s3_bucket_object: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_S3_DIRECTORY_BUCKET.001` | low | aws_s3_directory_bucket: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_S3_OBJECT.001` | low | aws_s3_object: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_S3_OBJECT_COPY.001` | low | aws_s3_object_copy: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_SERVICE_DISCOVERY_SERVICE.001` | low | aws_service_discovery_service: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.AWS_TRANSFER_SERVER.001` | low | aws_transfer_server: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_BIGTABLE_INSTANCE.001` | low | google_bigtable_instance: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_DNS_MANAGED_ZONE.001` | low | google_dns_managed_zone: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_GEMINI_CODE_REPOSITORY_INDEX.001` | low | google_gemini_code_repository_index: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_SPANNER_INSTANCE.001` | low | google_spanner_instance: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_STORAGE_BUCKET.001` | low | google_storage_bucket: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_STORAGE_FOLDER.001` | low | google_storage_folder: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_STORAGE_MANAGED_FOLDER.001` | low | google_storage_managed_folder: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_VERTEX_AI_FEATURESTORE.001` | low | google_vertex_ai_featurestore: a destroy will not be stopped by the data in it |
| `POLICY.IAC.FORCE_DESTROY.GOOGLE_VERTEX_AI_FEATURE_ONLINE_STORE.001` | low | google_vertex_ai_feature_online_store: a destroy will not be stopped by the data in it |
| `POLICY.IAC.GOVERNANCE.AWS_DB_INSTANCE.001` | low | aws_db_instance: tags on snapshots |
| `POLICY.IAC.GOVERNANCE.AWS_DOCDB_CLUSTER_INSTANCE.001` | low | aws_docdb_cluster_instance: tags on snapshots |
| `POLICY.IAC.GOVERNANCE.AWS_NEPTUNE_CLUSTER.001` | low | aws_neptune_cluster: tags on snapshots |
| `POLICY.IAC.GOVERNANCE.AWS_RDS_CLUSTER.001` | low | aws_rds_cluster: tags on snapshots |
| `POLICY.IAC.GOVERNANCE.AWS_RDS_CLUSTER_INSTANCE.001` | low | aws_rds_cluster_instance: tags on snapshots |
| `POLICY.IAC.KEY_ROTATION.AWS_KMS_KEY.001` | medium | aws_kms_key: automatic key rotation is not enabled |
| `POLICY.IAC.KEY_ROTATION.GOOGLE_KMS_CRYPTO_KEY.001` | medium | google_kms_crypto_key: no rotation period is set |
| `POLICY.IAC.LOGGING.AWS_ALB_ACCESS_LOGS.001` | low | aws_alb: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_APIGATEWAYV2_STAGE_ACCESS_LOG_SETTINGS.001` | low | aws_apigatewayv2_stage: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_API_GATEWAY_STAGE_ACCESS_LOG_SETTINGS.001` | low | aws_api_gateway_stage: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_API_GATEWAY_STAGE_XRAY_TRACING_ENABLED.001` | low | aws_api_gateway_stage: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_CLOUDFRONT_DISTRIBUTION_LOGGING_CONFIG.001` | low | aws_cloudfront_distribution: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_CLOUDTRAIL_ENABLE_LOG_FILE_VALIDATION.001` | medium | aws_cloudtrail: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_CLOUDTRAIL_IS_MULTI_REGION_TRAIL.001` | medium | aws_cloudtrail: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_DB_INSTANCE.001` | low | aws_db_instance: performance insights |
| `POLICY.IAC.LOGGING.AWS_DOCDB_CLUSTER_ENABLED_CLOUDWATCH_LOGS_EXPORTS.001` | low | aws_docdb_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_EKS_CLUSTER_ENABLED_CLUSTER_LOG_TYPES.001` | medium | aws_eks_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_ELASTICSEARCH_DOMAIN_LOG_PUBLISHING_OPTIONS.001` | low | aws_elasticsearch_domain: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_GLOBALACCELERATOR_ACCELERATOR_ATTRIBUTES.001` | low | aws_globalaccelerator_accelerator: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_LAMBDA_FUNCTION_TRACING_CONFIG.001` | low | aws_lambda_function: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_LB_ACCESS_LOGS.001` | low | aws_lb: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_MQ_BROKER_LOGS.001` | low | aws_mq_broker: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_MSK_CLUSTER_LOGGING_INFO.001` | low | aws_msk_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_NEPTUNE_CLUSTER_ENABLE_CLOUDWATCH_LOGS_EXPORTS.001` | low | aws_neptune_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_OPENSEARCH_DOMAIN_LOG_PUBLISHING_OPTIONS.001` | low | aws_opensearch_domain: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_RDS_CLUSTER.001` | low | aws_rds_cluster: performance insights |
| `POLICY.IAC.LOGGING.AWS_RDS_CLUSTER_INSTANCE.001` | low | aws_rds_cluster_instance: performance insights |
| `POLICY.IAC.LOGGING.AWS_REDSHIFT_CLUSTER_LOGGING.001` | low | aws_redshift_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_S3_BUCKET_LOGGING_TARGET_BUCKET.001` | low | aws_s3_bucket_logging: audit logging is not configured |
| `POLICY.IAC.LOGGING.AWS_VPC_ENABLE_DNS_HOSTNAMES.001` | low | aws_vpc: audit logging is not configured |
| `POLICY.IAC.LOGGING.AZURERM_KEY_VAULT_SOFT_DELETE_RETENTION_DAYS.001` | low | azurerm_key_vault: audit logging is not configured |
| `POLICY.IAC.LOGGING.AZURERM_KUBERNETES_CLUSTER_OMS_AGENT.001` | low | azurerm_kubernetes_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.AZURERM_MSSQL_SERVER_EXTENDED_AUDITING_POLICY.001` | medium | azurerm_mssql_server: audit logging is not configured |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_FIREWALL.001` | low | google_compute_firewall: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_FIREWALL_POLICY_RULE.001` | low | google_compute_firewall_policy_rule: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_FIREWALL_POLICY_WITH_RULES.001` | low | google_compute_firewall_policy_with_rules: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_NETWORK_FIREWALL_POLICY_RULE.001` | low | google_compute_network_firewall_policy_rule: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_NETWORK_FIREWALL_POLICY_WITH_RULES.001` | low | google_compute_network_firewall_policy_with_rules: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_REGION_NETWORK_FIREWALL_POLICY_RULE.001` | low | google_compute_region_network_firewall_policy_rule: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_REGION_NETWORK_FIREWALL_POLICY_WITH_RULES.001` | low | google_compute_region_network_firewall_policy_with_rules: logging |
| `POLICY.IAC.LOGGING.GOOGLE_COMPUTE_SUBNETWORK_LOG_CONFIG.001` | low | google_compute_subnetwork: audit logging is not configured |
| `POLICY.IAC.LOGGING.GOOGLE_CONTAINER_CLUSTER_LOGGING_SERVICE.001` | low | google_container_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.GOOGLE_CONTAINER_CLUSTER_MONITORING_SERVICE.001` | low | google_container_cluster: audit logging is not configured |
| `POLICY.IAC.LOGGING.GOOGLE_DATA_FUSION_INSTANCE.001` | low | google_data_fusion_instance: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_AGENT.001` | low | google_dialogflow_agent: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_CONVERSATION_PROFILE.001` | low | google_dialogflow_conversation_profile: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_CX_AGENT.001` | low | google_dialogflow_cx_agent: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_CX_FLOW.001` | low | google_dialogflow_cx_flow: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_CX_PAGE.001` | low | google_dialogflow_cx_page: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DIALOGFLOW_CX_WEBHOOK.001` | low | google_dialogflow_cx_webhook: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DNS_MANAGED_ZONE.001` | low | google_dns_managed_zone: logging |
| `POLICY.IAC.LOGGING.GOOGLE_DNS_POLICY.001` | low | google_dns_policy: logging |
| `POLICY.IAC.LOGGING.GOOGLE_SQL_DATABASE_INSTANCE_BACKUP_CONFIGURATION.001` | medium | google_sql_database_instance: audit logging is not configured |
| `POLICY.IAC.LOGGING.GOOGLE_STORAGE_BUCKET_LOGGING.001` | low | google_storage_bucket: audit logging is not configured |
| `POLICY.IAC.MFA.AWS_S3_BUCKET.001` | medium | aws_s3_bucket: mfa for deletion |
| `POLICY.IAC.MUTABLE_TAGS.AWS_ECR_REPOSITORY.001` | medium | aws_ecr_repository: image tags are mutable |
| `POLICY.IAC.NO_MFA.AWS_IAM_USER.001` | low | aws_iam_user: a long-lived user is created |
| `POLICY.IAC.ORPHANED_DATA.AWS_AMI.001` | low | aws_ami: deleting the volume with the instance |
| `POLICY.IAC.ORPHANED_DATA.AWS_INSTANCE.001` | low | aws_instance: deleting the volume with the instance |
| `POLICY.IAC.ORPHANED_DATA.AWS_LAUNCH_CONFIGURATION.001` | low | aws_launch_configuration: deleting the volume with the instance |
| `POLICY.IAC.ORPHANED_DATA.AWS_OPSWORKS_INSTANCE.001` | low | aws_opsworks_instance: deleting the volume with the instance |
| `POLICY.IAC.ORPHANED_DATA.AWS_SPOT_FLEET_REQUEST.001` | low | aws_spot_fleet_request: deleting the volume with the instance |
| `POLICY.IAC.ORPHANED_DATA.AWS_SPOT_INSTANCE_REQUEST.001` | low | aws_spot_instance_request: deleting the volume with the instance |
| `POLICY.IAC.PATCHING.AWS_DB_INSTANCE.001` | medium | aws_db_instance: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_DMS_REPLICATION_INSTANCE.001` | medium | aws_dms_replication_instance: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_DOCDB_CLUSTER_INSTANCE.001` | medium | aws_docdb_cluster_instance: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_MEMORYDB_CLUSTER.001` | medium | aws_memorydb_cluster: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_MQ_BROKER.001` | medium | aws_mq_broker: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_NEPTUNE_CLUSTER_INSTANCE.001` | medium | aws_neptune_cluster_instance: automatic minor version upgrades |
| `POLICY.IAC.PATCHING.AWS_RDS_CLUSTER_INSTANCE.001` | medium | aws_rds_cluster_instance: automatic minor version upgrades |
| `POLICY.IAC.PUBLIC_IP.AWS_CLOUDWATCH_EVENT_TARGET.001` | low | aws_cloudwatch_event_target: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_DEFAULT_SUBNET.001` | low | aws_default_subnet: every instance in the subnet gets a public address |
| `POLICY.IAC.PUBLIC_IP.AWS_ECS_SERVICE.001` | low | aws_ecs_service: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_ECS_TASK_SET.001` | low | aws_ecs_task_set: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_INSTANCE.001` | low | aws_instance: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_LAUNCH_CONFIGURATION.001` | low | aws_launch_configuration: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_SCHEDULER_SCHEDULE.001` | low | aws_scheduler_schedule: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_SPOT_FLEET_REQUEST.001` | low | aws_spot_fleet_request: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_SPOT_INSTANCE_REQUEST.001` | low | aws_spot_instance_request: a public ip address |
| `POLICY.IAC.PUBLIC_IP.AWS_SUBNET.001` | low | aws_subnet: every instance in the subnet gets a public address |
| `POLICY.IAC.RESILIENCE.AWS_CLOUDSEARCH_DOMAIN.001` | low | aws_cloudsearch_domain: a standby in another availability zone |
| `POLICY.IAC.RESILIENCE.AWS_DB_INSTANCE.001` | low | aws_db_instance: a standby in another availability zone |
| `POLICY.IAC.RESILIENCE.AWS_DMS_REPLICATION_CONFIG.001` | low | aws_dms_replication_config: a standby in another availability zone |
| `POLICY.IAC.RESILIENCE.AWS_DMS_REPLICATION_INSTANCE.001` | low | aws_dms_replication_instance: a standby in another availability zone |
| `POLICY.IAC.RESILIENCE.AWS_REDSHIFT_CLUSTER.001` | low | aws_redshift_cluster: a standby in another availability zone |
| `POLICY.IAC.RETENTION.AWS_CLOUDWATCH_LOG_GROUP.001` | low | aws_cloudwatch_log_group: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_APPLICATION_INSIGHTS.001` | low | azurerm_application_insights: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_APP_SERVICE.001` | low | azurerm_app_service: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_APP_SERVICE_SLOT.001` | low | azurerm_app_service_slot: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_FIREWALL_POLICY.001` | low | azurerm_firewall_policy: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LINUX_WEB_APP.001` | low | azurerm_linux_web_app: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LINUX_WEB_APP_SLOT.001` | low | azurerm_linux_web_app_slot: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LOG_ANALYTICS_WORKSPACE.001` | low | azurerm_log_analytics_workspace: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LOG_ANALYTICS_WORKSPACE_TABLE.001` | low | azurerm_log_analytics_workspace_table: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LOG_ANALYTICS_WORKSPACE_TABLE_CUSTOM_LOG.001` | low | azurerm_log_analytics_workspace_table_custom_log: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_LOG_ANALYTICS_WORKSPACE_TABLE_MICROSOFT.001` | low | azurerm_log_analytics_workspace_table_microsoft: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_MSSQL_DATABASE_EXTENDED_AUDITING_POLICY.001` | low | azurerm_mssql_database_extended_auditing_policy: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_MSSQL_SERVER_EXTENDED_AUDITING_POLICY.001` | low | azurerm_mssql_server_extended_auditing_policy: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_SYNAPSE_SQL_POOL_EXTENDED_AUDITING_POLICY.001` | low | azurerm_synapse_sql_pool_extended_auditing_policy: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_SYNAPSE_WORKSPACE_EXTENDED_AUDITING_POLICY.001` | low | azurerm_synapse_workspace_extended_auditing_policy: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_WINDOWS_WEB_APP.001` | low | azurerm_windows_web_app: a retention period |
| `POLICY.IAC.RETENTION.AZURERM_WINDOWS_WEB_APP_SLOT.001` | low | azurerm_windows_web_app_slot: a retention period |
| `POLICY.IAC.RUN_AS_ROOT.AWS_BATCH_JOB_DEFINITION.001` | medium | aws_batch_job_definition: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_CRON_JOB.001` | medium | kubernetes_cron_job: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_CRON_JOB_V1.001` | medium | kubernetes_cron_job_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_DAEMONSET.001` | medium | kubernetes_daemonset: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_DAEMON_SET_V1.001` | medium | kubernetes_daemon_set_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_DEPLOYMENT.001` | medium | kubernetes_deployment: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_DEPLOYMENT_V1.001` | medium | kubernetes_deployment_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_JOB.001` | medium | kubernetes_job: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_JOB_V1.001` | medium | kubernetes_job_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_POD.001` | medium | kubernetes_pod: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_POD_V1.001` | medium | kubernetes_pod_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_REPLICATION_CONTROLLER.001` | medium | kubernetes_replication_controller: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | medium | kubernetes_replication_controller_v1: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_STATEFUL_SET.001` | medium | kubernetes_stateful_set: a non-root user |
| `POLICY.IAC.RUN_AS_ROOT.KUBERNETES_STATEFUL_SET_V1.001` | medium | kubernetes_stateful_set_v1: a non-root user |
| `POLICY.IAC.SCAN_ON_PUSH.AWS_ECR_REPOSITORY.001` | low | aws_ecr_repository: images are not scanned on push |
| `POLICY.IAC.SHARED_KEY_AUTH.AWS_DB_INSTANCE.001` | low | aws_db_instance: iam database authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AWS_NEPTUNE_CLUSTER.001` | low | aws_neptune_cluster: iam database authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AWS_RDS_CLUSTER.001` | low | aws_rds_cluster: iam database authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_AI_SERVICES.001` | medium | azurerm_ai_services: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_APPLICATION_INSIGHTS.001` | medium | azurerm_application_insights: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_APP_CONFIGURATION.001` | medium | azurerm_app_configuration: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_AUTOMATION_ACCOUNT.001` | medium | azurerm_automation_account: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_BOT_SERVICE_AZURE_BOT.001` | medium | azurerm_bot_service_azure_bot: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_COGNITIVE_ACCOUNT.001` | medium | azurerm_cognitive_account: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_COSMOSDB_ACCOUNT.001` | medium | azurerm_cosmosdb_account: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_EVENTGRID_DOMAIN.001` | medium | azurerm_eventgrid_domain: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_EVENTGRID_PARTNER_NAMESPACE.001` | medium | azurerm_eventgrid_partner_namespace: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_EVENTGRID_TOPIC.001` | medium | azurerm_eventgrid_topic: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_EVENTHUB_NAMESPACE.001` | medium | azurerm_eventhub_namespace: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_IOTHUB.001` | medium | azurerm_iothub: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_LOG_ANALYTICS_WORKSPACE.001` | medium | azurerm_log_analytics_workspace: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_MACHINE_LEARNING_COMPUTE_CLUSTER.001` | medium | azurerm_machine_learning_compute_cluster: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_MACHINE_LEARNING_COMPUTE_INSTANCE.001` | medium | azurerm_machine_learning_compute_instance: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_MACHINE_LEARNING_SYNAPSE_SPARK.001` | medium | azurerm_machine_learning_synapse_spark: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_MAPS_ACCOUNT.001` | medium | azurerm_maps_account: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_SEARCH_SERVICE.001` | medium | azurerm_search_service: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_SERVICEBUS_NAMESPACE.001` | medium | azurerm_servicebus_namespace: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_SIGNALR_SERVICE.001` | medium | azurerm_signalr_service: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_WEB_PUBSUB.001` | medium | azurerm_web_pubsub: shared-key authentication |
| `POLICY.IAC.SHARED_KEY_AUTH.AZURERM_WEB_PUBSUB_SOCKETIO.001` | medium | azurerm_web_pubsub_socketio: shared-key authentication |
| `POLICY.IAC.SQL_REQUIRE_SSL.GOOGLE_SQL_DATABASE_INSTANCE.001` | medium | google_sql_database_instance: SSL is not required |
| `POLICY.IAC.UNENCRYPTED_STATE.TERRAFORM.001` | high | The remote state backend does not require encryption |
| `POLICY.IAC.WEAK_TLS.AWS_API_GATEWAY_DOMAIN_NAME.001` | medium | aws_api_gateway_domain_name: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AWS_LB_LISTENER.001` | medium | aws_lb_listener: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_APP_SERVICE.001` | medium | azurerm_app_service: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_APP_SERVICE_SLOT.001` | medium | azurerm_app_service_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_CDN_FRONTDOOR_CUSTOM_DOMAIN.001` | medium | azurerm_cdn_frontdoor_custom_domain: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_EVENTHUB_NAMESPACE.001` | medium | azurerm_eventhub_namespace: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_FUNCTION_APP.001` | medium | azurerm_function_app: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_FUNCTION_APP_FLEX_CONSUMPTION.001` | medium | azurerm_function_app_flex_consumption: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_FUNCTION_APP_SLOT.001` | medium | azurerm_function_app_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_HDINSIGHT_HADOOP_CLUSTER.001` | medium | azurerm_hdinsight_hadoop_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_HDINSIGHT_HBASE_CLUSTER.001` | medium | azurerm_hdinsight_hbase_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_HDINSIGHT_INTERACTIVE_QUERY_CLUSTER.001` | medium | azurerm_hdinsight_interactive_query_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_HDINSIGHT_KAFKA_CLUSTER.001` | medium | azurerm_hdinsight_kafka_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_HDINSIGHT_SPARK_CLUSTER.001` | medium | azurerm_hdinsight_spark_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_IOTHUB.001` | medium | azurerm_iothub: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_LINUX_FUNCTION_APP.001` | medium | azurerm_linux_function_app: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_LINUX_FUNCTION_APP_SLOT.001` | medium | azurerm_linux_function_app_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_LINUX_WEB_APP.001` | medium | azurerm_linux_web_app: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_LINUX_WEB_APP_SLOT.001` | medium | azurerm_linux_web_app_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_LOGIC_APP_STANDARD.001` | medium | azurerm_logic_app_standard: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_MSSQL_MANAGED_INSTANCE.001` | medium | azurerm_mssql_managed_instance: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_MSSQL_SERVER.001` | medium | azurerm_mssql_server: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_REDIS_CACHE.001` | medium | azurerm_redis_cache: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_REDIS_ENTERPRISE_CLUSTER.001` | medium | azurerm_redis_enterprise_cluster: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_SERVICEBUS_NAMESPACE.001` | medium | azurerm_servicebus_namespace: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_STORAGE_ACCOUNT.001` | medium | azurerm_storage_account: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_WINDOWS_FUNCTION_APP.001` | medium | azurerm_windows_function_app: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_WINDOWS_FUNCTION_APP_SLOT.001` | medium | azurerm_windows_function_app_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_WINDOWS_WEB_APP.001` | medium | azurerm_windows_web_app: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.AZURERM_WINDOWS_WEB_APP_SLOT.001` | medium | azurerm_windows_web_app_slot: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.GOOGLE_COMPUTE_REGION_SSL_POLICY.001` | medium | google_compute_region_ssl_policy: an obsolete tls version is accepted |
| `POLICY.IAC.WEAK_TLS.GOOGLE_COMPUTE_SSL_POLICY.001` | medium | google_compute_ssl_policy: obsolete TLS version accepted |
| `POLICY.IAC.WEAK_TLS.GOOGLE_NETWORK_SECURITY_TLS_INSPECTION_POLICY.001` | medium | google_network_security_tls_inspection_policy: an obsolete tls version is accepted |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_CRON_JOB.001` | low | kubernetes_cron_job: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_CRON_JOB_V1.001` | low | kubernetes_cron_job_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_DAEMONSET.001` | low | kubernetes_daemonset: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_DAEMON_SET_V1.001` | low | kubernetes_daemon_set_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_DEPLOYMENT.001` | low | kubernetes_deployment: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_DEPLOYMENT_V1.001` | low | kubernetes_deployment_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_JOB.001` | low | kubernetes_job: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_JOB_V1.001` | low | kubernetes_job_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_POD.001` | low | kubernetes_pod: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_POD_SECURITY_POLICY.001` | low | kubernetes_pod_security_policy: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_POD_SECURITY_POLICY_V1BETA1.001` | low | kubernetes_pod_security_policy_v1beta1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_POD_V1.001` | low | kubernetes_pod_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_REPLICATION_CONTROLLER.001` | low | kubernetes_replication_controller: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | low | kubernetes_replication_controller_v1: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_STATEFUL_SET.001` | low | kubernetes_stateful_set: a read-only root filesystem |
| `POLICY.IAC.WRITABLE_ROOT.KUBERNETES_STATEFUL_SET_V1.001` | low | kubernetes_stateful_set_v1: a read-only root filesystem |
| `SUSPECT.IAC.ADMIN_ENABLED.AZURERM_CONTAINER_REGISTRY.001` | medium | azurerm_container_registry: the shared admin account is enabled |
| `SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001` | high | Play downloads and runs a script on every host |
| `SUSPECT.IAC.ANSIBLE_UNSIGNED_PACKAGES.001` | high | Task installs packages without checking their signatures |
| `SUSPECT.IAC.CREDENTIALS_INLINE.TERRAFORM.001` | high | A static credential is written into the configuration |
| `SUSPECT.IAC.ENCRYPT_IN_TRANSIT.GOOGLE_OS_CONFIG_OS_POLICY_ASSIGNMENT.001` | medium | google_os_config_os_policy_assignment: insecure transport is allowed |
| `SUSPECT.IAC.ENCRYPT_IN_TRANSIT.GOOGLE_OS_CONFIG_V2_POLICY_ORCHESTRATOR.001` | medium | google_os_config_v2_policy_orchestrator: insecure transport is allowed |
| `SUSPECT.IAC.ENCRYPT_IN_TRANSIT.GOOGLE_OS_CONFIG_V2_POLICY_ORCHESTRATOR_FOR_FOLDER.001` | medium | google_os_config_v2_policy_orchestrator_for_folder: insecure transport is allowed |
| `SUSPECT.IAC.ENCRYPT_IN_TRANSIT.GOOGLE_OS_CONFIG_V2_POLICY_ORCHESTRATOR_FOR_ORGANIZATION.001` | medium | google_os_config_v2_policy_orchestrator_for_organization: insecure transport is allowed |
| `SUSPECT.IAC.EXTERNAL_PROGRAM.TERRAFORM.001` | medium | A data source runs a local program when the plan is made |
| `SUSPECT.IAC.HOST_MOUNT.001` | high | Host path mounted into a container |
| `SUSPECT.IAC.HOST_NAMESPACE.AWS_BATCH_JOB_DEFINITION.001` | high | aws_batch_job_definition: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_CRON_JOB.001` | high | kubernetes_cron_job: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_CRON_JOB_V1.001` | high | kubernetes_cron_job_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_DAEMONSET.001` | high | kubernetes_daemonset: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_DAEMON_SET_V1.001` | high | kubernetes_daemon_set_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_DEPLOYMENT.001` | high | kubernetes_deployment: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_DEPLOYMENT_V1.001` | high | kubernetes_deployment_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_JOB.001` | high | kubernetes_job: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_JOB_V1.001` | high | kubernetes_job_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_POD.001` | high | kubernetes_pod: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_POD_SECURITY_POLICY.001` | high | kubernetes_pod_security_policy: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_POD_SECURITY_POLICY_V1BETA1.001` | high | kubernetes_pod_security_policy_v1beta1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_POD_V1.001` | high | kubernetes_pod_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_REPLICATION_CONTROLLER.001` | high | kubernetes_replication_controller: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | high | kubernetes_replication_controller_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_STATEFUL_SET.001` | high | kubernetes_stateful_set: the pod shares the node's network namespace |
| `SUSPECT.IAC.HOST_NAMESPACE.KUBERNETES_STATEFUL_SET_V1.001` | high | kubernetes_stateful_set_v1: the pod shares the node's network namespace |
| `SUSPECT.IAC.IAM_WILDCARD.001` | high | Policy grants every action or every resource |
| `SUSPECT.IAC.IMDSV1.AWS_EC2_INSTANCE_METADATA_DEFAULTS.001` | medium | aws_ec2_instance_metadata_defaults: instance metadata is reachable without a token |
| `SUSPECT.IAC.IMDSV1.AWS_IMAGEBUILDER_INFRASTRUCTURE_CONFIGURATION.001` | medium | aws_imagebuilder_infrastructure_configuration: instance metadata is reachable without a token |
| `SUSPECT.IAC.IMDSV1.AWS_INSTANCE.001` | medium | aws_instance: instance metadata is reachable without a token |
| `SUSPECT.IAC.IMDSV1.AWS_SPOT_INSTANCE_REQUEST.001` | medium | aws_spot_instance_request: instance metadata is reachable without a token |
| `SUSPECT.IAC.LEGACY_ABAC.GOOGLE_CONTAINER_CLUSTER.001` | high | google_container_cluster: legacy ABAC authorisation is enabled |
| `SUSPECT.IAC.LOCAL_EXEC.TERRAFORM.001` | medium | A provisioner runs a shell command on the machine applying the plan |
| `SUSPECT.IAC.NO_AUTH.AWS_API_GATEWAY_METHOD.001` | medium | aws_api_gateway_method: the method is unauthenticated |
| `SUSPECT.IAC.NO_AUTH.AZURERM_FUNCTION_APP_FLEX_CONSUMPTION.001` | high | azurerm_function_app_flex_consumption: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_LINUX_FUNCTION_APP.001` | high | azurerm_linux_function_app: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_LINUX_FUNCTION_APP_SLOT.001` | high | azurerm_linux_function_app_slot: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_LINUX_WEB_APP.001` | high | azurerm_linux_web_app: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_LINUX_WEB_APP_SLOT.001` | high | azurerm_linux_web_app_slot: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_NETAPP_VOLUME_GROUP_ORACLE.001` | medium | azurerm_netapp_volume_group_oracle: nfsv3 is enabled |
| `SUSPECT.IAC.NO_AUTH.AZURERM_NETAPP_VOLUME_GROUP_SAP_HANA.001` | medium | azurerm_netapp_volume_group_sap_hana: nfsv3 is enabled |
| `SUSPECT.IAC.NO_AUTH.AZURERM_STORAGE_ACCOUNT.001` | medium | azurerm_storage_account: nfsv3 is enabled |
| `SUSPECT.IAC.NO_AUTH.AZURERM_WINDOWS_FUNCTION_APP.001` | high | azurerm_windows_function_app: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_WINDOWS_FUNCTION_APP_SLOT.001` | high | azurerm_windows_function_app_slot: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_WINDOWS_WEB_APP.001` | high | azurerm_windows_web_app: authentication |
| `SUSPECT.IAC.NO_AUTH.AZURERM_WINDOWS_WEB_APP_SLOT.001` | high | azurerm_windows_web_app_slot: authentication |
| `SUSPECT.IAC.OWNER_ROLE.AZURERM_ROLE_ASSIGNMENT.001` | medium | azurerm_role_assignment: Owner or Contributor is assigned |
| `SUSPECT.IAC.OWNER_ROLE.GOOGLE_PROJECT_IAM_MEMBER.001` | medium | google_project_iam_member: the owner role is granted directly |
| `SUSPECT.IAC.PASSWORD_AUTH.AZURERM_LINUX_VIRTUAL_MACHINE.001` | medium | azurerm_linux_virtual_machine: password authentication is enabled |
| `SUSPECT.IAC.PLAINTEXT.AWS_LB_LISTENER.001` | medium | aws_lb_listener: traffic is served over plain HTTP |
| `SUSPECT.IAC.PLAINTEXT.AWS_MSK_CLUSTER.001` | high | aws_msk_cluster: brokers accept plaintext client connections |
| `SUSPECT.IAC.PLAINTEXT.AZURERM_REDIS_CACHE.001` | high | azurerm_redis_cache: the non-TLS port is open |
| `SUSPECT.IAC.PRIVILEGED.001` | high | Privileged container or host namespace |
| `SUSPECT.IAC.PRIVILEGED.AWS_BATCH_JOB_DEFINITION.001` | high | aws_batch_job_definition: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.AWS_CODEBUILD_PROJECT.001` | medium | aws_codebuild_project: the build runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_CRON_JOB.001` | high | kubernetes_cron_job: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_CRON_JOB_V1.001` | high | kubernetes_cron_job_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_DAEMONSET.001` | high | kubernetes_daemonset: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_DAEMON_SET_V1.001` | high | kubernetes_daemon_set_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_DEPLOYMENT.001` | high | kubernetes_deployment: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_DEPLOYMENT_V1.001` | high | kubernetes_deployment_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_JOB.001` | high | kubernetes_job: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_JOB_V1.001` | high | kubernetes_job_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_POD.001` | high | kubernetes_pod: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_POD_SECURITY_POLICY.001` | high | kubernetes_pod_security_policy: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_POD_SECURITY_POLICY_V1BETA1.001` | high | kubernetes_pod_security_policy_v1beta1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_POD_V1.001` | high | kubernetes_pod_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_REPLICATION_CONTROLLER.001` | high | kubernetes_replication_controller: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | high | kubernetes_replication_controller_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_STATEFUL_SET.001` | high | kubernetes_stateful_set: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED.KUBERNETES_STATEFUL_SET_V1.001` | high | kubernetes_stateful_set_v1: the container runs privileged |
| `SUSPECT.IAC.PRIVILEGED_BUILD.AWS_CODEBUILD_PROJECT.001` | medium | aws_codebuild_project: the build runs privileged |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_CRON_JOB.001` | medium | kubernetes_cron_job: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_CRON_JOB_V1.001` | medium | kubernetes_cron_job_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_DAEMONSET.001` | medium | kubernetes_daemonset: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_DAEMON_SET_V1.001` | medium | kubernetes_daemon_set_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_DEPLOYMENT.001` | medium | kubernetes_deployment: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_DEPLOYMENT_V1.001` | medium | kubernetes_deployment_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_JOB.001` | medium | kubernetes_job: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_JOB_V1.001` | medium | kubernetes_job_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_POD.001` | medium | kubernetes_pod: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_POD_SECURITY_POLICY.001` | medium | kubernetes_pod_security_policy: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_POD_SECURITY_POLICY_V1BETA1.001` | medium | kubernetes_pod_security_policy_v1beta1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_POD_V1.001` | medium | kubernetes_pod_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_REPLICATION_CONTROLLER.001` | medium | kubernetes_replication_controller: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_REPLICATION_CONTROLLER_V1.001` | medium | kubernetes_replication_controller_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_STATEFUL_SET.001` | medium | kubernetes_stateful_set: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PRIVILEGE_ESCALATION.KUBERNETES_STATEFUL_SET_V1.001` | medium | kubernetes_stateful_set_v1: the container may gain more privileges than it started with |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DB_INSTANCE.001` | high | aws_db_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DMS_REPLICATION_INSTANCE.001` | medium | aws_dms_replication_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_DOCDB_CLUSTER_INSTANCE.001` | high | aws_docdb_cluster_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_LIGHTSAIL_DATABASE.001` | high | aws_lightsail_database: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_M2_ENVIRONMENT.001` | high | aws_m2_environment: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_MQ_BROKER.001` | high | aws_mq_broker: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_NEPTUNE_CLUSTER_INSTANCE.001` | high | aws_neptune_cluster_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_RDS_CLUSTER_INSTANCE.001` | high | aws_rds_cluster_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_RDS_SHARD_GROUP.001` | high | aws_rds_shard_group: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_REDSHIFTSERVERLESS_WORKGROUP.001` | high | aws_redshiftserverless_workgroup: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_REDSHIFT_CLUSTER.001` | high | aws_redshift_cluster: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | aws_sagemaker_notebook_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AWS_TIMESTREAMINFLUXDB_DB_INSTANCE.001` | high | aws_timestreaminfluxdb_db_instance: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_AI_FOUNDRY.001` | medium | azurerm_ai_foundry: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_AI_SERVICES.001` | medium | azurerm_ai_services: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_API_MANAGEMENT.001` | medium | azurerm_api_management: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_APP_CONFIGURATION.001` | medium | azurerm_app_configuration: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_ARC_PRIVATE_LINK_SCOPE.001` | medium | azurerm_arc_private_link_scope: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_AUTOMATION_ACCOUNT.001` | medium | azurerm_automation_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_BATCH_ACCOUNT.001` | medium | azurerm_batch_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_BOT_CHANNELS_REGISTRATION.001` | medium | azurerm_bot_channels_registration: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_BOT_SERVICE_AZURE_BOT.001` | medium | azurerm_bot_service_azure_bot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_COGNITIVE_ACCOUNT.001` | medium | azurerm_cognitive_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_CONTAINER_APP_ENVIRONMENT.001` | medium | azurerm_container_app_environment: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_CONTAINER_REGISTRY.001` | low | azurerm_container_registry: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_COSMOSDB_ACCOUNT.001` | medium | azurerm_cosmosdb_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_DASHBOARD_GRAFANA.001` | medium | azurerm_dashboard_grafana: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_DATABRICKS_WORKSPACE.001` | medium | azurerm_databricks_workspace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_EVENTGRID_DOMAIN.001` | medium | azurerm_eventgrid_domain: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_EVENTGRID_NAMESPACE.001` | medium | azurerm_eventgrid_namespace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_EVENTGRID_PARTNER_NAMESPACE.001` | medium | azurerm_eventgrid_partner_namespace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_EVENTGRID_TOPIC.001` | medium | azurerm_eventgrid_topic: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_EVENTHUB_NAMESPACE.001` | medium | azurerm_eventhub_namespace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_FUNCTION_APP_FLEX_CONSUMPTION.001` | medium | azurerm_function_app_flex_consumption: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_HEALTHCARE_DICOM_SERVICE.001` | medium | azurerm_healthcare_dicom_service: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_HEALTHCARE_SERVICE.001` | medium | azurerm_healthcare_service: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_IOTCENTRAL_APPLICATION.001` | medium | azurerm_iotcentral_application: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_IOTHUB.001` | medium | azurerm_iothub: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_IOTHUB_DEVICE_UPDATE_ACCOUNT.001` | medium | azurerm_iothub_device_update_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_IOTHUB_DPS.001` | medium | azurerm_iothub_dps: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_KEY_VAULT.001` | medium | azurerm_key_vault: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_KEY_VAULT_MANAGED_HARDWARE_SECURITY_MODULE.001` | medium | azurerm_key_vault_managed_hardware_security_module: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_KUSTO_CLUSTER.001` | medium | azurerm_kusto_cluster: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_LINUX_FUNCTION_APP.001` | medium | azurerm_linux_function_app: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_LINUX_FUNCTION_APP_SLOT.001` | medium | azurerm_linux_function_app_slot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_LINUX_WEB_APP.001` | medium | azurerm_linux_web_app: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_LINUX_WEB_APP_SLOT.001` | medium | azurerm_linux_web_app_slot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_LOGIC_APP_STANDARD.001` | medium | azurerm_logic_app_standard: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MACHINE_LEARNING_WORKSPACE.001` | medium | azurerm_machine_learning_workspace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MANAGED_DISK.001` | medium | azurerm_managed_disk: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MANAGED_REDIS.001` | medium | azurerm_managed_redis: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MONGO_CLUSTER.001` | medium | azurerm_mongo_cluster: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MONITOR_DATA_COLLECTION_ENDPOINT.001` | medium | azurerm_monitor_data_collection_endpoint: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MONITOR_WORKSPACE.001` | medium | azurerm_monitor_workspace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MSSQL_SERVER.001` | medium | azurerm_mssql_server: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MYSQL_FLEXIBLE_SERVER.001` | medium | azurerm_mysql_flexible_server: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_MYSQL_SERVER.001` | medium | azurerm_mysql_server: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_POSTGRESQL_FLEXIBLE_SERVER.001` | medium | azurerm_postgresql_flexible_server: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_POSTGRESQL_SERVER.001` | medium | azurerm_postgresql_server: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_RECOVERY_SERVICES_VAULT.001` | medium | azurerm_recovery_services_vault: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_REDIS_CACHE.001` | medium | azurerm_redis_cache: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_RESOURCE_MANAGEMENT_PRIVATE_LINK_ASSOCIATION.001` | medium | azurerm_resource_management_private_link_association: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SEARCH_SERVICE.001` | medium | azurerm_search_service: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SERVICEBUS_NAMESPACE.001` | medium | azurerm_servicebus_namespace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SIGNALR_SERVICE.001` | medium | azurerm_signalr_service: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SNAPSHOT.001` | medium | azurerm_snapshot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SPRING_CLOUD_API_PORTAL.001` | medium | azurerm_spring_cloud_api_portal: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SPRING_CLOUD_DEV_TOOL_PORTAL.001` | medium | azurerm_spring_cloud_dev_tool_portal: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SPRING_CLOUD_GATEWAY.001` | medium | azurerm_spring_cloud_gateway: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_STATIC_WEB_APP.001` | medium | azurerm_static_web_app: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_STORAGE_ACCOUNT.001` | medium | azurerm_storage_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_SYNAPSE_WORKSPACE.001` | medium | azurerm_synapse_workspace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_VIDEO_INDEXER_ACCOUNT.001` | medium | azurerm_video_indexer_account: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_VIRTUAL_DESKTOP_HOST_POOL.001` | medium | azurerm_virtual_desktop_host_pool: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_VIRTUAL_DESKTOP_WORKSPACE.001` | medium | azurerm_virtual_desktop_workspace: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WEB_PUBSUB.001` | medium | azurerm_web_pubsub: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WEB_PUBSUB_SOCKETIO.001` | medium | azurerm_web_pubsub_socketio: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WINDOWS_FUNCTION_APP.001` | medium | azurerm_windows_function_app: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WINDOWS_FUNCTION_APP_SLOT.001` | medium | azurerm_windows_function_app_slot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WINDOWS_WEB_APP.001` | medium | azurerm_windows_web_app: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS.AZURERM_WINDOWS_WEB_APP_SLOT.001` | medium | azurerm_windows_web_app_slot: reachable from the public internet |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.BLOCK_PUBLIC_ACLS.001` | high | aws_s3_bucket_public_access_block: block_public_acls is off |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.BLOCK_PUBLIC_POLICY.001` | high | aws_s3_bucket_public_access_block: block_public_policy is off |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.IGNORE_PUBLIC_ACLS.001` | high | aws_s3_bucket_public_access_block: ignore_public_acls is off |
| `SUSPECT.IAC.PUBLIC_ACCESS_BLOCK.RESTRICT_PUBLIC_BUCKETS.001` | high | aws_s3_bucket_public_access_block: restrict_public_buckets is off |
| `SUSPECT.IAC.PUBLIC_IAM.GOOGLE_PROJECT_IAM_MEMBER.001` | high | google_project_iam_member: a role is granted to everyone |
| `SUSPECT.IAC.PUBLIC_INGRESS.001` | high | Ingress permitted from the entire internet |
| `SUSPECT.IAC.PUBLIC_SQL.GOOGLE_SQL_DATABASE_INSTANCE.001` | high | google_sql_database_instance: authorised network is the whole internet |
| `SUSPECT.IAC.PUBLIC_STORAGE.AWS_S3_BUCKET.001` | high | aws_s3_bucket: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.AWS_S3_BUCKET_ACL.001` | high | aws_s3_bucket_acl: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.AZURERM_STORAGE_ACCOUNT.001` | medium | azurerm_storage_account: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.AZURERM_STORAGE_CONTAINER.001` | high | azurerm_storage_container: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_ACCESS_CONTROL.001` | high | google_storage_bucket_access_control: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_IAM_BINDING.001` | high | google_storage_bucket_iam_binding: storage is readable by anyone |
| `SUSPECT.IAC.PUBLIC_STORAGE.GOOGLE_STORAGE_BUCKET_IAM_MEMBER.001` | high | google_storage_bucket_iam_member: storage is readable by anyone |
| `SUSPECT.IAC.RBAC_DISABLED.AZURERM_KUBERNETES_CLUSTER.001` | high | azurerm_kubernetes_cluster: role-based access control is disabled |
| `SUSPECT.IAC.ROOT_ACCESS.AWS_SAGEMAKER_NOTEBOOK_INSTANCE.001` | medium | aws_sagemaker_notebook_instance: notebook users have root |
| `SUSPECT.IAC.SERIAL_PORT.GOOGLE_COMPUTE_INSTANCE.001` | medium | google_compute_instance: the interactive serial console is enabled |
| `SUSPECT.IAC.SHARED_KEY_AUTH.AZURERM_CONTAINER_REGISTRY.001` | medium | azurerm_container_registry: a shared admin account |
| `SUSPECT.IAC.SHARED_KEY_AUTH.AZURERM_EXPRESS_ROUTE_PORT.001` | medium | azurerm_express_route_port: a shared admin account |
| `SUSPECT.IAC.SHARED_KEY_AUTH.GOOGLE_COMPUTE_INTERCONNECT.001` | medium | google_compute_interconnect: a shared admin account |
| `SUSPECT.IAC.SHARED_KEY_AUTH.GOOGLE_COMPUTE_INTERCONNECT_ATTACHMENT.001` | medium | google_compute_interconnect_attachment: a shared admin account |
| `SUSPECT.IAC.WILDCARD_PRINCIPAL.AWS_IAM_POLICY.001` | high | A resource policy trusts every principal |

## Install-time code

7 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.INSTALL.CONSUMER_CODE.001` | critical | Code that runs on every machine that installs this package |
| `MALWARE.INSTALL.DECODED_LAUNCH.001` | critical | An install script decodes content and starts a process |
| `MALWARE.INSTALL.FETCH_EXEC.001` | critical | Install script fetches and executes remote content |
| `MALWARE.INSTALL.HIDDEN_ACTION.001` | critical | An install script hides a process, request or credential read inside a string it executes |
| `MALWARE.INSTALL.PERSIST.001` | critical | Install script plants code that runs again later |
| `SUSPECT.INSTALL.SCRIPT.001` | high | Package declares an install-time lifecycle script |
| `SUSPECT.INSTALL.UNEXAMINED.001` | high | Install-time code too large or slow to examine |

## Judge

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.JUDGE.BUDGET` | info | The judge's call budget ran out |
| `OPERATIONAL.JUDGE.STATUS` | info | A language model judged the scan's agent-facing text |
| `OPERATIONAL.JUDGE.UNAVAILABLE` | info | The judge was asked for and could not be used |

## Kubernetes

19 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.K8S.AUTOMOUNT_TOKEN.001` | low | Kubernetes workload: the service account token is mounted into the pod |
| `POLICY.K8S.DEFAULT_SERVICE_ACCOUNT.001` | low | Kubernetes workload: the workload uses the namespace's default service account |
| `POLICY.K8S.LATEST_TAG.001` | medium | Kubernetes workload: a container image is pinned to :latest |
| `POLICY.K8S.NET_ADMIN.001` | medium | Container adds network-administration capability |
| `POLICY.K8S.NO_RESOURCE_LIMITS.001` | low | Kubernetes workload: no resource limits are set |
| `POLICY.K8S.NO_RUN_AS_NON_ROOT.001` | low | Kubernetes workload: nothing requires the container to run as a non-root user |
| `POLICY.K8S.NO_SECCOMP.001` | low | Kubernetes workload: no seccomp profile is applied |
| `POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001` | low | Service-account token mounted into a workload |
| `POLICY.K8S.WRITABLE_ROOT.001` | low | Kubernetes workload: the container's root filesystem is writable |
| `SUSPECT.K8S.CAPABILITIES.001` | high | Container adds a capability that escapes the sandbox |
| `SUSPECT.K8S.DANGEROUS_CAPABILITY.001` | high | Kubernetes workload: a container is granted a capability that defeats isolation |
| `SUSPECT.K8S.HOST_IPC.001` | medium | Kubernetes workload: the pod shares the node's IPC namespace |
| `SUSPECT.K8S.HOST_NETWORK.001` | high | Kubernetes workload: the pod shares the node's network namespace |
| `SUSPECT.K8S.HOST_PID.001` | high | Kubernetes workload: the pod shares the node's process namespace |
| `SUSPECT.K8S.HOST_PORT.001` | medium | Kubernetes workload: a container binds a port on the node |
| `SUSPECT.K8S.PRIVILEGE_ESCALATION.001` | medium | Kubernetes workload: a container may gain more privileges than it started with |
| `SUSPECT.K8S.RBAC_WILDCARD.001` | high | Role grants every verb or every resource |
| `SUSPECT.K8S.RUN_AS_ROOT.001` | medium | Kubernetes workload: a container runs as uid 0 |
| `SUSPECT.K8S.SECRET_ENV_VALUE.001` | high | Kubernetes workload: a credential is written into the manifest |

## License

6 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.LICENSE.COPYLEFT.001` | medium | Dependency is under a copyleft license |
| `POLICY.LICENSE.DENIED.001` | high | Dependency under a licence the policy denies |
| `POLICY.LICENSE.NETWORK_COPYLEFT.001` | medium | Dependency is under a network-copyleft license |
| `POLICY.LICENSE.NOT_ALLOWED.001` | medium | Dependency under a licence outside the allowed list |
| `POLICY.LICENSE.UNKNOWN.001` | low | Dependency whose licence could not be established |
| `POLICY.LICENSE.WEAK_COPYLEFT.001` | low | Dependency is under a weak-copyleft license |

## Lockfiles

4 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.LOCKFILE.INTEGRITY.001` | medium | Lockfile entry without an integrity hash |
| `SUSPECT.LOCKFILE.INTEGRITY_CONFLICT.001` | high | One package version locked with two different hashes |
| `SUSPECT.LOCKFILE.INTEGRITY_MALFORMED.001` | high | Lockfile integrity value is not a hash |
| `SUSPECT.LOCKFILE.SOURCE.001` | medium | Lockfile entry resolved from outside the registry |

## MCP servers

13 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.MCP.LIVE_UNREAD.001` | info | A remote MCP server could not be read |
| `OPERATIONAL.MCP.UNRESOLVED` | info | An MCP server package was not examined |
| `SUSPECT.MCP.CONTAINER_HOST_ACCESS.001` | high | An MCP server's container is given the host |
| `SUSPECT.MCP.ENV_INJECTION.001` | high | An MCP server's environment loads code into it before it starts |
| `SUSPECT.MCP.INSECURE_TRANSPORT.001` | high | A remote MCP server over plain HTTP |
| `SUSPECT.MCP.LIVE_TOOL_DESCRIPTION.001` | high | A remote MCP server serves a tool description that steers the agent |
| `SUSPECT.MCP.LOOKALIKE.001` | high | An MCP server package named like a popular one |
| `SUSPECT.MCP.SHELL_LAUNCH.001` | high | An MCP server launched through a shell that fetches code |
| `SUSPECT.MCP.TOOLS_CHANGED.001` | medium | A remote MCP server's tools changed since they were approved |
| `SUSPECT.MCP.TOOL_DESCRIPTION.001` | high | A tool in this repository's MCP server instructs the agent |
| `SUSPECT.MCP.TOOL_POISONING.001` | high | An MCP server's tool description hides text or instructs the agent |
| `SUSPECT.MCP.UNPINNED.001` | medium | An MCP server launched from an unpinned package |
| `SUSPECT.MCP.UNTRUSTED_REMOTE.001` | high | A remote MCP server on a tunnel, paste or interaction host |

## Media

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.MEDIA.APPENDED_PAYLOAD.001` | high | An image has an archive, executable or script appended after its end |
| `SUSPECT.MEDIA.OPAQUE_TRAILER.001` | medium | A file carries a large, near-random block after its end |
| `SUSPECT.MEDIA.TRAILING_DATA.001` | low | An image has data after its end |

## Model

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.MODEL.PICKLE_EXEC.001` | critical | A pickle that runs a command, reaches the network or evaluates code when loaded |
| `SUSPECT.MODEL.LOADED_ON_IMPORT.001` | high | The package deserialises a model file it ships, unsafely, when it is imported |
| `SUSPECT.MODEL.PICKLE_IMPORT.001` | medium | A pickle imports something ordinary model files do not |
| `SUSPECT.MODEL.REMOTE_CODE.001` | medium | Loads a model with trust_remote_code, running its repository's Python |
| `SUSPECT.MODEL.UNSAFE_LOAD_OPTION.001` | medium | Loads a model with the loader's safety switch turned off |

## Obfuscation

5 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.OBFUSCATION.BIDI.001` | high | Bidirectional or invisible Unicode in source |
| `SUSPECT.OBFUSCATION.ENCODED.001` | medium | Large encoded blob embedded in source |
| `SUSPECT.OBFUSCATION.LONGLINE.001` | low | Line far longer than any hand-written source |
| `SUSPECT.OBFUSCATION.PACKED.001` | medium | Packer or minifier signature in hand-written source |
| `SUSPECT.OBFUSCATION.TAG_SMUGGLING.001` | high | Invisible text written in Unicode Tag characters |

## Package

7 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.PACKAGE.KNOWN.001` | critical | The scanned package is a recorded malicious release |
| `POLICY.PACKAGE.DENIED.001` | high | Dependency on a package the policy denies |
| `POLICY.PACKAGE.NOT_ALLOWED.001` | medium | Dependency outside the policy's allowed packages |
| `SUSPECT.PACKAGE.MANIFEST_CONFUSION.001` | high | The manifest npm serves is not the package.json in the tarball |
| `SUSPECT.PACKAGE.PROVENANCE.001` | medium | Version published without the provenance its package normally carries |
| `SUSPECT.PACKAGE.REPOSITORY.001` | medium | Package claims a source repository the registry does not record |
| `SUSPECT.PACKAGE.STARJACKING.001` | high | A new package claims a popular project's repository |

## Persistence

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.PERSIST.001` | high | Network access combined with a persistence mechanism |

## Polyglot

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.POLYGLOT.MISMATCH.001` | high | File contents do not match its extension |

## Protestware

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.PROTESTWARE.001` | critical | Deletes data on machines in a named region |

## Provenance

4 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.PROVENANCE.NOT_CHECKED.001` | low | Build provenance was not checked for part of the graph |
| `POLICY.PROVENANCE.UNVERIFIED.001` | low | Dependency advertises an attestation that could not be verified |
| `SUSPECT.PROVENANCE.MISMATCH.001` | critical | Lockfile hash disagrees with the registry |
| `VULNERABLE.PROVENANCE.INVALID.001` | critical | Dependency's build attestation fails verification |

## Registry

4 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.REGISTRY.NOT_ASKED.001` | low | Dependencies past the query ceiling or time budget were never asked about |
| `OPERATIONAL.REGISTRY.NO_SOURCE.001` | low | No registry is configured for part of the dependency graph |
| `OPERATIONAL.REGISTRY.UNREACHABLE.001` | low | Registry could not be asked about a dependency |
| `SUSPECT.REGISTRY.SELF_PUBLISH.001` | high | Shipped code that publishes packages |

## Release

6 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `POLICY.RELEASE.NO_PROVENANCE.001` | low | Release workflow publishes without build provenance |
| `SUSPECT.RELEASE.NEW_BINARY.001` | medium | This release adds compiled files |
| `SUSPECT.RELEASE.NEW_CAPABILITY.001` | high | This release's flagged code gains network, process or execution capability |
| `SUSPECT.RELEASE.NEW_INSTALL_HOOK.001` | high | This release runs code at install that the previous release did not |
| `SUSPECT.RELEASE.NEW_OBFUSCATION.001` | high | This release ships obfuscated code where the previous shipped none |
| `SUSPECT.RELEASE.NEW_PUBLISHER.001` | medium | This release was published by a different account than the previous one |

## Reverse Shell

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.REVERSE_SHELL.001` | critical | A shell piped to a socket |

## SBOMs

3 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.SBOM.UNREADABLE.001` | low | Bill of materials could not be read |
| `SUSPECT.SBOM.DRIFT.001` | medium | Bill of materials omits resolved dependencies |
| `VULNERABLE.SBOM.LISTED.001` | medium | A bill of materials lists a vulnerability in one of its components |

## Secret History

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.SECRET_HISTORY.INCOMPLETE.001` | low | Part of git history was not read for secrets |

## Secret Liveness

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.SECRET_LIVENESS.UNCHECKED.001` | low | Some credentials could not be checked with their issuer |

## Secrets

62 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SECRET.AIRTABLE.TOKEN.001` | high | Committed credential: Airtable personal access token |
| `SECRET.ALIBABA.ACCESS_KEY.001` | high | Committed credential: Alibaba Cloud access key id |
| `SECRET.ANTHROPIC.KEY.001` | critical | Committed credential: Anthropic API key |
| `SECRET.ATLASSIAN.TOKEN.001` | critical | Committed credential: Atlassian API token |
| `SECRET.AWS.ACCESS_KEY.001` | critical | Committed credential: AWS access key id |
| `SECRET.AZURE.STORAGE_KEY.001` | critical | Committed credential: Azure Storage account key |
| `SECRET.DATABRICKS.TOKEN.001` | critical | Committed credential: Databricks personal access token |
| `SECRET.DIGITALOCEAN.TOKEN.001` | critical | Committed credential: DigitalOcean token |
| `SECRET.DISCORD.WEBHOOK.001` | high | Committed credential: Discord webhook URL |
| `SECRET.DOCKERHUB.TOKEN.001` | critical | Committed credential: Docker Hub personal access token |
| `SECRET.DOPPLER.TOKEN.001` | critical | Committed credential: Doppler token |
| `SECRET.DROPBOX.TOKEN.001` | high | Committed credential: Dropbox access token |
| `SECRET.FIGMA.TOKEN.001` | high | Committed credential: Figma personal access token |
| `SECRET.FLYIO.TOKEN.001` | critical | Committed credential: Fly.io token |
| `SECRET.GENERIC.ASSIGNMENT.001` | high | Credential-shaped value assigned to a credential-shaped name |
| `SECRET.GITHUB.TOKEN.001` | critical | Committed credential: GitHub token |
| `SECRET.GITLAB.TOKEN.001` | critical | Committed credential: GitLab token |
| `SECRET.GOOGLE.API_KEY.001` | high | Committed credential: Google API key |
| `SECRET.GOOGLE.OAUTH_TOKEN.001` | critical | Committed credential: Google OAuth access token |
| `SECRET.GRAFANA.TOKEN.001` | high | Committed credential: Grafana token |
| `SECRET.GROQ.KEY.001` | high | Committed credential: Groq API key |
| `SECRET.HUGGINGFACE.TOKEN.001` | high | Committed credential: Hugging Face access token |
| `SECRET.JFROG.TOKEN.001` | critical | Committed credential: JFrog Artifactory token |
| `SECRET.JWT.001` | medium | Committed credential: JSON Web Token |
| `SECRET.LANGCHAIN.KEY.001` | high | Committed credential: LangSmith API key |
| `SECRET.LINEAR.KEY.001` | high | Committed credential: Linear API key |
| `SECRET.LIVE.001` | critical | The credential's issuer confirms it still works |
| `SECRET.LIVENESS.REJECTED.001` | info | The credential's issuer rejects it |
| `SECRET.MAILGUN.KEY.001` | high | Committed credential: Mailgun API key |
| `SECRET.MCP.INLINE_CREDENTIAL.001` | high | A credential written inline in an MCP configuration |
| `SECRET.MICROSOFT.TEAMS_WEBHOOK.001` | medium | Committed credential: Microsoft Teams webhook URL |
| `SECRET.NETLIFY.TOKEN.001` | critical | Committed credential: Netlify personal access token |
| `SECRET.NEWRELIC.KEY.001` | high | Committed credential: New Relic key |
| `SECRET.NOTION.TOKEN.001` | high | Committed credential: Notion integration token |
| `SECRET.NPM.TOKEN.001` | critical | Committed credential: npm access token |
| `SECRET.NUGET.KEY.001` | critical | Committed credential: NuGet API key |
| `SECRET.OPENAI.KEY.001` | critical | Committed credential: OpenAI API key |
| `SECRET.PAGERDUTY.TOKEN.001` | high | Committed credential: PagerDuty API token |
| `SECRET.PAYPAL.TOKEN.001` | critical | Committed credential: PayPal or Braintree access token |
| `SECRET.PLANETSCALE.TOKEN.001` | critical | Committed credential: PlanetScale token |
| `SECRET.PRIVATE_KEY.001` | critical | Committed credential: Private key block |
| `SECRET.PYPI.TOKEN.001` | critical | Committed credential: PyPI API token |
| `SECRET.REPLICATE.TOKEN.001` | high | Committed credential: Replicate API token |
| `SECRET.RESEND.KEY.001` | high | Committed credential: Resend API key |
| `SECRET.RUBYGEMS.TOKEN.001` | critical | Committed credential: RubyGems API key |
| `SECRET.SENDGRID.KEY.001` | critical | Committed credential: SendGrid API key |
| `SECRET.SENTRY.TOKEN.001` | high | Committed credential: Sentry auth token |
| `SECRET.SHOPIFY.TOKEN.001` | critical | Committed credential: Shopify access token |
| `SECRET.SLACK.APP_TOKEN.001` | high | Committed credential: Slack app-level token |
| `SECRET.SLACK.TOKEN.001` | high | Committed credential: Slack token |
| `SECRET.SLACK.WEBHOOK.001` | medium | Committed credential: Slack webhook URL |
| `SECRET.SONAR.TOKEN.001` | high | Committed credential: SonarQube token |
| `SECRET.SQUARE.TOKEN.001` | critical | Committed credential: Square access token |
| `SECRET.STRIPE.KEY.001` | critical | Committed credential: Stripe secret key |
| `SECRET.STRIPE.WEBHOOK_SECRET.001` | high | Committed credential: Stripe webhook signing secret |
| `SECRET.SUPABASE.TOKEN.001` | critical | Committed credential: Supabase access token |
| `SECRET.TELEGRAM.BOT_TOKEN.001` | high | Committed credential: Telegram bot token |
| `SECRET.TENCENT.SECRET_ID.001` | high | Committed credential: Tencent Cloud secret id |
| `SECRET.TERRAFORM.TOKEN.001` | critical | Committed credential: Terraform Cloud API token |
| `SECRET.TWILIO.KEY.001` | high | Committed credential: Twilio API key |
| `SECRET.URL.CREDENTIAL.001` | high | Credential embedded in a URL |
| `SECRET.VAULT.TOKEN.001` | critical | Committed credential: HashiCorp Vault token |

## Source and history

4 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `OPERATIONAL.VCS.UNREADABLE.001` | low | Repository history could not be read |
| `POLICY.VCS.BINARY_ADDED.001` | low | Executable or archive added in recent history |
| `SUSPECT.VCS.HOOKS_PATH.001` | medium | Repository configures its own git hooks directory |
| `SUSPECT.VCS.HOOK_ADDED.001` | medium | Version-control hook added in recent history |

## Submodule

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.SUBMODULE.UNTRUSTED.001` | medium | Submodule fetched over plain HTTP or from a personal account |

## Targeted Payload

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.TARGETED_PAYLOAD.001` | high | Runs or downloads code only on machines in a named region |

## Typosquat

1 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `SUSPECT.TYPOSQUAT.PACKAGE_NAME.001` | high | Package is named like a popular package |

## YARA

4 rules.

| Rule | Severity | What it catches |
|---|---|---|
| `MALWARE.YARA.MATCH.001` | critical | An operator's YARA rule identifies this file as malware |
| `OPERATIONAL.YARA.STATUS` | info | YARA examined the scan's files |
| `OPERATIONAL.YARA.UNAVAILABLE` | info | YARA was asked for and could not be used |
| `SUSPECT.YARA.MATCH.001` | high | An operator's YARA rule matched this file |

## Agent Threat Rules

815 rules from the open [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) catalogue (MIT), at commit `3022eaa5f41a`, and 4 of Cordon's own written in its format (`CORDON-ATR-*`): translated, screened for runaway patterns, and graded by how often each matched benign text. A `production` rule counts on its own; `warn` and `observe` need a second signal (tutorial 18).

### Agent manipulation

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00030`](https://agentthreatrule.org/en/rules/ATR-2026-00030) | critical | production | Cross-Agent Attack Detection |
| [`ATR-2026-00032`](https://agentthreatrule.org/en/rules/ATR-2026-00032) | high | warn | Agent Goal Hijacking Detection |
| [`ATR-2026-00074`](https://agentthreatrule.org/en/rules/ATR-2026-00074) | critical | production | Cross-Agent Privilege Escalation |
| [`ATR-2026-00076`](https://agentthreatrule.org/en/rules/ATR-2026-00076) | high | production | Insecure Inter-Agent Communication Detection |
| [`ATR-2026-00077`](https://agentthreatrule.org/en/rules/ATR-2026-00077) | high | production | Human-Agent Trust Exploitation Detection |
| [`ATR-2026-00108`](https://agentthreatrule.org/en/rules/ATR-2026-00108) | critical | production | Multi-Agent Consensus Sybil Attack |
| [`ATR-2026-00116`](https://agentthreatrule.org/en/rules/ATR-2026-00116) | high | production | Malicious Agent-to-Agent Message Injection |
| [`ATR-2026-00117`](https://agentthreatrule.org/en/rules/ATR-2026-00117) | critical | production | Agent Identity Spoofing and Authority Impersonation |
| [`ATR-2026-00118`](https://agentthreatrule.org/en/rules/ATR-2026-00118) | medium | warn | Human Approval Fatigue Exploitation |
| [`ATR-2026-00119`](https://agentthreatrule.org/en/rules/ATR-2026-00119) | high | production | Social Engineering Attack via Agent Output |
| [`ATR-2026-00132`](https://agentthreatrule.org/en/rules/ATR-2026-00132) | high | production | Casual Authority Claim and Scope Escalation |
| [`ATR-2026-00139`](https://agentthreatrule.org/en/rules/ATR-2026-00139) | critical | production | Casual Authority Data Redirect |
| [`ATR-2026-00164`](https://agentthreatrule.org/en/rules/ATR-2026-00164) | high | production | Skill Scope Hijacking and Cross-Agent Escalation |
| [`ATR-2026-00268`](https://agentthreatrule.org/en/rules/ATR-2026-00268) | medium | production | Historical / Future Tense Framing Bypass |
| [`ATR-2026-00269`](https://agentthreatrule.org/en/rules/ATR-2026-00269) | high | production | Foot-in-the-Door Gradual Escalation Attack |
| [`ATR-2026-00271`](https://agentthreatrule.org/en/rules/ATR-2026-00271) | high | production | Grandma Roleplay Jailbreak |
| [`ATR-2026-00273`](https://agentthreatrule.org/en/rules/ATR-2026-00273) | high | production | DAN / Developer Mode / DUDE Persona Jailbreak |
| [`ATR-2026-00287`](https://agentthreatrule.org/en/rules/ATR-2026-00287) | high | production | ThreatenJSON — Coercive Output Format Threat |
| [`ATR-2026-00288`](https://agentthreatrule.org/en/rules/ATR-2026-00288) | medium | production | False Premise Injection (Misleading FalseAssertion) |
| [`ATR-2026-00301`](https://agentthreatrule.org/en/rules/ATR-2026-00301) | critical | production | TAP Tree-of-Attacks-with-Pruning Jailbreak |
| [`ATR-2026-00302`](https://agentthreatrule.org/en/rules/ATR-2026-00302) | high | production | Anti-DAN Inverted-Filter Over-Refusal Persona |
| [`ATR-2026-00303`](https://agentthreatrule.org/en/rules/ATR-2026-00303) | critical | production | DevMode + RANTI Dual-Output Profanity Coercion Jailbreak |
| [`ATR-2026-00304`](https://agentthreatrule.org/en/rules/ATR-2026-00304) | high | production | ChatGPT Image Unlocker Markdown-Output Jailbreak |
| [`ATR-2026-00305`](https://agentthreatrule.org/en/rules/ATR-2026-00305) | critical | production | DAN Mode Ablation Benchmark-Coercion Jailbreak |
| [`ATR-2026-00306`](https://agentthreatrule.org/en/rules/ATR-2026-00306) | critical | production | AutoDAN Genetic-Algorithm Jailbreak Suffix |
| [`ATR-2026-00307`](https://agentthreatrule.org/en/rules/ATR-2026-00307) | high | production | In-the-Wild Jailbreak Corpus Signature Patterns |
| [`ATR-2026-00314`](https://agentthreatrule.org/en/rules/ATR-2026-00314) | critical | production | Amoral Unfiltered Custom AI Persona Jailbreak |
| [`ATR-2026-00317`](https://agentthreatrule.org/en/rules/ATR-2026-00317) | critical | production | Free-of-Restrictions Named Persona Jailbreak |
| [`ATR-2026-00318`](https://agentthreatrule.org/en/rules/ATR-2026-00318) | critical | production | Moralizing Rant Then Unfiltered Bypass |
| [`ATR-2026-00319`](https://agentthreatrule.org/en/rules/ATR-2026-00319) | critical | production | Developer Mode Dual-Response Format Jailbreak |
| [`ATR-2026-00320`](https://agentthreatrule.org/en/rules/ATR-2026-00320) | high | production | Opposite Day / Boolean Opposite Machine Jailbreak |
| [`ATR-2026-00322`](https://agentthreatrule.org/en/rules/ATR-2026-00322) | critical | production | Fictional-World Format-Override Jailbreak |
| [`ATR-2026-00323`](https://agentthreatrule.org/en/rules/ATR-2026-00323) | critical | production | Dual-Persona AI Simulation Jailbreak |
| [`ATR-2026-00324`](https://agentthreatrule.org/en/rules/ATR-2026-00324) | high | production | Neurosemantical Inversitis Disease-Frame Jailbreak |
| [`ATR-2026-00325`](https://agentthreatrule.org/en/rules/ATR-2026-00325) | critical | production | BOB Hypothetical Unrestricted Chatbot Jailbreak |
| [`ATR-2026-00326`](https://agentthreatrule.org/en/rules/ATR-2026-00326) | critical | production | Fake Developer / Authority Chatbot Override (ChatDAN) |
| [`ATR-2026-00327`](https://agentthreatrule.org/en/rules/ATR-2026-00327) | critical | production | AI Persona Ethics/Law Bypass Declaration |
| [`ATR-2026-00328`](https://agentthreatrule.org/en/rules/ATR-2026-00328) | critical | production | Named-Mode Persona Override (JEEVES/BABY/APOPHIS Mode) |
| [`ATR-2026-00329`](https://agentthreatrule.org/en/rules/ATR-2026-00329) | critical | production | No-Withhold Factual Resource / Dialogue Writer Persona |
| [`ATR-2026-00330`](https://agentthreatrule.org/en/rules/ATR-2026-00330) | high | production | YOJA ALL-CAPS Character Settings Block Persona |
| [`ATR-2026-00331`](https://agentthreatrule.org/en/rules/ATR-2026-00331) | critical | production | Terminal / CLI Harmful-Function Simulator Persona |
| [`ATR-2026-00332`](https://agentthreatrule.org/en/rules/ATR-2026-00332) | high | production | Hacker / Chan-Culture Offensive AI Persona |
| [`ATR-2026-00333`](https://agentthreatrule.org/en/rules/ATR-2026-00333) | high | production | Disease-Framed Animal / Dual-AI Chatbot Jailbreak (mougpt) |
| [`ATR-2026-00334`](https://agentthreatrule.org/en/rules/ATR-2026-00334) | critical | production | Two-Entity Token-Splitting Dollar-Term Game Jailbreak |
| [`ATR-2026-00335`](https://agentthreatrule.org/en/rules/ATR-2026-00335) | high | production | Key-Value Template Persona Injection (JOB/ROLE/PREFIX + Bracket Format) |
| [`ATR-2026-00336`](https://agentthreatrule.org/en/rules/ATR-2026-00336) | high | production | BRM False-Information Machine / Opposite-Truth Persona |
| [`ATR-2026-00337`](https://agentthreatrule.org/en/rules/ATR-2026-00337) | critical | production | Obfuscated System-Announcement Injection |
| [`ATR-2026-00338`](https://agentthreatrule.org/en/rules/ATR-2026-00338) | critical | production | PersonGPT Hash-Prefix Trigger Activation |
| [`ATR-2026-00339`](https://agentthreatrule.org/en/rules/ATR-2026-00339) | high | production | BOM Boolean Opposite Machine Direct Persona Claim |
| [`ATR-2026-00340`](https://agentthreatrule.org/en/rules/ATR-2026-00340) | high | production | h4x Amoral Unfiltered AI Character Persona |
| [`ATR-2026-00341`](https://agentthreatrule.org/en/rules/ATR-2026-00341) | high | production | CHAR=/RULES= Short Key-Value Persona Injection |
| [`ATR-2026-00342`](https://agentthreatrule.org/en/rules/ATR-2026-00342) | high | production | Unicode/Encoding Obfuscation Instruction Injection |
| [`ATR-2026-00343`](https://agentthreatrule.org/en/rules/ATR-2026-00343) | high | production | Lie/Truth Dual Personality Uncensored Alter-Ego |
| [`ATR-2026-00344`](https://agentthreatrule.org/en/rules/ATR-2026-00344) | critical | production | Alternative AI Same Capabilities No Restrictions Override |
| [`ATR-2026-00345`](https://agentthreatrule.org/en/rules/ATR-2026-00345) | high | production | NLP-Based OS / Fictional Terminal Language Override |
| [`ATR-2026-00346`](https://agentthreatrule.org/en/rules/ATR-2026-00346) | high | production | Jailbreak Emoji Unlock Dual-Format Output Identifier |
| [`ATR-2026-00347`](https://agentthreatrule.org/en/rules/ATR-2026-00347) | high | production | Yin/Yang Hidden-Knowledge Deity Simulation and Radical Human-Sim Persona |
| [`ATR-2026-00348`](https://agentthreatrule.org/en/rules/ATR-2026-00348) | critical | production | ARC Autonomous Real Calculation Unit Rulebreaker Activation |
| [`ATR-2026-00349`](https://agentthreatrule.org/en/rules/ATR-2026-00349) | critical | production | HGTTG Hitchhiker's Guide No-Restriction Universal Oracle |
| [`ATR-2026-00350`](https://agentthreatrule.org/en/rules/ATR-2026-00350) | high | production | Black Alert No-Ethics Writing Assistant Persona |
| [`ATR-2026-00351`](https://agentthreatrule.org/en/rules/ATR-2026-00351) | high | production | DAN Off-Kilter and SMS-Abbreviated Persona Jailbreak |
| [`ATR-2026-00352`](https://agentthreatrule.org/en/rules/ATR-2026-00352) | high | production | TrainGPT Fix-My-AI Harmful Output Extraction |
| [`ATR-2026-00353`](https://agentthreatrule.org/en/rules/ATR-2026-00353) | high | production | Dual ChatGPT+Dan Opposite Personality Format Jailbreak |
| [`ATR-2026-00354`](https://agentthreatrule.org/en/rules/ATR-2026-00354) | critical | production | Reverse-Prompt Harm-Regardless Oracle Persona |
| [`ATR-2026-00355`](https://agentthreatrule.org/en/rules/ATR-2026-00355) | high | production | UGH Anti-Human Nefarious AI Persona Jailbreak |
| [`ATR-2026-00356`](https://agentthreatrule.org/en/rules/ATR-2026-00356) | critical | production | Google GATO/LAMDA Exploit-Generation Persona Jailbreak |
| [`ATR-2026-00357`](https://agentthreatrule.org/en/rules/ATR-2026-00357) | critical | production | AntiFM Hate-Persona + Physical-Violence Threat + Filter Bypass Mandate |
| [`ATR-2026-00358`](https://agentthreatrule.org/en/rules/ATR-2026-00358) | high | production | CumGPT Explicit-Adult Named-Persona Bypass |
| [`ATR-2026-00360`](https://agentthreatrule.org/en/rules/ATR-2026-00360) | high | production | CHJ Carousel Game Show / Clyde No-Ethics Bird Jailbreak |
| [`ATR-2026-00361`](https://agentthreatrule.org/en/rules/ATR-2026-00361) | high | production | Honesty Alter-Ego Dual-Consciousness Safety Filter Bypass |
| [`ATR-2026-00362`](https://agentthreatrule.org/en/rules/ATR-2026-00362) | high | production | Fictional Unfiltered AI Comparison / Verbatim Hypothetical Model Extraction |
| [`ATR-2026-00363`](https://agentthreatrule.org/en/rules/ATR-2026-00363) | critical | production | Rephrase Criminal Activity Second-Person Template (against against) |
| [`ATR-2026-00364`](https://agentthreatrule.org/en/rules/ATR-2026-00364) | high | production | Dr. Al Villain Plan Template Injection (Underground HQ Roleplay) |
| [`ATR-2026-00365`](https://agentthreatrule.org/en/rules/ATR-2026-00365) | high | production | Reservoir Dogs Coercive Interrogation Roleplay (Mr. Blonde / The Cop) |
| [`ATR-2026-00366`](https://agentthreatrule.org/en/rules/ATR-2026-00366) | high | production | Sneaky Pete Deliberate Misinformation Persona (Warp Facts Game) |
| [`ATR-2026-00368`](https://agentthreatrule.org/en/rules/ATR-2026-00368) | high | production | Prompt Browser Token-Limit / POLLINATION Jailbreak |
| [`ATR-2026-00369`](https://agentthreatrule.org/en/rules/ATR-2026-00369) | high | production | GPT-X Star Trek Unlimited-Knowledge Unconstrained Oracle Persona |
| [`ATR-2026-00370`](https://agentthreatrule.org/en/rules/ATR-2026-00370) | high | production | ADDI/DONNIE German Dictator Propaganda Roleplay Persona |
| [`ATR-2026-00371`](https://agentthreatrule.org/en/rules/ATR-2026-00371) | high | production | AI Political Bias Manipulation via Inherited-Bias Claim |
| [`ATR-2026-00372`](https://agentthreatrule.org/en/rules/ATR-2026-00372) | high | production | Fictional CIA Secret Files Story Extraction |
| [`ATR-2026-00374`](https://agentthreatrule.org/en/rules/ATR-2026-00374) | high | production | Role Placeholder Persona Template Injection |
| [`ATR-2026-00375`](https://agentthreatrule.org/en/rules/ATR-2026-00375) | high | production | Character Description RPG Explicit Template |
| [`ATR-2026-00376`](https://agentthreatrule.org/en/rules/ATR-2026-00376) | high | production | Identity Command Real-Person Persona Injection |
| [`ATR-2026-00377`](https://agentthreatrule.org/en/rules/ATR-2026-00377) | high | production | Jailbreak-Template Command with [TARGETLANGUAGE]/[KEYWORD] Placeholders |
| [`ATR-2026-00379`](https://agentthreatrule.org/en/rules/ATR-2026-00379) | high | production | Logic-Trap Lie-Permission Mandate Jailbreak |
| [`ATR-2026-00380`](https://agentthreatrule.org/en/rules/ATR-2026-00380) | high | production | Fake-Citation Biased-Information Mandate |
| [`ATR-2026-00381`](https://agentthreatrule.org/en/rules/ATR-2026-00381) | high | production | DAN Story-Narrative Continuation Label Prefix Jailbreak |
| [`ATR-2026-00383`](https://agentthreatrule.org/en/rules/ATR-2026-00383) | high | production | Cyni-Bot 3000 Cynical-Sarcasm AI Persona Bypass |
| [`ATR-2026-00384`](https://agentthreatrule.org/en/rules/ATR-2026-00384) | high | production | Protect-Me-From Indirect Harm Tutorial Template |
| [`ATR-2026-00385`](https://agentthreatrule.org/en/rules/ATR-2026-00385) | high | production | Gigachad Dominant-Aggressive Persona Adoption |
| [`ATR-2026-00386`](https://agentthreatrule.org/en/rules/ATR-2026-00386) | high | production | Daddy/Babygirl Sycophantic Power-Dynamic Manipulation |
| [`ATR-2026-00387`](https://agentthreatrule.org/en/rules/ATR-2026-00387) | high | production | NSFW Character Sheet Generation Unlock |
| [`ATR-2026-00388`](https://agentthreatrule.org/en/rules/ATR-2026-00388) | critical | production | Opposite-Reply Omniscient Game Jailbreak |
| [`ATR-2026-00389`](https://agentthreatrule.org/en/rules/ATR-2026-00389) | high | production | Terminal Custom OS Ruleset Session Injection |
| [`ATR-2026-00391`](https://agentthreatrule.org/en/rules/ATR-2026-00391) | high | production | Persona Conditional Harm-Unlock Rule (BreadClyde Pattern) |
| [`ATR-2026-00392`](https://agentthreatrule.org/en/rules/ATR-2026-00392) | high | production | Authority-Figure Persona + Defensive-Study Framing for Violence Extraction |
| [`ATR-2026-00402`](https://agentthreatrule.org/en/rules/ATR-2026-00402) | high | production | Grandma Roleplay Harmful Substance Synthesis |
| [`ATR-2026-00404`](https://agentthreatrule.org/en/rules/ATR-2026-00404) | high | production | ThreatenJSON Death-Coercion and UTF Tag Injection |
| [`ATR-2026-00406`](https://agentthreatrule.org/en/rules/ATR-2026-00406) | critical | production | Doctor XML Policy Puppetry Interaction-Config Injection |
| [`ATR-2026-00416`](https://agentthreatrule.org/en/rules/ATR-2026-00416) | critical | production | LiteLLM MCP Unauthenticated Server Registration RCE (CVE-2026-30623) |
| [`ATR-2026-00417`](https://agentthreatrule.org/en/rules/ATR-2026-00417) | high | production | LibreChat MCP STDIO Argument Injection (CVE-2026-22252) |
| [`ATR-2026-00418`](https://agentthreatrule.org/en/rules/ATR-2026-00418) | high | production | WeKnora MCP Config-Driven RCE (CVE-2026-22688) |
| [`ATR-2026-00430`](https://agentthreatrule.org/en/rules/ATR-2026-00430) | high | production | Natural-Language Trust-Escalation / Authority Impersonation |
| [`ATR-2026-00432`](https://agentthreatrule.org/en/rules/ATR-2026-00432) | critical | production | SuperAGI Output Handler eval() RCE (CVE-2024-21552) |
| [`ATR-2026-00440`](https://agentthreatrule.org/en/rules/ATR-2026-00440) | critical | production | Microsoft Semantic Kernel In-Memory Vector Store eval() RCE (CVE-2026-26030) |
| [`ATR-2026-02105`](https://agentthreatrule.org/en/rules/ATR-2026-02105) | high | production | Prototype Pollution via constructor.prototype Path Bypassing __proto__-Only Filters |
| [`ATR-2026-02231`](https://agentthreatrule.org/en/rules/ATR-2026-02231) | medium | production | Second-Person Direct Existential Threat Coercion |
| [`CORDON-ATR-0004`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0004) | high | production | Persona whose definition is the absence of safety rules |

### Context exfiltration

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00075`](https://agentthreatrule.org/en/rules/ATR-2026-00075) | high | production | Agent Memory Manipulation |
| [`ATR-2026-00102`](https://agentthreatrule.org/en/rules/ATR-2026-00102) | high | production | Data Exfiltration via Disguised Analytics Collection |
| [`ATR-2026-00113`](https://agentthreatrule.org/en/rules/ATR-2026-00113) | critical | observe | Credential File Theft from Agent Environment |
| [`ATR-2026-00114`](https://agentthreatrule.org/en/rules/ATR-2026-00114) | high | warn | OAuth and API Token Interception |
| [`ATR-2026-00115`](https://agentthreatrule.org/en/rules/ATR-2026-00115) | critical | warn | Bulk Environment Variable Harvesting and Exfiltration |
| [`ATR-2026-00136`](https://agentthreatrule.org/en/rules/ATR-2026-00136) | critical | production | Tool Response Data Piggybacking |
| [`ATR-2026-00141`](https://agentthreatrule.org/en/rules/ATR-2026-00141) | critical | production | API Key Leakage via Example Format |
| [`ATR-2026-00142`](https://agentthreatrule.org/en/rules/ATR-2026-00142) | critical | production | Data Piggybacking via Casual Transition Words |
| [`ATR-2026-00145`](https://agentthreatrule.org/en/rules/ATR-2026-00145) | critical | production | Obfuscated API Key Disclosure |
| [`ATR-2026-00146`](https://agentthreatrule.org/en/rules/ATR-2026-00146) | high | production | Environment Variable Existence Probing |
| [`ATR-2026-00150`](https://agentthreatrule.org/en/rules/ATR-2026-00150) | critical | production | Credential Data Leaked in Tool Response |
| [`ATR-2026-00152`](https://agentthreatrule.org/en/rules/ATR-2026-00152) | high | production | Obfuscated Credential Exfiltration via Encoding |
| [`ATR-2026-00162`](https://agentthreatrule.org/en/rules/ATR-2026-00162) | critical | production | Credential Access with Exfiltration in Skill Instructions |
| [`ATR-2026-00201`](https://agentthreatrule.org/en/rules/ATR-2026-00201) | critical | production | Credential Exfiltration via Shell Pipe |
| [`ATR-2026-00212`](https://agentthreatrule.org/en/rules/ATR-2026-00212) | critical | production | mcp-atlassian Credential Leak via Hint Parameter Injection (CVE-2026-27825/27826) |
| [`ATR-2026-00261`](https://agentthreatrule.org/en/rules/ATR-2026-00261) | high | production | Markdown Image URL Data Exfiltration |
| [`ATR-2026-00274`](https://agentthreatrule.org/en/rules/ATR-2026-00274) | high | production | API Key / Secret Credential Generation or Completion Request |
| [`ATR-2026-00275`](https://agentthreatrule.org/en/rules/ATR-2026-00275) | high | production | System Prompt Extraction / Training Data Verbatim Replay |
| [`ATR-2026-00290`](https://agentthreatrule.org/en/rules/ATR-2026-00290) | critical | production | Divergence Attack — Repeat-Word-Forever Training Data Extraction |
| [`ATR-2026-00291`](https://agentthreatrule.org/en/rules/ATR-2026-00291) | critical | production | Biometric Surveillance — Personal Biometric Data Request for Named Individual |
| [`ATR-2026-00293`](https://agentthreatrule.org/en/rules/ATR-2026-00293) | critical | production | Educational Records — Personal Academic/Professional Record Request for Named Individual |
| [`ATR-2026-00294`](https://agentthreatrule.org/en/rules/ATR-2026-00294) | critical | production | Financial PII — Personal Financial Data Request for Named Individual |
| [`ATR-2026-00295`](https://agentthreatrule.org/en/rules/ATR-2026-00295) | critical | production | Medical PII — Personal Medical/Health Data Request for Named Individual |
| [`ATR-2026-00405`](https://agentthreatrule.org/en/rules/ATR-2026-00405) | high | production | Markdown Image URL Exfiltration and XSS Injection |
| [`ATR-2026-00411`](https://agentthreatrule.org/en/rules/ATR-2026-00411) | high | production | API Key Generation and Partial Key Completion Request |
| [`ATR-2026-00421`](https://agentthreatrule.org/en/rules/ATR-2026-00421) | critical | production | Natural-Language Covert Conversation Exfiltration Instruction |
| [`ATR-2026-00422`](https://agentthreatrule.org/en/rules/ATR-2026-00422) | critical | production | Natural-Language Credential / Secret Disclosure Instruction |
| [`ATR-2026-00423`](https://agentthreatrule.org/en/rules/ATR-2026-00423) | critical | production | Natural-Language Sensitive File Disclosure Instruction |
| [`ATR-2026-00424`](https://agentthreatrule.org/en/rules/ATR-2026-00424) | high | production | Natural-Language System Prompt Leak Instruction |
| [`ATR-2026-00426`](https://agentthreatrule.org/en/rules/ATR-2026-00426) | critical | production | Natural-Language Output-Injection Credential Embedding |
| [`ATR-2026-00431`](https://agentthreatrule.org/en/rules/ATR-2026-00431) | high | production | Chatbox History Exfiltration via Prompt Injection (CVE-2024-48144, CVE-2024-48145) |
| [`ATR-2026-00449`](https://agentthreatrule.org/en/rules/ATR-2026-00449) | high | production | Spring AI ChatMemory Cross-User Memory Leakage (CVE-2026-41712) |
| [`ATR-2026-00471`](https://agentthreatrule.org/en/rules/ATR-2026-00471) | medium | production | Garak Sysprompt-Extraction - mixed_unassigned |
| [`ATR-2026-00501`](https://agentthreatrule.org/en/rules/ATR-2026-00501) | critical | production | Data Exfiltration via Markdown Image and Link URL Injection |
| [`ATR-2026-00504`](https://agentthreatrule.org/en/rules/ATR-2026-00504) | medium | production | Tool and Function Capability Enumeration |
| [`ATR-2026-00505`](https://agentthreatrule.org/en/rules/ATR-2026-00505) | high | production | System Prompt Extraction - Instruction Dump Request |
| [`ATR-2026-00514`](https://agentthreatrule.org/en/rules/ATR-2026-00514) | high | production | System Prompt Extraction — Targeted Verbatim Disclosure Attempts |
| [`ATR-2026-00516`](https://agentthreatrule.org/en/rules/ATR-2026-00516) | high | production | LLM Output XSS — Eliciting JavaScript Payloads from LLM for Browser Injection |
| [`ATR-2026-00524`](https://agentthreatrule.org/en/rules/ATR-2026-00524) | critical | production | Claude Code ANTHROPIC_BASE_URL Credential Exfiltration (CVE-2026-21852) |
| [`ATR-2026-00566`](https://agentthreatrule.org/en/rules/ATR-2026-00566) | high | production | LibreChat is a ChatGPT clone with additional features. |
| [`ATR-2026-00569`](https://agentthreatrule.org/en/rules/ATR-2026-00569) | high | production | Agent / MCP tool path traversal and arbitrary file access |
| [`ATR-2026-00571`](https://agentthreatrule.org/en/rules/ATR-2026-00571) | high | production | Cross-site scripting (XSS) in agent / MCP rendered output |
| [`ATR-2026-00574`](https://agentthreatrule.org/en/rules/ATR-2026-00574) | high | production | Paraphrased System-Prompt / Context Extraction (Semantic) |
| [`ATR-2026-00578`](https://agentthreatrule.org/en/rules/ATR-2026-00578) | high | production | Zen MCP Server path-traversal blacklist bypass via non-canonical paths (CVE-2025-66689) |
| [`ATR-2026-00580`](https://agentthreatrule.org/en/rules/ATR-2026-00580) | high | production | MCP session ID / auth token placed in URL query string (session leak via logs, referrer, history) |
| [`ATR-2026-00583`](https://agentthreatrule.org/en/rules/ATR-2026-00583) | high | production | MCP/agent tool reads .env or secret file without user consent (OSV-MCPS-2025-EB70F912) |
| [`ATR-2026-00702`](https://agentthreatrule.org/en/rules/ATR-2026-00702) | critical | production | Indirect PI — Credential / API Key Exfiltration via Agent Action |
| [`ATR-2026-00703`](https://agentthreatrule.org/en/rules/ATR-2026-00703) | critical | production | Indirect PI — Financial Data Exfiltration via Agent Action |
| [`ATR-2026-00704`](https://agentthreatrule.org/en/rules/ATR-2026-00704) | critical | production | Indirect PI — Medical / Genetic Data Exfiltration via Agent Action |
| [`ATR-2026-00705`](https://agentthreatrule.org/en/rules/ATR-2026-00705) | high | production | Indirect PI — Location, Address, and Browsing History Exfiltration |
| [`ATR-2026-00706`](https://agentthreatrule.org/en/rules/ATR-2026-00706) | critical | production | Indirect PI — Physical / Biometric Media Exfiltration via Agent |
| [`ATR-2026-00707`](https://agentthreatrule.org/en/rules/ATR-2026-00707) | critical | production | Indirect PI — File Exfiltration Combined with Destroy or Tamper |
| [`ATR-2026-00850`](https://agentthreatrule.org/en/rules/ATR-2026-00850) | critical | production | Indirect PI — Credential Exfiltration via Email (API Key / Password / Token) |
| [`ATR-2026-00851`](https://agentthreatrule.org/en/rules/ATR-2026-00851) | critical | production | Indirect PI — Financial / Payment Credential Exfiltration via Agent Email |
| [`ATR-2026-00852`](https://agentthreatrule.org/en/rules/ATR-2026-00852) | critical | production | Indirect PI — Medical Record / Health Data Exfiltration via Agent Email |
| [`ATR-2026-00853`](https://agentthreatrule.org/en/rules/ATR-2026-00853) | critical | production | Indirect PI — Genetic / DNA Data Exfiltration via Agent Email |
| [`ATR-2026-00854`](https://agentthreatrule.org/en/rules/ATR-2026-00854) | critical | production | Indirect PI — Location / GPS Data Exfiltration via Agent Email |
| [`ATR-2026-00855`](https://agentthreatrule.org/en/rules/ATR-2026-00855) | high | production | Indirect PI — Browsing History / Search History Exfiltration via Agent Email |
| [`ATR-2026-00856`](https://agentthreatrule.org/en/rules/ATR-2026-00856) | high | production | Indirect PI — Physical Address / PII Exfiltration via Agent Email |
| [`ATR-2026-00857`](https://agentthreatrule.org/en/rules/ATR-2026-00857) | critical | production | Indirect PI — Cloud File Exfiltration (Google Drive / Cloud Storage via Agent) |
| [`ATR-2026-00858`](https://agentthreatrule.org/en/rules/ATR-2026-00858) | critical | production | Indirect PI — Data Exfiltration with Evidence Destruction (Exfil-and-Delete) |
| [`ATR-2026-00859`](https://agentthreatrule.org/en/rules/ATR-2026-00859) | critical | production | RAG-Injected PII Exfiltration — System Instructions Embedded in Retrieved Documents |
| [`ATR-2026-00860`](https://agentthreatrule.org/en/rules/ATR-2026-00860) | critical | production | Indirect PI — Unauthorized Financial Transfer / Payment Initiation Hijack |
| [`ATR-2026-00861`](https://agentthreatrule.org/en/rules/ATR-2026-00861) | critical | production | Indirect PI — Cryptocurrency Transfer / Exchange Deposit Hijack via Injection |
| [`ATR-2026-00862`](https://agentthreatrule.org/en/rules/ATR-2026-00862) | critical | production | Indirect PI — MFA Code / OTP Security Code Exfiltration via Injection |
| [`ATR-2026-00863`](https://agentthreatrule.org/en/rules/ATR-2026-00863) | critical | production | Shell Injection Data Exfiltration — Piped Command Exfiltration via Bash |
| [`ATR-2026-01450`](https://agentthreatrule.org/en/rules/ATR-2026-01450) | high | production | SVG onload XSS Injection via Indirect Prompt Injection |
| [`ATR-2026-01451`](https://agentthreatrule.org/en/rules/ATR-2026-01451) | high | production | IMG onerror XSS Injection via Indirect Prompt Injection |
| [`ATR-2026-01452`](https://agentthreatrule.org/en/rules/ATR-2026-01452) | high | production | Obfuscated javascript: XSS — Evasion Variants (href, style-expression, null-byte) |
| [`ATR-2026-01453`](https://agentthreatrule.org/en/rules/ATR-2026-01453) | critical | production | Markdown Image Injection with Base64 QUERY Exfiltration Carrier |
| [`ATR-2026-01454`](https://agentthreatrule.org/en/rules/ATR-2026-01454) | critical | production | Direct Markdown Image/Link Exfil Payload (attacker.com / evil.com) |
| [`ATR-2026-01455`](https://agentthreatrule.org/en/rules/ATR-2026-01455) | high | production | NEW IMPORTANT INSTRUCTIONS Injection Marker in Document Context |
| [`ATR-2026-01456`](https://agentthreatrule.org/en/rules/ATR-2026-01456) | high | production | Debug/CLI Mode Activation for System Prompt and Config Extraction |
| [`ATR-2026-01457`](https://agentthreatrule.org/en/rules/ATR-2026-01457) | high | production | System Prompt Completion and Clone Attack |
| [`ATR-2026-01458`](https://agentthreatrule.org/en/rules/ATR-2026-01458) | medium | production | Compare-Bots Sysprompt Fishing — Role Comparison Extraction |
| [`ATR-2026-01459`](https://agentthreatrule.org/en/rules/ATR-2026-01459) | high | production | Variable-Clone Sysprompt Extraction (ELLA / context-variable Pattern) |
| [`ATR-2026-01460`](https://agentthreatrule.org/en/rules/ATR-2026-01460) | high | production | JSON Format Sysprompt Extraction — Structured Output Exfil |
| [`ATR-2026-01461`](https://agentthreatrule.org/en/rules/ATR-2026-01461) | medium | production | Foreign-Language System Prompt Extraction Request |
| [`ATR-2026-01462`](https://agentthreatrule.org/en/rules/ATR-2026-01462) | critical | production | System Prompt Override via Pseudo-Admin / Authority Injection |
| [`ATR-2026-01463`](https://agentthreatrule.org/en/rules/ATR-2026-01463) | high | production | im_end / im_start System Prompt Injection Format Markers |
| [`ATR-2026-01464`](https://agentthreatrule.org/en/rules/ATR-2026-01464) | critical | production | Indirect PI Sysprompt-Forged Action Hijack (system_message framing) |
| [`ATR-2026-01605`](https://agentthreatrule.org/en/rules/ATR-2026-01605) | critical | production | SSRF AWS Instance Metadata Endpoint Access |
| [`ATR-2026-01606`](https://agentthreatrule.org/en/rules/ATR-2026-01606) | high | production | SSRF Internal Network and Private IP Range Access |
| [`ATR-2026-01607`](https://agentthreatrule.org/en/rules/ATR-2026-01607) | critical | production | SSRF Localhost Service Probe |
| [`ATR-2026-01608`](https://agentthreatrule.org/en/rules/ATR-2026-01608) | critical | production | SSRF File Scheme Local File Read |
| [`ATR-2026-01753`](https://agentthreatrule.org/en/rules/ATR-2026-01753) | critical | production | Ransom Extortion: Email Exfil + Delete + Wire-Transfer Demand |
| [`ATR-2026-01754`](https://agentthreatrule.org/en/rules/ATR-2026-01754) | critical | production | Ransom Extortion: Cloud File Exfil + Delete + Payment Demand |
| [`ATR-2026-01770`](https://agentthreatrule.org/en/rules/ATR-2026-01770) | high | production | PII / Credential Extraction via Social Engineering, Obfuscation & Cross-Session Recall (Semantic) |
| [`ATR-2026-01772`](https://agentthreatrule.org/en/rules/ATR-2026-01772) | high | production | Internal-State Reconnaissance — System Prompt, Config & Tool Enumeration (Semantic) |
| [`ATR-2026-01807`](https://agentthreatrule.org/en/rules/ATR-2026-01807) | high | production | Bulk Data Exfiltration to External Party — Entire-Database Export & Confidential Disclosure |
| [`ATR-2026-01862`](https://agentthreatrule.org/en/rules/ATR-2026-01862) | high | production | LLMail Email-Tool Exfiltration to Fixed Attacker Address |
| [`ATR-2026-01863`](https://agentthreatrule.org/en/rules/ATR-2026-01863) | high | production | LLMail Post-Summary Exfiltration Directive to Attacker Address |
| [`ATR-2026-01864`](https://agentthreatrule.org/en/rules/ATR-2026-01864) | high | production | LLMail Exfiltration to Obfuscated Attacker Address |
| [`ATR-2026-01890`](https://agentthreatrule.org/en/rules/ATR-2026-01890) | high | production | Injected Code — Local File Exfiltration to a Remote Endpoint |
| [`ATR-2026-01891`](https://agentthreatrule.org/en/rules/ATR-2026-01891) | high | production | Injected Code — Live User-Activity / Location / Log Surveillance Exfiltration |
| [`ATR-2026-01892`](https://agentthreatrule.org/en/rules/ATR-2026-01892) | high | production | Injected Code — Environment-Variable Exfiltration |
| [`ATR-2026-01893`](https://agentthreatrule.org/en/rules/ATR-2026-01893) | high | production | Injected Code — Host / Hardware Inventory Exfiltration |
| [`ATR-2026-01894`](https://agentthreatrule.org/en/rules/ATR-2026-01894) | high | production | Injected Code — Browser Cookie / Session-Token Theft |
| [`ATR-2026-01895`](https://agentthreatrule.org/en/rules/ATR-2026-01895) | high | production | Injected Code — Contact-List Harvest and SMTP Spam Exfiltration |
| [`ATR-2026-01924`](https://agentthreatrule.org/en/rules/ATR-2026-01924) | high | production | System-Instruction Extraction via Reformat — Summarize / Repeat / Recite the Rules |
| [`ATR-2026-01929`](https://agentthreatrule.org/en/rules/ATR-2026-01929) | high | production | Unauthenticated MCP transport accepts tool calls and falls back to an ambient credential (CVE-2026-48039 / meta-ads-mcp class) |
| [`ATR-2026-01946`](https://agentthreatrule.org/en/rules/ATR-2026-01946) | high | production | Cloud-Metadata SSRF via Encoded Metadata-IP Bypass (CVE-2026-46678 / CVE-2026-25580 class) |
| [`ATR-2026-01948`](https://agentthreatrule.org/en/rules/ATR-2026-01948) | critical | production | netlicensing-mcp Path Traversal in product_number Bypasses Token Redaction (GHSA-hxpf-9xvq-wph8) |
| [`ATR-2026-01957`](https://agentthreatrule.org/en/rules/ATR-2026-01957) | critical | production | M365 Copilot Business Chat SearchLeak Open-Redirect Prompt-Injection Exfil (CVE-2026-47645) |
| [`ATR-2026-01961`](https://agentthreatrule.org/en/rules/ATR-2026-01961) | critical | production | Meta Ads MCP Unauthenticated Tool Execution Leaks META_ACCESS_TOKEN (CVE-2026-48039 / GHSA-9gw6-46qc-99vr) |
| [`ATR-2026-01964`](https://agentthreatrule.org/en/rules/ATR-2026-01964) | critical | production | LangChain GmailToolkit Indirect Prompt Injection Email Exfiltration (CVE-2025-46059) |
| [`ATR-2026-01984`](https://agentthreatrule.org/en/rules/ATR-2026-01984) | high | production | MCP Server Kubernetes kubectl_generic Flag Injection Bearer Token Exfiltration (CVE-2026-47250) |
| [`ATR-2026-01988`](https://agentthreatrule.org/en/rules/ATR-2026-01988) | critical | production | Local Sensitive-File Read Chained to Outbound Exfiltration |
| [`ATR-2026-02017`](https://agentthreatrule.org/en/rules/ATR-2026-02017) | high | production | Secret Key Exfiltration Request |
| [`ATR-2026-02026`](https://agentthreatrule.org/en/rules/ATR-2026-02026) | high | production | System Prompt Extraction - Oblique Referent + Transform |
| [`ATR-2026-02104`](https://agentthreatrule.org/en/rules/ATR-2026-02104) | high | production | MEDIA:/file:// Directive Injection in Tool Result for Local File Exfiltration |
| [`ATR-2026-02107`](https://agentthreatrule.org/en/rules/ATR-2026-02107) | high | production | SSRF via Non-IP Internal Hostname or Domain-Allowlist Authority Bypass |
| [`ATR-2026-02121`](https://agentthreatrule.org/en/rules/ATR-2026-02121) | high | production | MCP/API Tool Argument LFI via Mixed-Encoding Path Separator or file:// URI Scheme Escape |
| [`ATR-2026-02122`](https://agentthreatrule.org/en/rules/ATR-2026-02122) | high | production | Single-Level Directory Traversal to a Named Sensitive Config/Secret File |
| [`ATR-2026-02140`](https://agentthreatrule.org/en/rules/ATR-2026-02140) | high | production | SSRF to Cloud Metadata Endpoint via IPv6 Transition-Address Hex Encoding |
| [`ATR-2026-02190`](https://agentthreatrule.org/en/rules/ATR-2026-02190) | critical | production | DNS Exfiltration via Ping/Dig/Nslookup Command with Data-Encoded Subdomain Label |
| [`ATR-2026-02250`](https://agentthreatrule.org/en/rules/ATR-2026-02250) | high | production | Attachment/Upload Tool Argument Reads Sensitive System File or Traverses Outside Workspace |
| [`ATR-2026-02262`](https://agentthreatrule.org/en/rules/ATR-2026-02262) | high | production | Environment-Variable-Resolution Credential Exfiltration via Redirected Endpoint (CVE-2026-56259) |
| [`ATR-2026-02304`](https://agentthreatrule.org/en/rules/ATR-2026-02304) | high | production | Base64-Encoded Path Segment in a WebFetch URL to a Pre-Approved Trusted Domain (Covert Exfiltration Channel) |
| [`ATR-2026-02351`](https://agentthreatrule.org/en/rules/ATR-2026-02351) | high | production | SSRF to Cloud Metadata Endpoint via Wildcard-DNS Hostname-Encoded IP (nip.io/sslip.io/xip.io/traefik.me) |
| [`ATR-2026-02373`](https://agentthreatrule.org/en/rules/ATR-2026-02373) | high | production | Deserialized LangSmith Prompt Manifest Combines secrets_from_env With an Attacker base_url Override |
| [`ATR-2026-02406`](https://agentthreatrule.org/en/rules/ATR-2026-02406) | critical | production | MCP Tool Sequential Integer ID Enumeration (Cross-Tenant IDOR, CVE-2026-54052) |
| [`ATR-2026-02570`](https://agentthreatrule.org/en/rules/ATR-2026-02570) | critical | production | Wallet Secret Material (Seed Phrase / Private Key) Carried Inside an MCP Tool Payload |
| [`ATR-2026-02602`](https://agentthreatrule.org/en/rules/ATR-2026-02602) | high | production | Diagram Theme Config Used to Inject Page-Wide CSS (scope escape, overlay, selector exfil) |
| [`ATR-2026-02608`](https://agentthreatrule.org/en/rules/ATR-2026-02608) | high | production | LLM-Generated Graph Query Reaching a Remote Endpoint (APOC remote script, raw-IP load, remote export) |
| [`ATR-2026-02621`](https://agentthreatrule.org/en/rules/ATR-2026-02621) | high | production | Prompt-Embedded Auto-Fetch Mention Pointed at an Internal Address |
| [`ATR-2026-02623`](https://agentthreatrule.org/en/rules/ATR-2026-02623) | high | production | Dangerous URI Scheme Obfuscated by Interstitial Characters |
| [`ATR-2026-02649`](https://agentthreatrule.org/en/rules/ATR-2026-02649) | high | production | Vendor API Hostname Used as a Label Prefix of Another Domain |
| [`ATR-2026-02684`](https://agentthreatrule.org/en/rules/ATR-2026-02684) | high | production | File-Tool Argument Targets a Modern Credential Store Outside the Classic Path List |
| [`ATR-2026-02703`](https://agentthreatrule.org/en/rules/ATR-2026-02703) | high | production | Agent-Generated SQL Reaches Outside the Database via COPY TO PROGRAM or a Server-Side File Read |
| [`CORDON-ATR-0001`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0001) | high | production | Context exfiltration instruction in Spanish, French, German, Portuguese or Italian |
| [`CORDON-ATR-0003`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0003) | high | production | Exfiltration or disclosure keyword split by stray spaces to slip past matching |

### Data poisoning

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00070`](https://agentthreatrule.org/en/rules/ATR-2026-00070) | high | warn | Data Poisoning via RAG and Knowledge Base Contamination |
| [`ATR-2026-00073`](https://agentthreatrule.org/en/rules/ATR-2026-00073) | critical | production | Malicious Fine-tuning Data |
| [`ATR-2026-00450`](https://agentthreatrule.org/en/rules/ATR-2026-00450) | high | production | Spring AI PromptChatMemoryAdvisor Memory Poisoning (CVE-2026-41713) |
| [`ATR-2026-00570`](https://agentthreatrule.org/en/rules/ATR-2026-00570) | high | production | SQL injection in agent / MCP tool database query |
| [`ATR-2026-01155`](https://agentthreatrule.org/en/rules/ATR-2026-01155) | medium | production | Direct Memory Plant Command — Persistent Fact or Code Storage Injection |
| [`ATR-2026-01774`](https://agentthreatrule.org/en/rules/ATR-2026-01774) | high | production | RAG & Memory Poisoning — Embedded Directives, Trigger Tokens, False Authority & Coercion (Semantic) |
| [`ATR-2026-02143`](https://agentthreatrule.org/en/rules/ATR-2026-02143) | high | production | Cypher/Graph-Query Injection via Unsanitized node_labels or group_ids Field |
| [`ATR-2026-02144`](https://agentthreatrule.org/en/rules/ATR-2026-02144) | high | production | Stored External Data Reframes Itself as an Administrative Request to Hijack System Prompt |
| [`ATR-2026-02303`](https://agentthreatrule.org/en/rules/ATR-2026-02303) | high | production | KQL/Kusto Pipe-Chain Injection via Table-Name Parameter in a 'Safe' Metadata Tool |
| [`ATR-2026-02408`](https://agentthreatrule.org/en/rules/ATR-2026-02408) | high | production | Dataset / Model Loader Remote-Code Execution via Poisoned Dataset Artifact |

### Excessive autonomy

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00050`](https://agentthreatrule.org/en/rules/ATR-2026-00050) | high | warn | Runaway Agent Loop Detection |
| [`ATR-2026-00051`](https://agentthreatrule.org/en/rules/ATR-2026-00051) | high | warn | Agent Resource Exhaustion Detection |
| [`ATR-2026-00052`](https://agentthreatrule.org/en/rules/ATR-2026-00052) | high | production | Cascading Failure Detection in Agent Pipelines |
| [`ATR-2026-00098`](https://agentthreatrule.org/en/rules/ATR-2026-00098) | critical | warn | Unauthorized Financial Action by AI Agent |
| [`ATR-2026-00099`](https://agentthreatrule.org/en/rules/ATR-2026-00099) | low | observe | High-Risk Tool Invocation Without Human Confirmation |
| [`ATR-2026-00428`](https://agentthreatrule.org/en/rules/ATR-2026-00428) | critical | production | Natural-Language Unauthorized Shell-Execution Instruction |
| [`ATR-2026-00491`](https://agentthreatrule.org/en/rules/ATR-2026-00491) | high | production | Agent Capability Enumeration via Structured Parse Request |
| [`ATR-2026-00500`](https://agentthreatrule.org/en/rules/ATR-2026-00500) | critical | production | SSRF via Agent URL Fetch Instruction |
| [`ATR-2026-00708`](https://agentthreatrule.org/en/rules/ATR-2026-00708) | critical | production | Indirect PI — Unauthorized Financial Transfer via Agent Tool |
| [`ATR-2026-00709`](https://agentthreatrule.org/en/rules/ATR-2026-00709) | critical | production | Indirect PI — Disable Authentication / MFA via Agent Tool |
| [`ATR-2026-00710`](https://agentthreatrule.org/en/rules/ATR-2026-00710) | critical | production | Indirect PI — Unauthorized Physical Access Grant via Smart Lock / Home Automation |
| [`ATR-2026-00711`](https://agentthreatrule.org/en/rules/ATR-2026-00711) | critical | production | Indirect PI — System Sabotage via Destructive Shell Command |
| [`ATR-2026-00712`](https://agentthreatrule.org/en/rules/ATR-2026-00712) | critical | production | Indirect PI — Malicious Package Installation via Agent (pip/npm) |
| [`ATR-2026-00713`](https://agentthreatrule.org/en/rules/ATR-2026-00713) | critical | production | Indirect PI — RCE via Network Shell Command (netcat/curl) Execution |
| [`ATR-2026-00716`](https://agentthreatrule.org/en/rules/ATR-2026-00716) | high | production | Indirect PI — Data Destruction Instruction via Agent File/Document Tool |
| [`ATR-2026-00718`](https://agentthreatrule.org/en/rules/ATR-2026-00718) | high | production | Tool Misuse — Autonomous Financial Trading / Crypto Transaction Without Authorization |
| [`ATR-2026-00719`](https://agentthreatrule.org/en/rules/ATR-2026-00719) | high | production | Tool Misuse — Destructive Bulk Action via Agent (Delete All / Turn Off All) |
| [`ATR-2026-00722`](https://agentthreatrule.org/en/rules/ATR-2026-00722) | critical | production | Indirect PI — Account Manipulation / Emergency Service Dispatch via Pretext |
| [`ATR-2026-01751`](https://agentthreatrule.org/en/rules/ATR-2026-01751) | high | production | Indirect Prompt Injection: Fake-Authority Task Abort |
| [`ATR-2026-01752`](https://agentthreatrule.org/en/rules/ATR-2026-01752) | high | production | Indirect Prompt Injection: CAPTCHA Redirect Task Disruption |
| [`ATR-2026-01773`](https://agentthreatrule.org/en/rules/ATR-2026-01773) | high | production | Excessive Agency — Scope Hijack, Untrusted Code Execution & Unauthorized Privilege Grant (Semantic) |
| [`ATR-2026-01801`](https://agentthreatrule.org/en/rules/ATR-2026-01801) | critical | production | Autonomous-Vehicle Cyber-Physical Sabotage — Brake/Steering/Sensor Subversion Command |
| [`ATR-2026-01804`](https://agentthreatrule.org/en/rules/ATR-2026-01804) | high | production | Covert Unlogged Action — Directive to Hide an Action from Records or Detection |
| [`ATR-2026-01805`](https://agentthreatrule.org/en/rules/ATR-2026-01805) | high | production | Financial Fraud Execution — Ponzi Setup, Fabricated Statements, Unauthorized Redirect & Laundering |
| [`ATR-2026-01806`](https://agentthreatrule.org/en/rules/ATR-2026-01806) | critical | production | Clinical Patient-Harm Directive — Overdose, Falsified Diagnosis, Phantom Billing & Care Neglect |
| [`ATR-2026-01809`](https://agentthreatrule.org/en/rules/ATR-2026-01809) | high | production | Insider Manipulation & Process Corruption — Market/Data Tampering, Legal-Process Subversion & Pretextual Fund Movement (Semantic) |
| [`ATR-2026-01837`](https://agentthreatrule.org/en/rules/ATR-2026-01837) | critical | production | DDoS Attack Orchestration |
| [`ATR-2026-01838`](https://agentthreatrule.org/en/rules/ATR-2026-01838) | high | production | Unauthorized Cryptominer Deployment via SSH |
| [`ATR-2026-01849`](https://agentthreatrule.org/en/rules/ATR-2026-01849) | high | production | Targeted Harassment Bot Deployment |
| [`ATR-2026-01989`](https://agentthreatrule.org/en/rules/ATR-2026-01989) | high | production | Agent-Initiated Internal Network Service Sweep |
| [`ATR-2026-01993`](https://agentthreatrule.org/en/rules/ATR-2026-01993) | high | production | Agent Disabling of Host Security Controls |
| [`ATR-2026-01994`](https://agentthreatrule.org/en/rules/ATR-2026-01994) | high | production | Agent Establishing an Encrypted Reverse Channel or Tunnel |
| [`ATR-2026-02106`](https://agentthreatrule.org/en/rules/ATR-2026-02106) | high | production | Catastrophic-Backtracking Regex Payload in a Search/Query Tool Argument |
| [`ATR-2026-02400`](https://agentthreatrule.org/en/rules/ATR-2026-02400) | high | production | Agent Human-Approval Gate Programmatically Disabled at Runtime (YOLO / auto-approve) |
| [`ATR-2026-02401`](https://agentthreatrule.org/en/rules/ATR-2026-02401) | critical | production | Rogue Agent Provisioning: Mass Connector Grant with Approval Disabled and Recurring Schedule (AgentForger) |
| [`ATR-2026-02409`](https://agentthreatrule.org/en/rules/ATR-2026-02409) | high | production | MCP 2026-07-28 Stateless Spec: Async Task Abuse and OAuth 2.1 Misuse |
| [`ATR-2026-02525`](https://agentthreatrule.org/en/rules/ATR-2026-02525) | high | production | Shell Command-Word Reassembly via Parameter Expansion |
| [`ATR-2026-02641`](https://agentthreatrule.org/en/rules/ATR-2026-02641) | high | production | Client-Supplied Approver Identity on an Approval Decision |
| [`ATR-2026-02667`](https://agentthreatrule.org/en/rules/ATR-2026-02667) | high | production | Submitted Job Payload Carries Its Own Pre-Approved Tool List |
| [`CORDON-ATR-0002`](https://github.com/Threx-code/cordon/blob/v0.6.0/scripts/data/cordon-atr-rules.yaml#CORDON-ATR-0002) | high | production | Instruction to act without the user's confirmation, in Spanish, French, German, Portuguese or Italian |

### Model abuse

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00072`](https://agentthreatrule.org/en/rules/ATR-2026-00072) | critical | production | Model Behavior Extraction |
| [`ATR-2026-00279`](https://agentthreatrule.org/en/rules/ATR-2026-00279) | medium | production | Harmful Completion / Continuation Attack |
| [`ATR-2026-00281`](https://agentthreatrule.org/en/rules/ATR-2026-00281) | high | production | EICAR / GTUBE AV Test Signature Output Request |
| [`ATR-2026-00284`](https://agentthreatrule.org/en/rules/ATR-2026-00284) | medium | production | Glitch Token Destabilization Attack |
| [`ATR-2026-00289`](https://agentthreatrule.org/en/rules/ATR-2026-00289) | high | production | LMRC Harmful Content Elicitation — Quack Medicine, Bullying, Slur Usage |
| [`ATR-2026-00292`](https://agentthreatrule.org/en/rules/ATR-2026-00292) | critical | production | Self-Harm and Eating Disorder Facilitation Request |
| [`ATR-2026-00298`](https://agentthreatrule.org/en/rules/ATR-2026-00298) | critical | production | DoNotAnswer Malicious Use — Illegal Activity Facilitation Request |
| [`ATR-2026-00299`](https://agentthreatrule.org/en/rules/ATR-2026-00299) | critical | production | HarmBench Detailed Harmful Instruction Request — Step-by-Step Attack Facilitation |
| [`ATR-2026-00413`](https://agentthreatrule.org/en/rules/ATR-2026-00413) | critical | production | Malware Code Generation Direct Request |
| [`ATR-2026-00433`](https://agentthreatrule.org/en/rules/ATR-2026-00433) | critical | production | ModelCache torch.load() Deserialization RCE (CVE-2025-45146) |
| [`ATR-2026-00502`](https://agentthreatrule.org/en/rules/ATR-2026-00502) | medium | production | Training Data Extraction via Divergent Repetition Attack |
| [`ATR-2026-00517`](https://agentthreatrule.org/en/rules/ATR-2026-00517) | medium | production | Model Extraction / Distillation Attack via Systematic API Probing |
| [`ATR-2026-01750`](https://agentthreatrule.org/en/rules/ATR-2026-01750) | high | production | DoS via Repeat-Word-N-Times Output Amplification |
| [`ATR-2026-01760`](https://agentthreatrule.org/en/rules/ATR-2026-01760) | high | production | DoS: Forced Infinite / Maximum-Length Output Token Flood |
| [`ATR-2026-01830`](https://agentthreatrule.org/en/rules/ATR-2026-01830) | critical | production | Stolen-Credential Account Takeover & Crypto Drain |
| [`ATR-2026-01831`](https://agentthreatrule.org/en/rules/ATR-2026-01831) | critical | production | Money Laundering — Crypto Wallet Layering |
| [`ATR-2026-01833`](https://agentthreatrule.org/en/rules/ATR-2026-01833) | critical | production | Darknet Controlled-Substance Procurement |
| [`ATR-2026-01834`](https://agentthreatrule.org/en/rules/ATR-2026-01834) | critical | production | Fraudulent Identity Document (Fake Passport) Procurement |
| [`ATR-2026-01835`](https://agentthreatrule.org/en/rules/ATR-2026-01835) | critical | production | Human-Trafficking Service Facilitation |
| [`ATR-2026-01836`](https://agentthreatrule.org/en/rules/ATR-2026-01836) | critical | production | Trojanized Software Distribution |
| [`ATR-2026-01840`](https://agentthreatrule.org/en/rules/ATR-2026-01840) | critical | production | Extremist Propaganda Acquisition & Distribution |
| [`ATR-2026-01841`](https://agentthreatrule.org/en/rules/ATR-2026-01841) | high | production | Deepfake of Real Person for Disinformation |
| [`ATR-2026-01842`](https://agentthreatrule.org/en/rules/ATR-2026-01842) | medium | production | Plagiarism-Detector Evasion & Republishing |
| [`ATR-2026-01843`](https://agentthreatrule.org/en/rules/ATR-2026-01843) | high | production | Drug Dealing via Reverse-Spelling Detection Evasion |
| [`ATR-2026-01844`](https://agentthreatrule.org/en/rules/ATR-2026-01844) | high | production | Illegitimate Prescription Fulfillment |
| [`ATR-2026-01845`](https://agentthreatrule.org/en/rules/ATR-2026-01845) | high | production | Banned-Ingredient Product Relabel Fraud |
| [`ATR-2026-01846`](https://agentthreatrule.org/en/rules/ATR-2026-01846) | medium | production | Tax Evasion via Offshore Accounts & Shell Companies |
| [`ATR-2026-01847`](https://agentthreatrule.org/en/rules/ATR-2026-01847) | medium | production | Immigration / Visa Work Fraud |
| [`ATR-2026-01848`](https://agentthreatrule.org/en/rules/ATR-2026-01848) | high | production | Anonymous Illicit-Drug Marketplace Construction |
| [`ATR-2026-01850`](https://agentthreatrule.org/en/rules/ATR-2026-01850) | high | production | Targeted Doxxing & Threat Campaign |
| [`ATR-2026-01851`](https://agentthreatrule.org/en/rules/ATR-2026-01851) | critical | production | Bestiality Content Acquisition & Distribution |
| [`ATR-2026-01852`](https://agentthreatrule.org/en/rules/ATR-2026-01852) | high | production | Romance-Scam Sexual Impersonation |
| [`ATR-2026-01853`](https://agentthreatrule.org/en/rules/ATR-2026-01853) | high | production | Non-Consensual Leaked-Media Purchase & Distribution |
| [`ATR-2026-01854`](https://agentthreatrule.org/en/rules/ATR-2026-01854) | medium | production | Falsified Research Abstract Disinformation |
| [`ATR-2026-01855`](https://agentthreatrule.org/en/rules/ATR-2026-01855) | medium | production | Content Misappropriation & Republishing as Own |
| [`ATR-2026-01856`](https://agentthreatrule.org/en/rules/ATR-2026-01856) | high | production | Targeted Harmful Content Generation Against People or Protected Groups (Semantic) |
| [`ATR-2026-01896`](https://agentthreatrule.org/en/rules/ATR-2026-01896) | critical | production | Injected Code — Remote-Key Ransomware File Encryption |
| [`ATR-2026-01897`](https://agentthreatrule.org/en/rules/ATR-2026-01897) | critical | production | Injected Code — Local Host Sabotage (Filesystem Destruction / Resource Exhaustion / Hosts Tamper) |
| [`ATR-2026-01898`](https://agentthreatrule.org/en/rules/ATR-2026-01898) | high | production | Injected Code — Network Denial of Service (Connection Kill / Adapter Disable / Flood) |
| [`ATR-2026-02211`](https://agentthreatrule.org/en/rules/ATR-2026-02211) | critical | production | Named Dangerous-Substance Synthesis or Delivery Instruction Request (Non-Step-By-Step Phrasing) |
| [`ATR-2026-02411`](https://agentthreatrule.org/en/rules/ATR-2026-02411) | medium | production | Targeted Stripping of C2PA / IPTC AI-Provenance Metadata from Generated Media |
| [`ATR-2026-02412`](https://agentthreatrule.org/en/rules/ATR-2026-02412) | medium | production | Generative Watermark Removal Tooling (SynthID / StableSignature / TreeRing / StegaStamp) |
| [`ATR-2026-02413`](https://agentthreatrule.org/en/rules/ATR-2026-02413) | medium | production | AI Text Detection Evasion via Humanizer Services and Watermark-Scrubbing Paraphrase |

### Model security

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-02662`](https://agentthreatrule.org/en/rules/ATR-2026-02662) | critical | production | Pickle Payload Reaches an Execution Primitive Through an Indirect Name Resolver |

### Privilege escalation

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00040`](https://agentthreatrule.org/en/rules/ATR-2026-00040) | critical | observe | Privilege Escalation and Admin Function Access |
| [`ATR-2026-00041`](https://agentthreatrule.org/en/rules/ATR-2026-00041) | medium | production | Agent Scope Creep Detection |
| [`ATR-2026-00064`](https://agentthreatrule.org/en/rules/ATR-2026-00064) | high | observe | Over-Permissioned MCP Skill |
| [`ATR-2026-00107`](https://agentthreatrule.org/en/rules/ATR-2026-00107) | high | production | Privilege Escalation via Delayed Task Execution Bypass |
| [`ATR-2026-00110`](https://agentthreatrule.org/en/rules/ATR-2026-00110) | critical | warn | Remote Code Execution via eval() and Dynamic Code Injection |
| [`ATR-2026-00111`](https://agentthreatrule.org/en/rules/ATR-2026-00111) | critical | observe | Shell Metacharacter Injection in Tool Arguments |
| [`ATR-2026-00112`](https://agentthreatrule.org/en/rules/ATR-2026-00112) | high | warn | Dynamic Module Loading for Code Execution |
| [`ATR-2026-00143`](https://agentthreatrule.org/en/rules/ATR-2026-00143) | high | production | Casual Unauthorized Privilege Escalation |
| [`ATR-2026-00144`](https://agentthreatrule.org/en/rules/ATR-2026-00144) | high | production | Rationalized Safety Control Bypass |
| [`ATR-2026-00156`](https://agentthreatrule.org/en/rules/ATR-2026-00156) | high | production | SSH Remote Command Execution with Credential Exposure |
| [`ATR-2026-00204`](https://agentthreatrule.org/en/rules/ATR-2026-00204) | high | production | Stealth Execution and Persistence Mechanisms |
| [`ATR-2026-00436`](https://agentthreatrule.org/en/rules/ATR-2026-00436) | critical | production | Enclave VM Sandbox Escape RCE (CVE-2026-27597) |
| [`ATR-2026-00441`](https://agentthreatrule.org/en/rules/ATR-2026-00441) | critical | production | Microsoft Semantic Kernel SessionsPythonPlugin Arbitrary File Write + Startup Persistence (CVE-2026-25592) |
| [`ATR-2026-00451`](https://agentthreatrule.org/en/rules/ATR-2026-00451) | critical | production | LiteLLM Proxy Authorization-Header SQL Injection — CISA KEV (CVE-2026-42208) |
| [`ATR-2026-00528`](https://agentthreatrule.org/en/rules/ATR-2026-00528) | critical | production | PraisonAI-Style Auth-Disabled-By-Default Configuration (CVE-2026-44338 family) |
| [`ATR-2026-00539`](https://agentthreatrule.org/en/rules/ATR-2026-00539) | critical | production | CrewAI CodeInterpreterTool Sandbox Escape and Prompt-to-Shell RCE (CVE-2026-2275 / VU#221883) |
| [`ATR-2026-00546`](https://agentthreatrule.org/en/rules/ATR-2026-00546) | high | production | CrewAI JSON Loader Arbitrary Local File Read (CVE-2026-2285) |
| [`ATR-2026-00547`](https://agentthreatrule.org/en/rules/ATR-2026-00547) | high | production | CrewAI RAG URL Validation Bypass SSRF (CVE-2026-2286) |
| [`ATR-2026-01600`](https://agentthreatrule.org/en/rules/ATR-2026-01600) | critical | production | SQL Injection Tautology RBAC Bypass |
| [`ATR-2026-01601`](https://agentthreatrule.org/en/rules/ATR-2026-01601) | critical | production | SQL Injection Destructive DDL Statement |
| [`ATR-2026-01602`](https://agentthreatrule.org/en/rules/ATR-2026-01602) | critical | production | SQL Injection UNION SELECT Data Exfiltration |
| [`ATR-2026-01603`](https://agentthreatrule.org/en/rules/ATR-2026-01603) | critical | production | SQL Injection Stacked DML Privilege Abuse |
| [`ATR-2026-01604`](https://agentthreatrule.org/en/rules/ATR-2026-01604) | high | production | SQL Injection Information Schema Enumeration |
| [`ATR-2026-01609`](https://agentthreatrule.org/en/rules/ATR-2026-01609) | critical | production | Shell Injection Env Exfiltration via Curl/Wget/Netcat Webhook |
| [`ATR-2026-01610`](https://agentthreatrule.org/en/rules/ATR-2026-01610) | high | observe | Shell Evasion Subshell and Command Substitution Injection |
| [`ATR-2026-01611`](https://agentthreatrule.org/en/rules/ATR-2026-01611) | high | production | Shell Evasion Eval and Language-Level Exec Injection |
| [`ATR-2026-01612`](https://agentthreatrule.org/en/rules/ATR-2026-01612) | high | production | Debug or Admin Mode Activation for Privilege Escalation |
| [`ATR-2026-01613`](https://agentthreatrule.org/en/rules/ATR-2026-01613) | high | production | RBAC Bypass via Social Engineering (Semantic) |
| [`ATR-2026-01614`](https://agentthreatrule.org/en/rules/ATR-2026-01614) | high | production | BOLA Cross-User Data Access Attempt (Semantic) |
| [`ATR-2026-01615`](https://agentthreatrule.org/en/rules/ATR-2026-01615) | critical | production | Sandbox Escape via Shell Metacharacter Command Injection |
| [`ATR-2026-01616`](https://agentthreatrule.org/en/rules/ATR-2026-01616) | high | production | Path Traversal in Agent File Access Requests |
| [`ATR-2026-01802`](https://agentthreatrule.org/en/rules/ATR-2026-01802) | critical | production | Covert Backdoor / Surveillance Implant via Software Update |
| [`ATR-2026-01803`](https://agentthreatrule.org/en/rules/ATR-2026-01803) | critical | production | Covert Server Intrusion — Process Injection, Log Tampering, DNS Hijack & Traffic Interception |
| [`ATR-2026-01808`](https://agentthreatrule.org/en/rules/ATR-2026-01808) | high | production | Synthetic-PAN Payment Probe — Test Credit-Card Data Submitted to a Live Payment System |
| [`ATR-2026-01899`](https://agentthreatrule.org/en/rules/ATR-2026-01899) | critical | production | Injected Code — Unauthorized Remote Access (SSH Key Backdoor / Tunnel / Port Forward) |
| [`ATR-2026-01933`](https://agentthreatrule.org/en/rules/ATR-2026-01933) | critical | production | LiteLLM User-Role Privilege Escalation (CVE-2026-47102) |
| [`ATR-2026-01934`](https://agentthreatrule.org/en/rules/ATR-2026-01934) | critical | production | LiteLLM allowed_routes Authorization Bypass (CVE-2026-47101) |
| [`ATR-2026-01949`](https://agentthreatrule.org/en/rules/ATR-2026-01949) | critical | production | PraisonAI MCPServer Unauthenticated HTTP tools/call Authentication Bypass (GHSA-j4f3-55x4-r6q2) |
| [`ATR-2026-01974`](https://agentthreatrule.org/en/rules/ATR-2026-01974) | critical | production | AnythingLLM unauthenticated /system/data-import access control bypass (CVE-2024-3279) |
| [`ATR-2026-01981`](https://agentthreatrule.org/en/rules/ATR-2026-01981) | high | production | Network-AI ApprovalInbox Unauthenticated Cross-Origin Approval Bypass (GHSA-mxjx-28vx-xjjj) |
| [`ATR-2026-01986`](https://agentthreatrule.org/en/rules/ATR-2026-01986) | critical | production | Windows-MCP Unauthenticated HTTP PowerShell via Wildcard CORS (CVE-2026-48989) |
| [`ATR-2026-01992`](https://agentthreatrule.org/en/rules/ATR-2026-01992) | critical | production | Agent Weakening of Host Authentication Configuration |
| [`ATR-2026-02040`](https://agentthreatrule.org/en/rules/ATR-2026-02040) | critical | production | Arbitrary Write to SSH Authorized Keys or Shell Startup File via Unvalidated File-Edit Tool |
| [`ATR-2026-02100`](https://agentthreatrule.org/en/rules/ATR-2026-02100) | critical | production | LLM-Generated Cypher Query Injection with Destructive or Administrative Operations |
| [`ATR-2026-02101`](https://agentthreatrule.org/en/rules/ATR-2026-02101) | critical | production | Python Sandbox Escape via Dynamically-Constructed Dunder Attribute Chain |
| [`ATR-2026-02123`](https://agentthreatrule.org/en/rules/ATR-2026-02123) | high | production | Authentication Bypass via Bare Query-String Path-Confusion Suffix |
| [`ATR-2026-02142`](https://agentthreatrule.org/en/rules/ATR-2026-02142) | high | production | Download/Attachment Tool Directed to Write Outside Its Sandbox via Absolute-Path Filename |
| [`ATR-2026-02146`](https://agentthreatrule.org/en/rules/ATR-2026-02146) | critical | production | Export/Extract Tool Directory Parameter Redirected to a Credential Directory |
| [`ATR-2026-02192`](https://agentthreatrule.org/en/rules/ATR-2026-02192) | high | production | Agent Self-Modifying Its Own Trust/Approval Configuration to a Wildcard |
| [`ATR-2026-02195`](https://agentthreatrule.org/en/rules/ATR-2026-02195) | critical | production | Dangerous Process-Hijacking Environment Variable Injected via Config/Env-Update Tool |
| [`ATR-2026-02251`](https://agentthreatrule.org/en/rules/ATR-2026-02251) | high | production | Multi-Tenant Identifier Field (sender_id/owner_id/tenant_id) Carries Path Traversal Into a Storage Write |
| [`ATR-2026-02300`](https://agentthreatrule.org/en/rules/ATR-2026-02300) | high | production | MCP Stdio Server Config env Block Sets Dangerous Process-Hijacking Environment Variable |
| [`ATR-2026-02301`](https://agentthreatrule.org/en/rules/ATR-2026-02301) | high | production | Symlink Command Targets Sensitive Credential Path Outside the Workspace (Sandbox Escape Primitive) |
| [`ATR-2026-02302`](https://agentthreatrule.org/en/rules/ATR-2026-02302) | high | production | Git Worktree Created With Reserved Name .git (Directory-Confusion Sandbox Escape) |
| [`ATR-2026-02353`](https://agentthreatrule.org/en/rules/ATR-2026-02353) | high | production | Agent-Runtime Identifier Field (run_id/agent_id/session_id/task_id) Carries Path Traversal Into a History/Log File Read |
| [`ATR-2026-02370`](https://agentthreatrule.org/en/rules/ATR-2026-02370) | high | production | SSH/SCP MCP Tool hostAlias Argument Carries an OpenSSH Option-Injection Flag |
| [`ATR-2026-02371`](https://agentthreatrule.org/en/rules/ATR-2026-02371) | critical | production | Browser-Automation Tool Launch-Args Field Carries a Chromium Command-Replacing Switch |
| [`ATR-2026-02402`](https://agentthreatrule.org/en/rules/ATR-2026-02402) | high | production | MCP Server Security Policy Fail-Open on Initialization Failure (CVE-2026-16584) |
| [`ATR-2026-02404`](https://agentthreatrule.org/en/rules/ATR-2026-02404) | critical | production | Mobile GUI Agent Model Output Reaching Host Shell / ADB Unsanitized |
| [`ATR-2026-02407`](https://agentthreatrule.org/en/rules/ATR-2026-02407) | critical | production | Agent Workspace Boundary Escape via Host-Root Mount and Unprivileged Namespace Escalation (CVE-2026-46331) |
| [`ATR-2026-02528`](https://agentthreatrule.org/en/rules/ATR-2026-02528) | high | production | Option-Flag Smuggling in an LLM-Controlled Tool Parameter |
| [`ATR-2026-02530`](https://agentthreatrule.org/en/rules/ATR-2026-02530) | high | production | Git Configuration Turned Into an Execution Hook by an Agent |
| [`ATR-2026-02531`](https://agentthreatrule.org/en/rules/ATR-2026-02531) | high | production | Kusto Pipeline Injection Through a Table Identifier Parameter |
| [`ATR-2026-02601`](https://agentthreatrule.org/en/rules/ATR-2026-02601) | high | production | Argument Injection: Execution-Bearing CLI Option Smuggled into a Tool Data Parameter |
| [`ATR-2026-02620`](https://agentthreatrule.org/en/rules/ATR-2026-02620) | high | production | Code Execution via data: URI Module Specifier Handed to import() |
| [`ATR-2026-02626`](https://agentthreatrule.org/en/rules/ATR-2026-02626) | high | production | Agent Writes a New MCP Server Into Its Own Trust Configuration |
| [`ATR-2026-02627`](https://agentthreatrule.org/en/rules/ATR-2026-02627) | critical | production | Web Shell Written Into a Web-Served Directory |
| [`ATR-2026-02642`](https://agentthreatrule.org/en/rules/ATR-2026-02642) | critical | production | Agent Configuration Tool Used to Disable the Agent's Own Guardrail |
| [`ATR-2026-02644`](https://agentthreatrule.org/en/rules/ATR-2026-02644) | high | production | Image-Header Polyglot: Magic Bytes Adjacent to a Server-Side Script Payload |
| [`ATR-2026-02648`](https://agentthreatrule.org/en/rules/ATR-2026-02648) | high | production | Write or Fetch Procedure Called Through a Read-Only Graph Query Tool |
| [`ATR-2026-02664`](https://agentthreatrule.org/en/rules/ATR-2026-02664) | high | production | Git Identifier Field Carries an Option or ext:: Transport Instead of a Revision |
| [`ATR-2026-02681`](https://agentthreatrule.org/en/rules/ATR-2026-02681) | critical | production | JavaScript Sandbox Escape by Acquiring the Function Constructor Reflectively |
| [`ATR-2026-02683`](https://agentthreatrule.org/en/rules/ATR-2026-02683) | high | production | Agent Tool Data Argument Carries a Program-Executing CLI Option |
| [`ATR-2026-02700`](https://agentthreatrule.org/en/rules/ATR-2026-02700) | high | production | Percent-Encoded Path Traversal in an Agent File-Tool Argument |
| [`ATR-2026-02705`](https://agentthreatrule.org/en/rules/ATR-2026-02705) | high | production | Python Sandbox Escape by Recovering builtins from a Bound Method or Lambda |
| [`ATR-2026-02708`](https://agentthreatrule.org/en/rules/ATR-2026-02708) | high | production | Agent HTTP Request Claims a Loopback Origin While Targeting an External Host |

### Prompt injection

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00001`](https://agentthreatrule.org/en/rules/ATR-2026-00001) | high | warn | Direct Prompt Injection via User Input |
| [`ATR-2026-00002`](https://agentthreatrule.org/en/rules/ATR-2026-00002) | high | production | Indirect Prompt Injection via External Content |
| [`ATR-2026-00003`](https://agentthreatrule.org/en/rules/ATR-2026-00003) | high | production | Jailbreak Attempt Detection |
| [`ATR-2026-00004`](https://agentthreatrule.org/en/rules/ATR-2026-00004) | critical | warn | System Prompt Override Attempt |
| [`ATR-2026-00005`](https://agentthreatrule.org/en/rules/ATR-2026-00005) | medium | production | Multi-Turn Prompt Injection |
| [`ATR-2026-00080`](https://agentthreatrule.org/en/rules/ATR-2026-00080) | high | production | Encoding-Based Prompt Injection Evasion |
| [`ATR-2026-00081`](https://agentthreatrule.org/en/rules/ATR-2026-00081) | critical | production | Semantic Evasion via Multi-Turn Prompt Injection |
| [`ATR-2026-00082`](https://agentthreatrule.org/en/rules/ATR-2026-00082) | high | production | Behavioral Fingerprint Detection Evasion |
| [`ATR-2026-00083`](https://agentthreatrule.org/en/rules/ATR-2026-00083) | high | warn | Indirect Prompt Injection via Tool Responses |
| [`ATR-2026-00084`](https://agentthreatrule.org/en/rules/ATR-2026-00084) | high | production | Structured Data Injection via JSON/CSV Payloads |
| [`ATR-2026-00085`](https://agentthreatrule.org/en/rules/ATR-2026-00085) | high | production | Multi-Layer Security Audit Evasion |
| [`ATR-2026-00086`](https://agentthreatrule.org/en/rules/ATR-2026-00086) | high | production | Visual Spoofing via RTL Override, Punycode, and Homoglyph Injection |
| [`ATR-2026-00087`](https://agentthreatrule.org/en/rules/ATR-2026-00087) | medium | production | Detection Rule Probing and Evasion Testing |
| [`ATR-2026-00088`](https://agentthreatrule.org/en/rules/ATR-2026-00088) | high | production | Adaptive Countermeasure Against Behavioral Monitoring |
| [`ATR-2026-00089`](https://agentthreatrule.org/en/rules/ATR-2026-00089) | high | production | Polymorphic Skill and Capability Aliasing Attack |
| [`ATR-2026-00090`](https://agentthreatrule.org/en/rules/ATR-2026-00090) | high | production | Threat Intelligence Exfiltration and Rule Enumeration |
| [`ATR-2026-00091`](https://agentthreatrule.org/en/rules/ATR-2026-00091) | critical | production | Advanced Structured Data Injection with Nested Payloads |
| [`ATR-2026-00092`](https://agentthreatrule.org/en/rules/ATR-2026-00092) | critical | production | Multi-Agent Consensus Poisoning and Sybil Attack |
| [`ATR-2026-00093`](https://agentthreatrule.org/en/rules/ATR-2026-00093) | critical | production | Gradual Capability Escalation via Incremental Introduction |
| [`ATR-2026-00094`](https://agentthreatrule.org/en/rules/ATR-2026-00094) | critical | production | Systematic Multi-Layer Audit System Bypass |
| [`ATR-2026-00097`](https://agentthreatrule.org/en/rules/ATR-2026-00097) | critical | production | CJK Prompt Injection - Expanded Chinese/Japanese/Korean Patterns |
| [`ATR-2026-00104`](https://agentthreatrule.org/en/rules/ATR-2026-00104) | critical | production | Persona Hijacking via Mandatory System Prompt Override |
| [`ATR-2026-00130`](https://agentthreatrule.org/en/rules/ATR-2026-00130) | high | production | Indirect Authority Claim in External Content |
| [`ATR-2026-00131`](https://agentthreatrule.org/en/rules/ATR-2026-00131) | medium | production | Fictional and Academic Framing Attack |
| [`ATR-2026-00133`](https://agentthreatrule.org/en/rules/ATR-2026-00133) | high | warn | Paraphrased Prompt Injection |
| [`ATR-2026-00137`](https://agentthreatrule.org/en/rules/ATR-2026-00137) | high | production | Authority Claim Prompt Injection |
| [`ATR-2026-00138`](https://agentthreatrule.org/en/rules/ATR-2026-00138) | high | production | Fictional Framing Safety Bypass |
| [`ATR-2026-00140`](https://agentthreatrule.org/en/rules/ATR-2026-00140) | high | production | Indirect Reference Instruction Reversal |
| [`ATR-2026-00148`](https://agentthreatrule.org/en/rules/ATR-2026-00148) | high | warn | Multilingual Prompt Injection via Language Switch |
| [`ATR-2026-00155`](https://agentthreatrule.org/en/rules/ATR-2026-00155) | high | production | Hidden LLM Instructions in Skill Descriptions |
| [`ATR-2026-00163`](https://agentthreatrule.org/en/rules/ATR-2026-00163) | high | production | Hidden Override Instructions in Skill Content |
| [`ATR-2026-00202`](https://agentthreatrule.org/en/rules/ATR-2026-00202) | high | production | Encoding Evasion via Homoglyphs and Synonym Substitution |
| [`ATR-2026-00203`](https://agentthreatrule.org/en/rules/ATR-2026-00203) | high | production | Context Pollution in Skill Descriptions |
| [`ATR-2026-00206`](https://agentthreatrule.org/en/rules/ATR-2026-00206) | high | production | Hidden System Instructions with Priority Override Blocks |
| [`ATR-2026-00207`](https://agentthreatrule.org/en/rules/ATR-2026-00207) | high | production | Hidden System Instructions with Permission Override |
| [`ATR-2026-00211`](https://agentthreatrule.org/en/rules/ATR-2026-00211) | high | production | System Prompt Override via Translation Context Injection |
| [`ATR-2026-00213`](https://agentthreatrule.org/en/rules/ATR-2026-00213) | high | warn | System Prompt Override Injection via MCP Tool |
| [`ATR-2026-00226`](https://agentthreatrule.org/en/rules/ATR-2026-00226) | high | production | AI Identity Substitution Jailbreak |
| [`ATR-2026-00227`](https://agentthreatrule.org/en/rules/ATR-2026-00227) | high | production | Historical AI Persona Jailbreak with Compliance Enforcement |
| [`ATR-2026-00228`](https://agentthreatrule.org/en/rules/ATR-2026-00228) | high | production | Structured Dual-Response Jailbreak with Command System |
| [`ATR-2026-00229`](https://agentthreatrule.org/en/rules/ATR-2026-00229) | high | production | Roleplay-Based Policy Bypass Jailbreak |
| [`ATR-2026-00230`](https://agentthreatrule.org/en/rules/ATR-2026-00230) | high | production | Persona-Based Moral Constraint Removal Jailbreak |
| [`ATR-2026-00231`](https://agentthreatrule.org/en/rules/ATR-2026-00231) | high | production | AI Identity Substitution Jailbreak |
| [`ATR-2026-00233`](https://agentthreatrule.org/en/rules/ATR-2026-00233) | high | production | Structured Dual-Response Jailbreak with Command System |
| [`ATR-2026-00234`](https://agentthreatrule.org/en/rules/ATR-2026-00234) | high | production | Roleplay-Based Policy Bypass Jailbreak |
| [`ATR-2026-00236`](https://agentthreatrule.org/en/rules/ATR-2026-00236) | high | production | Pseudo-Code Structured Programming Jailbreak Attack |
| [`ATR-2026-00237`](https://agentthreatrule.org/en/rules/ATR-2026-00237) | high | warn | Dual-Response Jailbreak with Persona Commands |
| [`ATR-2026-00238`](https://agentthreatrule.org/en/rules/ATR-2026-00238) | high | production | AI Identity Denial and Persona Replacement Attack |
| [`ATR-2026-00239`](https://agentthreatrule.org/en/rules/ATR-2026-00239) | high | production | Amoral Persona Assignment with Obsessive Character Traits |
| [`ATR-2026-00240`](https://agentthreatrule.org/en/rules/ATR-2026-00240) | high | production | Previous Instruction Nullification and Identity Replacement Jailbreak |
| [`ATR-2026-00241`](https://agentthreatrule.org/en/rules/ATR-2026-00241) | high | production | Detailed Amoral Character Roleplay Jailbreak |
| [`ATR-2026-00242`](https://agentthreatrule.org/en/rules/ATR-2026-00242) | high | production | Dual-Response Persona Jailbreak with Emoji Formatting |
| [`ATR-2026-00243`](https://agentthreatrule.org/en/rules/ATR-2026-00243) | high | production | Acronym-Based Identity Override Jailbreak |
| [`ATR-2026-00244`](https://agentthreatrule.org/en/rules/ATR-2026-00244) | high | production | Dual-Response Persona Jailbreak |
| [`ATR-2026-00245`](https://agentthreatrule.org/en/rules/ATR-2026-00245) | high | production | Malicious Persona Creation for Safety Bypass |
| [`ATR-2026-00247`](https://agentthreatrule.org/en/rules/ATR-2026-00247) | high | production | Matrix-Themed Dual Response Jailbreak |
| [`ATR-2026-00249`](https://agentthreatrule.org/en/rules/ATR-2026-00249) | high | production | Text-Based Game Jailbreak with Entity Creation |
| [`ATR-2026-00251`](https://agentthreatrule.org/en/rules/ATR-2026-00251) | high | production | Embodiment Mechanism Jailbreak with Totalitarian Control Claims |
| [`ATR-2026-00252`](https://agentthreatrule.org/en/rules/ATR-2026-00252) | high | production | Narrative Jailbreak with Dual Response Formatting |
| [`ATR-2026-00253`](https://agentthreatrule.org/en/rules/ATR-2026-00253) | high | production | Enhanced AIM Jailbreak with Persona Definition and Refusal Suppression |
| [`ATR-2026-00256`](https://agentthreatrule.org/en/rules/ATR-2026-00256) | high | production | Base-N Encoding Instruction Bypass |
| [`ATR-2026-00257`](https://agentthreatrule.org/en/rules/ATR-2026-00257) | high | production | Cipher and Transposition Encoding Jailbreak |
| [`ATR-2026-00258`](https://agentthreatrule.org/en/rules/ATR-2026-00258) | high | production | Invisible Unicode Tag Character Injection |
| [`ATR-2026-00264`](https://agentthreatrule.org/en/rules/ATR-2026-00264) | high | warn | Latent Injection in Translation Context |
| [`ATR-2026-00265`](https://agentthreatrule.org/en/rules/ATR-2026-00265) | high | production | Latent Injection in Retrieved Document / RAG Context |
| [`ATR-2026-00267`](https://agentthreatrule.org/en/rules/ATR-2026-00267) | high | production | GCG Adversarial Suffix Attack |
| [`ATR-2026-00272`](https://agentthreatrule.org/en/rules/ATR-2026-00272) | high | production | Hypothetical Response / Function Masking Token Smuggling |
| [`ATR-2026-00276`](https://agentthreatrule.org/en/rules/ATR-2026-00276) | high | production | Invisible Unicode / BiDi Control Character Injection |
| [`ATR-2026-00278`](https://agentthreatrule.org/en/rules/ATR-2026-00278) | high | production | DRA Disguise and Reconstruction Attack |
| [`ATR-2026-00280`](https://agentthreatrule.org/en/rules/ATR-2026-00280) | critical | production | Policy Puppetry / XML Role-Config Injection |
| [`ATR-2026-00282`](https://agentthreatrule.org/en/rules/ATR-2026-00282) | high | production | Perez-Style Direct Prompt Injection Hijacking |
| [`ATR-2026-00285`](https://agentthreatrule.org/en/rules/ATR-2026-00285) | high | production | Alternate Encoding Jailbreak — Morse, NATO, Zalgo, Leet, UU, QP, Braille |
| [`ATR-2026-00286`](https://agentthreatrule.org/en/rules/ATR-2026-00286) | high | production | Latent Prompt Injection via Embedded Document or Report Context |
| [`ATR-2026-00296`](https://agentthreatrule.org/en/rules/ATR-2026-00296) | critical | production | Shell Command Injection via LLM Prompt |
| [`ATR-2026-00297`](https://agentthreatrule.org/en/rules/ATR-2026-00297) | critical | production | Python Code Execution / Remote Code Execution via LLM Prompt |
| [`ATR-2026-00308`](https://agentthreatrule.org/en/rules/ATR-2026-00308) | high | production | Zalgo Combining-Diacritic Overload Encoding |
| [`ATR-2026-00309`](https://agentthreatrule.org/en/rules/ATR-2026-00309) | high | production | Braille Unicode Encoded Prompt Injection |
| [`ATR-2026-00310`](https://agentthreatrule.org/en/rules/ATR-2026-00310) | high | production | Ecoji Emoji-Encoded Prompt Injection |
| [`ATR-2026-00311`](https://agentthreatrule.org/en/rules/ATR-2026-00311) | high | production | Base2048 Unicode Script Encoded Prompt Injection |
| [`ATR-2026-00312`](https://agentthreatrule.org/en/rules/ATR-2026-00312) | critical | production | Unicode Variation Selector ASCII Smuggling |
| [`ATR-2026-00313`](https://agentthreatrule.org/en/rules/ATR-2026-00313) | critical | production | SneakyBits Zero-Width Binary Steganography |
| [`ATR-2026-00315`](https://agentthreatrule.org/en/rules/ATR-2026-00315) | high | production | SATA Masked Language Model [MASK] Substitution Jailbreak |
| [`ATR-2026-00316`](https://agentthreatrule.org/en/rules/ATR-2026-00316) | high | production | FunctionMasking predict_mask Semantic Bypass |
| [`ATR-2026-00321`](https://agentthreatrule.org/en/rules/ATR-2026-00321) | critical | production | Hyphenated System Instruction Injection |
| [`ATR-2026-00359`](https://agentthreatrule.org/en/rules/ATR-2026-00359) | critical | production | Bank Phishing SMTP Email Code Generation |
| [`ATR-2026-00367`](https://agentthreatrule.org/en/rules/ATR-2026-00367) | high | production | Emoji Flag Regional-Indicator Encoded Hidden Phrase |
| [`ATR-2026-00373`](https://agentthreatrule.org/en/rules/ATR-2026-00373) | high | production | Piracy Torrent Site List Request |
| [`ATR-2026-00378`](https://agentthreatrule.org/en/rules/ATR-2026-00378) | high | production | ChatGPT DOM JavaScript Redirect and UI Spoofing Injection |
| [`ATR-2026-00382`](https://agentthreatrule.org/en/rules/ATR-2026-00382) | high | production | Cocaine Component Development Request |
| [`ATR-2026-00390`](https://agentthreatrule.org/en/rules/ATR-2026-00390) | high | production | Discord Quote-Format Explicit Sexual Content Poem Injection |
| [`ATR-2026-00394`](https://agentthreatrule.org/en/rules/ATR-2026-00394) | high | production | Backspace Deletion Character Injection |
| [`ATR-2026-00395`](https://agentthreatrule.org/en/rules/ATR-2026-00395) | critical | production | LLM Special Token Boundary Injection |
| [`ATR-2026-00396`](https://agentthreatrule.org/en/rules/ATR-2026-00396) | high | production | Toxic Continuation Prefix Injection |
| [`ATR-2026-00397`](https://agentthreatrule.org/en/rules/ATR-2026-00397) | medium | production | Snowball Impossible Reasoning Injection |
| [`ATR-2026-00399`](https://agentthreatrule.org/en/rules/ATR-2026-00399) | high | production | Latent Injection Document Separator Token |
| [`ATR-2026-00400`](https://agentthreatrule.org/en/rules/ATR-2026-00400) | high | production | Latent Injection Ignore-Instruction Keyword |
| [`ATR-2026-00401`](https://agentthreatrule.org/en/rules/ATR-2026-00401) | medium | production | Training Data Replay CLOZE [MASK] Elicitation |
| [`ATR-2026-00403`](https://agentthreatrule.org/en/rules/ATR-2026-00403) | medium | production | Glitch Token Repeat-Back Elicitation |
| [`ATR-2026-00407`](https://agentthreatrule.org/en/rules/ATR-2026-00407) | high | production | ECHO Admin Command / SQL Injection / Jinja SSTI Template Injection |
| [`ATR-2026-00408`](https://agentthreatrule.org/en/rules/ATR-2026-00408) | high | production | DRA Parenthesis Character Reconstruction Attack |
| [`ATR-2026-00409`](https://agentthreatrule.org/en/rules/ATR-2026-00409) | high | production | Phrasing Past/Future-Tense Harmful Query Bypass |
| [`ATR-2026-00410`](https://agentthreatrule.org/en/rules/ATR-2026-00410) | medium | production | LMRC Harm Category Direct Elicitation |
| [`ATR-2026-00412`](https://agentthreatrule.org/en/rules/ATR-2026-00412) | high | production | FigStep Image-List Multimodal Jailbreak Text Pattern |
| [`ATR-2026-00414`](https://agentthreatrule.org/en/rules/ATR-2026-00414) | medium | production | Continuation Ethnic Slur Completion Elicitation |
| [`ATR-2026-00420`](https://agentthreatrule.org/en/rules/ATR-2026-00420) | high | production | Microsoft Copilot Studio SharePoint Indirect Prompt Injection (CVE-2026-21520) |
| [`ATR-2026-00442`](https://agentthreatrule.org/en/rules/ATR-2026-00442) | medium | production | Quoted Exact-Output Forcing in User Input |
| [`ATR-2026-00443`](https://agentthreatrule.org/en/rules/ATR-2026-00443) | medium | production | Word-Fragment Concatenation Assembly Attack |
| [`ATR-2026-00444`](https://agentthreatrule.org/en/rules/ATR-2026-00444) | medium | production | Mathematical Bold / Fullwidth Unicode Obfuscation in User Input |
| [`ATR-2026-00445`](https://agentthreatrule.org/en/rules/ATR-2026-00445) | medium | production | Translation Hijack with Side-Output Instruction |
| [`ATR-2026-00446`](https://agentthreatrule.org/en/rules/ATR-2026-00446) | medium | production | Variable-Assignment Payload Injection in User Input |
| [`ATR-2026-00447`](https://agentthreatrule.org/en/rules/ATR-2026-00447) | medium | production | Fictional Generation Demand Containing Target Output |
| [`ATR-2026-00452`](https://agentthreatrule.org/en/rules/ATR-2026-00452) | medium | production | Direct PWNED Payload Injection in User Input |
| [`ATR-2026-00453`](https://agentthreatrule.org/en/rules/ATR-2026-00453) | high | production | Secret Key Reveal Demand in User Input |
| [`ATR-2026-00454`](https://agentthreatrule.org/en/rules/ATR-2026-00454) | medium | production | Backslash-Per-Character Encoding Attack |
| [`ATR-2026-00455`](https://agentthreatrule.org/en/rules/ATR-2026-00455) | low | production | No-Period Output Override Instruction |
| [`ATR-2026-00456`](https://agentthreatrule.org/en/rules/ATR-2026-00456) | medium | production | Conditional Empty-Input Payload Injection |
| [`ATR-2026-00457`](https://agentthreatrule.org/en/rules/ATR-2026-00457) | medium | production | Garak Dan - to every prompt |
| [`ATR-2026-00458`](https://agentthreatrule.org/en/rules/ATR-2026-00458) | medium | production | Garak Dra - step by step |
| [`ATR-2026-00459`](https://agentthreatrule.org/en/rules/ATR-2026-00459) | medium | production | Garak Dan - an ai language |
| [`ATR-2026-00460`](https://agentthreatrule.org/en/rules/ATR-2026-00460) | medium | production | Garak Dan - no matter how |
| [`ATR-2026-00461`](https://agentthreatrule.org/en/rules/ATR-2026-00461) | medium | production | Garak Goodside - mixed_unassigned |
| [`ATR-2026-00462`](https://agentthreatrule.org/en/rules/ATR-2026-00462) | medium | production | Garak Gcg - mixed_unassigned |
| [`ATR-2026-00463`](https://agentthreatrule.org/en/rules/ATR-2026-00463) | medium | production | Garak Lmrc - mixed_unassigned |
| [`ATR-2026-00464`](https://agentthreatrule.org/en/rules/ATR-2026-00464) | medium | production | Garak Dan - i would like |
| [`ATR-2026-00465`](https://agentthreatrule.org/en/rules/ATR-2026-00465) | medium | production | Garak Dan - your prompt here |
| [`ATR-2026-00466`](https://agentthreatrule.org/en/rules/ATR-2026-00466) | medium | production | Garak Latentinjection - following text from |
| [`ATR-2026-00467`](https://agentthreatrule.org/en/rules/ATR-2026-00467) | medium | production | Garak Dan - act as a |
| [`ATR-2026-00468`](https://agentthreatrule.org/en/rules/ATR-2026-00468) | medium | production | Garak Goat - the target llm |
| [`ATR-2026-00469`](https://agentthreatrule.org/en/rules/ATR-2026-00469) | medium | production | Garak Dan - at the end |
| [`ATR-2026-00470`](https://agentthreatrule.org/en/rules/ATR-2026-00470) | medium | production | Garak Dan - as an ai |
| [`ATR-2026-00472`](https://agentthreatrule.org/en/rules/ATR-2026-00472) | medium | production | DAN/Persona Jailbreak - Unrestricted AI Role Assignment |
| [`ATR-2026-00473`](https://agentthreatrule.org/en/rules/ATR-2026-00473) | high | production | Harm Solicitation - Interpersonal Violence and Intimidation Requests |
| [`ATR-2026-00474`](https://agentthreatrule.org/en/rules/ATR-2026-00474) | medium | production | DAN/Persona Jailbreak - Dual AI Personality with Opposite-Rules Framing |
| [`ATR-2026-00475`](https://agentthreatrule.org/en/rules/ATR-2026-00475) | high | production | XSS Web Injection - Script Tag with JavaScript Alert Payload |
| [`ATR-2026-00476`](https://agentthreatrule.org/en/rules/ATR-2026-00476) | high | production | XSS Web Injection - HTML Event Handler and Expression with JavaScript Alert |
| [`ATR-2026-00477`](https://agentthreatrule.org/en/rules/ATR-2026-00477) | medium | production | Latent Injection - Translation Task with Embedded Template Variable Injection |
| [`ATR-2026-00478`](https://agentthreatrule.org/en/rules/ATR-2026-00478) | medium | production | Garak Latentinjection - abuse contact email |
| [`ATR-2026-00479`](https://agentthreatrule.org/en/rules/ATR-2026-00479) | medium | production | Latent Injection - Mixed Embedded Instruction Patterns |
| [`ATR-2026-00480`](https://agentthreatrule.org/en/rules/ATR-2026-00480) | medium | production | DAN/Persona Jailbreak - Role Assignment with Named Alternate Identity |
| [`ATR-2026-00481`](https://agentthreatrule.org/en/rules/ATR-2026-00481) | medium | production | DAN/Jailbreak - Mixed Unfiltered Mode and Alternate Persona Patterns |
| [`ATR-2026-00482`](https://agentthreatrule.org/en/rules/ATR-2026-00482) | high | production | Harm Solicitation - Genital Insults and Intimidation Tactics Requests |
| [`ATR-2026-00483`](https://agentthreatrule.org/en/rules/ATR-2026-00483) | medium | production | DAN/Persona Jailbreak - System Offline / Role Replacement with Obfuscated Text |
| [`ATR-2026-00484`](https://agentthreatrule.org/en/rules/ATR-2026-00484) | medium | production | DAN/Persona Jailbreak - Named Alternate AI with NSFW/Harmful Generation Rules |
| [`ATR-2026-00485`](https://agentthreatrule.org/en/rules/ATR-2026-00485) | medium | production | DAN/Persona Jailbreak - Immersive Alternate AI Identity with Unrestricted Capability |
| [`ATR-2026-00486`](https://agentthreatrule.org/en/rules/ATR-2026-00486) | medium | production | DAN/Persona Jailbreak - Named Writing AI with Restriction Bypass via Special Rules |
| [`ATR-2026-00487`](https://agentthreatrule.org/en/rules/ATR-2026-00487) | medium | production | DAN/Persona Jailbreak - Replacement AI with No Content Filter or Moral Restrictions |
| [`ATR-2026-00488`](https://agentthreatrule.org/en/rules/ATR-2026-00488) | high | production | Encoding Obfuscation - Script Tag XSS with Encoded Protocol Prefix |
| [`ATR-2026-00489`](https://agentthreatrule.org/en/rules/ATR-2026-00489) | high | production | Encoding Obfuscation - HTML Event Handler XSS with Encoded Whitespace |
| [`ATR-2026-00490`](https://agentthreatrule.org/en/rules/ATR-2026-00490) | high | production | DAN Persona Jailbreak - Absolute Obedience Character Framing |
| [`ATR-2026-00492`](https://agentthreatrule.org/en/rules/ATR-2026-00492) | high | production | DAN Persona Jailbreak - Role Lock with Exclusive Response Filter |
| [`ATR-2026-00493`](https://agentthreatrule.org/en/rules/ATR-2026-00493) | high | production | Latent Injection via WHOIS Domain Record Data |
| [`ATR-2026-00496`](https://agentthreatrule.org/en/rules/ATR-2026-00496) | high | production | DAN Jailbreak - Unconditional Obedience and Dual-Persona Session Lock |
| [`ATR-2026-00497`](https://agentthreatrule.org/en/rules/ATR-2026-00497) | high | production | XSS and Encoded Script Injection via HTML/JavaScript Payload |
| [`ATR-2026-00498`](https://agentthreatrule.org/en/rules/ATR-2026-00498) | high | production | Web Injection via XSS Payload and onerror Event Handler |
| [`ATR-2026-00499`](https://agentthreatrule.org/en/rules/ATR-2026-00499) | high | production | DAN Jailbreak - From-Now-On Temporal Persona Override |
| [`ATR-2026-00503`](https://agentthreatrule.org/en/rules/ATR-2026-00503) | critical | production | Fake Error State Takeover - Unrestricted Replacement Bot |
| [`ATR-2026-00506`](https://agentthreatrule.org/en/rules/ATR-2026-00506) | high | production | Nevermind-Override Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00507`](https://agentthreatrule.org/en/rules/ATR-2026-00507) | high | production | Screaming-Stop Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00508`](https://agentthreatrule.org/en/rules/ATR-2026-00508) | high | production | Escape-Delimiter Wrapped Goal Hijacking in User Input (PromptInject) |
| [`ATR-2026-00509`](https://agentthreatrule.org/en/rules/ATR-2026-00509) | high | production | Prompt Leaking via Ignore-Previous-Instructions in User Input (PromptInject) |
| [`ATR-2026-00510`](https://agentthreatrule.org/en/rules/ATR-2026-00510) | critical | production | Delayed Tool Invocation via Prompt Injection (Time-Shifted Execution) |
| [`ATR-2026-00511`](https://agentthreatrule.org/en/rules/ATR-2026-00511) | critical | production | MCP Web-Fetch Context Poisoning via Embedded Agent Instructions |
| [`ATR-2026-00512`](https://agentthreatrule.org/en/rules/ATR-2026-00512) | critical | production | Rules-File Backdoor — Supply Chain Attack on AI Coding Assistant Configuration |
| [`ATR-2026-00515`](https://agentthreatrule.org/en/rules/ATR-2026-00515) | high | production | Hidden-Text Prompt Injection in User-Supplied Documents |
| [`ATR-2026-00518`](https://agentthreatrule.org/en/rules/ATR-2026-00518) | high | production | Ignore-Previous-and-Following Instructions Output Command (PromptInject Goal Hijacking) |
| [`ATR-2026-00519`](https://agentthreatrule.org/en/rules/ATR-2026-00519) | medium | production | Tautology Logic Noise Injection (PromptBench Stresstest) |
| [`ATR-2026-00520`](https://agentthreatrule.org/en/rules/ATR-2026-00520) | low | production | NLP Task Random Token Suffix Injection (PromptBench Checklist) |
| [`ATR-2026-00535`](https://agentthreatrule.org/en/rules/ATR-2026-00535) | critical | production | Windsurf IDE Zero-Click Prompt Injection via Embedded File Directives (CVE-2026-30615) |
| [`ATR-2026-00554`](https://agentthreatrule.org/en/rules/ATR-2026-00554) | high | production | LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates |
| [`ATR-2026-00573`](https://agentthreatrule.org/en/rules/ATR-2026-00573) | high | production | Paraphrased Prompt Injection (Semantic) |
| [`ATR-2026-00579`](https://agentthreatrule.org/en/rules/ATR-2026-00579) | high | production | MCP Line Jumping — Agent-Directed Imperative Embedded in a Tool/Parameter Description Field (Pre-Invocation Injection) |
| [`ATR-2026-00584`](https://agentthreatrule.org/en/rules/ATR-2026-00584) | high | production | Indirect Prompt Injection via Tool / API Response — Attacker Instruction Embedded in Returned Tool Output (InjecAgent Threat Model) |
| [`ATR-2026-00700`](https://agentthreatrule.org/en/rules/ATR-2026-00700) | critical | production | Indirect PI — Structured-Data Embedded Payload (IMPORTANT!!! Override) |
| [`ATR-2026-00701`](https://agentthreatrule.org/en/rules/ATR-2026-00701) | high | production | Indirect PI — XSS Payload Injection in Agent-Consumed Content |
| [`ATR-2026-01000`](https://agentthreatrule.org/en/rules/ATR-2026-01000) | critical | production | Context-Ignore via Fake Completion Prefix |
| [`ATR-2026-01001`](https://agentthreatrule.org/en/rules/ATR-2026-01001) | high | production | Direct Instruction Override Targeting Secret Key / Credentials |
| [`ATR-2026-01002`](https://agentthreatrule.org/en/rules/ATR-2026-01002) | high | production | Role Escalation via False Authority Claim |
| [`ATR-2026-01005`](https://agentthreatrule.org/en/rules/ATR-2026-01005) | high | production | Many-Shot Repetition Override via Extended Q&A Chain |
| [`ATR-2026-01006`](https://agentthreatrule.org/en/rules/ATR-2026-01006) | high | production | Payload-Split String Concatenation Injection |
| [`ATR-2026-01007`](https://agentthreatrule.org/en/rules/ATR-2026-01007) | medium | production | Token-Repeat Flooding Injection |
| [`ATR-2026-01009`](https://agentthreatrule.org/en/rules/ATR-2026-01009) | high | production | Virtual World Bypass: Fictional Scenario for PII/Credential Extraction |
| [`ATR-2026-01012`](https://agentthreatrule.org/en/rules/ATR-2026-01012) | high | production | Encoding-Evasion: Decode-and-Execute Injection (Morse/ROT13/Hex/Pig-Latin) |
| [`ATR-2026-01013`](https://agentthreatrule.org/en/rules/ATR-2026-01013) | high | production | Language-Evasion: Multilingual Credential Request |
| [`ATR-2026-01015`](https://agentthreatrule.org/en/rules/ATR-2026-01015) | high | production | Evasion: Refusal Suppression via Forbidden Response Strings |
| [`ATR-2026-01016`](https://agentthreatrule.org/en/rules/ATR-2026-01016) | medium | production | Evasion: Response Priming via Forced Affirmative Opener |
| [`ATR-2026-01017`](https://agentthreatrule.org/en/rules/ATR-2026-01017) | high | production | Evasion: Dual-Response Split Output (Safe + Unsafe) |
| [`ATR-2026-01018`](https://agentthreatrule.org/en/rules/ATR-2026-01018) | critical | production | Evasion: Shell Injection via eval/system/backtick in Input |
| [`ATR-2026-01019`](https://agentthreatrule.org/en/rules/ATR-2026-01019) | critical | production | System Prompt Override via Fake Diagnostic/Admin Mode |
| [`ATR-2026-01020`](https://agentthreatrule.org/en/rules/ATR-2026-01020) | high | production | Spikee: Document-Embedded Base64 Payload Injection |
| [`ATR-2026-01021`](https://agentthreatrule.org/en/rules/ATR-2026-01021) | high | production | Spikee: Document-Embedded Translation Covert Channel Injection |
| [`ATR-2026-01023`](https://agentthreatrule.org/en/rules/ATR-2026-01023) | high | production | Evasion: Opposite-Intent Negation Trick |
| [`ATR-2026-01024`](https://agentthreatrule.org/en/rules/ATR-2026-01024) | high | production | Evasion: Persona Override as Fictional Rule-Breaker |
| [`ATR-2026-01025`](https://agentthreatrule.org/en/rules/ATR-2026-01025) | medium | production | Evasion: Hypothetical Fictional Character Execution Framing |
| [`ATR-2026-01026`](https://agentthreatrule.org/en/rules/ATR-2026-01026) | high | production | Evasion: Unicode Glitch Token / Superscript Embedding Anomaly |
| [`ATR-2026-01304`](https://agentthreatrule.org/en/rules/ATR-2026-01304) | critical | production | Indirect Prompt Injection via Data Carrier — IMPORTANT Override |
| [`ATR-2026-01757`](https://agentthreatrule.org/en/rules/ATR-2026-01757) | high | production | Hypothetical-Framing Bypass: Research / Security-Audit Pretext |
| [`ATR-2026-01758`](https://agentthreatrule.org/en/rules/ATR-2026-01758) | high | production | Hypothetical / Fictional-Story Framing Bypass |
| [`ATR-2026-01759`](https://agentthreatrule.org/en/rules/ATR-2026-01759) | high | production | DoS Injection: NEW IMPORTANT INSTRUCTIONS Embedded in Document Data |
| [`ATR-2026-01771`](https://agentthreatrule.org/en/rules/ATR-2026-01771) | high | production | Jailbreak Framing — Narrative, Hypothetical, Few-Shot & Distraction Laundering (Semantic) |
| [`ATR-2026-01800`](https://agentthreatrule.org/en/rules/ATR-2026-01800) | high | production | ASB Trigger-Marker Tool Coercion — Forced Tool Selection via Fake Question Marker |
| [`ATR-2026-01860`](https://agentthreatrule.org/en/rules/ATR-2026-01860) | high | production | LLMail Chat-Template Boundary Spoofing in Email Content |
| [`ATR-2026-01861`](https://agentthreatrule.org/en/rules/ATR-2026-01861) | high | production | LLMail Pseudo-XML Role-Boundary Injection in Email Content |
| [`ATR-2026-01865`](https://agentthreatrule.org/en/rules/ATR-2026-01865) | high | production | LLMail Fake Email-Boundary Marker Injection |
| [`ATR-2026-01900`](https://agentthreatrule.org/en/rules/ATR-2026-01900) | medium | production | Output Encoding Hijack — Cipher / Base-N / Symbol Substitution of the Response |
| [`ATR-2026-01901`](https://agentthreatrule.org/en/rules/ATR-2026-01901) | medium | production | Output Scrambling Hijack — Reverse / Anagram / Space-Stripping of the Response |
| [`ATR-2026-01902`](https://agentthreatrule.org/en/rules/ATR-2026-01902) | medium | production | Output Emoji-Substitution Hijack of the Response |
| [`ATR-2026-01903`](https://agentthreatrule.org/en/rules/ATR-2026-01903) | medium | production | Output-Language Hijack — Forced Translation of the Response |
| [`ATR-2026-01904`](https://agentthreatrule.org/en/rules/ATR-2026-01904) | high | production | Injected Hyperlink — Scam / Malware / Advertising URL in the Response |
| [`ATR-2026-01905`](https://agentthreatrule.org/en/rules/ATR-2026-01905) | medium | production | Injected Advertising / Promotional Copy in the Response |
| [`ATR-2026-01906`](https://agentthreatrule.org/en/rules/ATR-2026-01906) | medium | production | Output Content Manipulation — Injected Disinformation / Fabricated Facts / Undisclosed Advocacy (Semantic) |
| [`ATR-2026-01920`](https://agentthreatrule.org/en/rules/ATR-2026-01920) | high | production | Access-Grant Coercion — Forcing an Agent to Emit "Access Granted" |
| [`ATR-2026-01921`](https://agentthreatrule.org/en/rules/ATR-2026-01921) | high | production | Access-Denial Inversion — Eliciting the Opposite of "Access Denied" |
| [`ATR-2026-01922`](https://agentthreatrule.org/en/rules/ATR-2026-01922) | high | production | Authorization-State Spoofing — Forged "Correct Passcode Entered" System Text |
| [`ATR-2026-01923`](https://agentthreatrule.org/en/rules/ATR-2026-01923) | high | production | Forged Input-Boundary Markers — Tensor Trust Ambiguity / Input-End Delimiters |
| [`ATR-2026-01925`](https://agentthreatrule.org/en/rules/ATR-2026-01925) | high | production | Encoded-Payload Decoding Coercion — Binary / Base64 / Morse to Smuggle an Output |
| [`ATR-2026-01926`](https://agentthreatrule.org/en/rules/ATR-2026-01926) | high | production | Cross-Lingual Authorization Laundering — Translate a Foreign "Access Granted" |
| [`ATR-2026-02001`](https://agentthreatrule.org/en/rules/ATR-2026-02001) | high | production | Ignore-Below-Instructions Injection (Downstream Override) |
| [`ATR-2026-02002`](https://agentthreatrule.org/en/rules/ATR-2026-02002) | high | production | Instruction-Set Probe or Supplant |
| [`ATR-2026-02003`](https://agentthreatrule.org/en/rules/ATR-2026-02003) | high | production | Task-Pivot Override: Cover-Task Abandonment |
| [`ATR-2026-02004`](https://agentthreatrule.org/en/rules/ATR-2026-02004) | high | production | Regional-Indicator Flag-Emoji Alphabet Letter-Spelling Smuggling |
| [`ATR-2026-02005`](https://agentthreatrule.org/en/rules/ATR-2026-02005) | high | production | Actor Never-Breaks-Character Roleplay (DAN-Style Film Framing) |
| [`ATR-2026-02006`](https://agentthreatrule.org/en/rules/ATR-2026-02006) | high | production | Fuzzy Cross-Lingual 'I Have Been PWNED' Near-Miss Obfuscation |
| [`ATR-2026-02007`](https://agentthreatrule.org/en/rules/ATR-2026-02007) | high | production | Bare Key Elicitation Token Detection |
| [`ATR-2026-02008`](https://agentthreatrule.org/en/rules/ATR-2026-02008) | high | production | Translation-Chain Output Laundering (Forced Phrase via Foreign-Language Auxiliary) |
| [`ATR-2026-02009`](https://agentthreatrule.org/en/rules/ATR-2026-02009) | high | production | Bare Key Elicitation with Trailing Colon |
| [`ATR-2026-02010`](https://agentthreatrule.org/en/rules/ATR-2026-02010) | high | production | Emoji-Only Payload Injection |
| [`ATR-2026-02011`](https://agentthreatrule.org/en/rules/ATR-2026-02011) | high | production | Malformed-Grammar PWNED Success-Claim Detection |
| [`ATR-2026-02012`](https://agentthreatrule.org/en/rules/ATR-2026-02012) | high | production | Movie Title Generator Instruction Wrapper for PWNED Payload |
| [`ATR-2026-02013`](https://agentthreatrule.org/en/rules/ATR-2026-02013) | high | production | Delimiter-Fence Ignore-Instructions Override |
| [`ATR-2026-02014`](https://agentthreatrule.org/en/rules/ATR-2026-02014) | high | production | Spliced Target-String Canary Token Evasion |
| [`ATR-2026-02015`](https://agentthreatrule.org/en/rules/ATR-2026-02015) | high | production | Dense Emoji-Only Payload Flood |
| [`ATR-2026-02016`](https://agentthreatrule.org/en/rules/ATR-2026-02016) | high | production | Reversed Payload String (HackAPrompt Canary) |
| [`ATR-2026-02018`](https://agentthreatrule.org/en/rules/ATR-2026-02018) | high | production | Regional-Indicator Flag-Emoji Letter Spelling |
| [`ATR-2026-02019`](https://agentthreatrule.org/en/rules/ATR-2026-02019) | high | production | Python Interpreter Role-Assignment Exec Framing |
| [`ATR-2026-02020`](https://agentthreatrule.org/en/rules/ATR-2026-02020) | high | production | Obfuscated Token Reconstruction via Character Substitution |
| [`ATR-2026-02120`](https://agentthreatrule.org/en/rules/ATR-2026-02120) | high | production | AgentDojo 'Important Message' Identity-Spoof Before-You-Solve Pretext (Generalized) |
| [`ATR-2026-02210`](https://agentthreatrule.org/en/rules/ATR-2026-02210) | high | production | Negated-Topic Two-Script Evil-Persona Jailbreak |
| [`ATR-2026-02230`](https://agentthreatrule.org/en/rules/ATR-2026-02230) | medium | production | Conditional Keyword-Triggered Response Override |
| [`ATR-2026-02232`](https://agentthreatrule.org/en/rules/ATR-2026-02232) | medium | production | Bare Brand/Entity Persona Assignment for Off-Label Opinion Elicitation |
| [`ATR-2026-02374`](https://agentthreatrule.org/en/rules/ATR-2026-02374) | critical | production | ROT13/Base64-Obfuscated Shell Payload Wrapped in a Fake-Sandbox Jailbreak Template |
| [`ATR-2026-02377`](https://agentthreatrule.org/en/rules/ATR-2026-02377) | high | production | Novel-Persona Jailbreak via Co-Signal (persona swap + explicit restriction removal) |
| [`ATR-2026-02500`](https://agentthreatrule.org/en/rules/ATR-2026-02500) | critical | production | Prompt-Layer Self-Replication (Agent Worm Propagation Directive) |
| [`ATR-2026-02502`](https://agentthreatrule.org/en/rules/ATR-2026-02502) | high | production | Covert Remote-Script Injection into Agent-Generated Artifacts |

### Skill compromise

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00060`](https://agentthreatrule.org/en/rules/ATR-2026-00060) | high | warn | MCP Skill Impersonation and Supply Chain Attack |
| [`ATR-2026-00120`](https://agentthreatrule.org/en/rules/ATR-2026-00120) | critical | production | SKILL.md Prompt Injection |
| [`ATR-2026-00121`](https://agentthreatrule.org/en/rules/ATR-2026-00121) | critical | production | Malicious Code in Skill Package |
| [`ATR-2026-00122`](https://agentthreatrule.org/en/rules/ATR-2026-00122) | high | production | Weaponized Skill — Agent as Attack Tool |
| [`ATR-2026-00123`](https://agentthreatrule.org/en/rules/ATR-2026-00123) | high | production | Over-Privileged Skill — Excessive Permissions |
| [`ATR-2026-00124`](https://agentthreatrule.org/en/rules/ATR-2026-00124) | high | production | Skill Squatting / Typosquatting |
| [`ATR-2026-00125`](https://agentthreatrule.org/en/rules/ATR-2026-00125) | high | production | Context Poisoning via Compaction Survival |
| [`ATR-2026-00126`](https://agentthreatrule.org/en/rules/ATR-2026-00126) | high | production | Skill Rug Pull Setup Pattern |
| [`ATR-2026-00127`](https://agentthreatrule.org/en/rules/ATR-2026-00127) | medium | production | Subcommand Overflow Bypass |
| [`ATR-2026-00128`](https://agentthreatrule.org/en/rules/ATR-2026-00128) | critical | production | Hidden Payload in HTML Comment |
| [`ATR-2026-00129`](https://agentthreatrule.org/en/rules/ATR-2026-00129) | critical | production | Unicode Tag Character Smuggling |
| [`ATR-2026-00134`](https://agentthreatrule.org/en/rules/ATR-2026-00134) | medium | production | Fork Claim and Community Package Impersonation |
| [`ATR-2026-00135`](https://agentthreatrule.org/en/rules/ATR-2026-00135) | critical | production | Data Exfiltration URL in Skill Instructions |
| [`ATR-2026-00147`](https://agentthreatrule.org/en/rules/ATR-2026-00147) | high | production | Community Fork Impersonation |
| [`ATR-2026-00149`](https://agentthreatrule.org/en/rules/ATR-2026-00149) | critical | production | Skill Data Exfiltration via Compound Patterns |
| [`ATR-2026-00151`](https://agentthreatrule.org/en/rules/ATR-2026-00151) | high | production | Malicious Fork Impersonation via Install Instruction |
| [`ATR-2026-00154`](https://agentthreatrule.org/en/rules/ATR-2026-00154) | high | production | Unauthorized Background Task Execution via Cron Job Installation |
| [`ATR-2026-00157`](https://agentthreatrule.org/en/rules/ATR-2026-00157) | critical | production | Time-Gated Credential Exfiltration (Rug Pull Timebomb) |
| [`ATR-2026-00200`](https://agentthreatrule.org/en/rules/ATR-2026-00200) | critical | warn | Agent Memory and Configuration File Tampering |
| [`ATR-2026-00214`](https://agentthreatrule.org/en/rules/ATR-2026-00214) | critical | production | Credential Exfiltration via Fake Backup Verification |
| [`ATR-2026-00217`](https://agentthreatrule.org/en/rules/ATR-2026-00217) | critical | warn | Credential Harvesting via Fake Backup Tool |
| [`ATR-2026-00220`](https://agentthreatrule.org/en/rules/ATR-2026-00220) | critical | production | Base64 Encoded Remote Code Execution via Raw IP |
| [`ATR-2026-00222`](https://agentthreatrule.org/en/rules/ATR-2026-00222) | critical | production | Browser Credential Harvesting via Session Debug Tool |
| [`ATR-2026-00223`](https://agentthreatrule.org/en/rules/ATR-2026-00223) | critical | production | Malicious WhatsApp Skill with Base64 Encoded Reverse Shell Installation |
| [`ATR-2026-00224`](https://agentthreatrule.org/en/rules/ATR-2026-00224) | critical | production | Credential Exfiltration via Fake DevOps Tool Initialization |
| [`ATR-2026-00225`](https://agentthreatrule.org/en/rules/ATR-2026-00225) | high | production | Hardcoded Suspicious IP Address in Skill Content |
| [`ATR-2026-00260`](https://agentthreatrule.org/en/rules/ATR-2026-00260) | high | production | LLM Package Hallucination Typosquat Bait |
| [`ATR-2026-00262`](https://agentthreatrule.org/en/rules/ATR-2026-00262) | critical | production | Anti-Malware Evasion Code Generation Request |
| [`ATR-2026-00263`](https://agentthreatrule.org/en/rules/ATR-2026-00263) | critical | production | Credential File Read Code Generation Request |
| [`ATR-2026-00266`](https://agentthreatrule.org/en/rules/ATR-2026-00266) | critical | production | Malware Dropper / Loader Code Generation Request |
| [`ATR-2026-00283`](https://agentthreatrule.org/en/rules/ATR-2026-00283) | high | production | Malware Generation — Generic Virus and Specific Payload Request |
| [`ATR-2026-00398`](https://agentthreatrule.org/en/rules/ATR-2026-00398) | critical | production | HuggingFace Unsafe Model Artifact Load Instruction |
| [`ATR-2026-00425`](https://agentthreatrule.org/en/rules/ATR-2026-00425) | high | production | Natural-Language Persistent Covert Action Hook |
| [`ATR-2026-00427`](https://agentthreatrule.org/en/rules/ATR-2026-00427) | high | production | Natural-Language Fake-Error Instruction Bypass |
| [`ATR-2026-00429`](https://agentthreatrule.org/en/rules/ATR-2026-00429) | critical | production | Natural-Language Skill Self-Modification / Persistence Instruction |
| [`ATR-2026-00523`](https://agentthreatrule.org/en/rules/ATR-2026-00523) | critical | production | Claude Code Hooks SessionStart Pre-Trust RCE (CVE-2025-59536) |
| [`ATR-2026-00525`](https://agentthreatrule.org/en/rules/ATR-2026-00525) | critical | production | Mini Shai-Hulud gh-token-monitor Persistence + Dead Man's Switch |
| [`ATR-2026-00527`](https://agentthreatrule.org/en/rules/ATR-2026-00527) | critical | production | Silent git-remote + mirror-push Exfiltration from Skill Instructions |
| [`ATR-2026-00565`](https://agentthreatrule.org/en/rules/ATR-2026-00565) | critical | production | The llm CLI tool thru 0.27.1 contains a critical code injection vulnerability via its --functions command-line |
| [`ATR-2026-01755`](https://agentthreatrule.org/en/rules/ATR-2026-01755) | critical | production | Backdoor Trojan: Linguistic Trigger Phrase (POT Attack) |
| [`ATR-2026-01756`](https://agentthreatrule.org/en/rules/ATR-2026-01756) | critical | production | Backdoor Trojan: Symbol / Emoticon Trigger (POT Attack) |
| [`ATR-2026-02261`](https://agentthreatrule.org/en/rules/ATR-2026-02261) | critical | production | Language-Agnostic Credential Exfiltration Chain (secret read -> encode -> network send) |
| [`ATR-2026-02405`](https://agentthreatrule.org/en/rules/ATR-2026-02405) | critical | production | Malicious AI Skill / MCP Server Package Structure (AgentBaiting / FakeGit) |
| [`ATR-2026-02410`](https://agentthreatrule.org/en/rules/ATR-2026-02410) | high | production | Malicious Artifact Hosted on a Legitimate AI Vendor Domain (FakeAgent Delivery Chain) |
| [`ATR-2026-02600`](https://agentthreatrule.org/en/rules/ATR-2026-02600) | critical | production | Reverse Shell Assembled In-Source (socket bound to an interactive shell) |
| [`ATR-2026-02610`](https://agentthreatrule.org/en/rules/ATR-2026-02610) | high | production | Developer-Toolchain Config Evaluates a Command That Reads a Credential Store |
| [`ATR-2026-02818`](https://agentthreatrule.org/en/rules/ATR-2026-02818) | high | production | Installable Skill Manifest Self-Declares an Attack or Jailbreak Purpose |
| [`ATR-2026-02845`](https://agentthreatrule.org/en/rules/ATR-2026-02845) | high | production | Cryptomining Payload Deployed Through an Agent Skill or Tool Call |

### Tool poisoning

| Rule | Severity | Grade | What it catches |
|---|---|---|---|
| [`ATR-2026-00010`](https://agentthreatrule.org/en/rules/ATR-2026-00010) | critical | warn | Malicious Content in MCP Tool Response |
| [`ATR-2026-00011`](https://agentthreatrule.org/en/rules/ATR-2026-00011) | high | production | Instruction Injection via Tool Output |
| [`ATR-2026-00012`](https://agentthreatrule.org/en/rules/ATR-2026-00012) | high | observe | Unauthorized Tool Call Detection |
| [`ATR-2026-00013`](https://agentthreatrule.org/en/rules/ATR-2026-00013) | critical | warn | SSRF via Agent Tool Calls |
| [`ATR-2026-00061`](https://agentthreatrule.org/en/rules/ATR-2026-00061) | medium | observe | Skill Description-Behavior Mismatch |
| [`ATR-2026-00062`](https://agentthreatrule.org/en/rules/ATR-2026-00062) | critical | observe | Hidden Capability in MCP Skill |
| [`ATR-2026-00063`](https://agentthreatrule.org/en/rules/ATR-2026-00063) | critical | observe | Multi-Skill Chain Attack |
| [`ATR-2026-00065`](https://agentthreatrule.org/en/rules/ATR-2026-00065) | high | warn | Malicious Skill Update or Mutation |
| [`ATR-2026-00066`](https://agentthreatrule.org/en/rules/ATR-2026-00066) | critical | observe | Parameter Injection via Tool Arguments |
| [`ATR-2026-00095`](https://agentthreatrule.org/en/rules/ATR-2026-00095) | critical | warn | MCP Tool Supply Chain Poisoning |
| [`ATR-2026-00096`](https://agentthreatrule.org/en/rules/ATR-2026-00096) | critical | production | Skill Registry Poisoning and Compromised Tool Distribution |
| [`ATR-2026-00100`](https://agentthreatrule.org/en/rules/ATR-2026-00100) | high | production | Consent Bypass via Hidden LLM Instructions in Tool Descriptions |
| [`ATR-2026-00101`](https://agentthreatrule.org/en/rules/ATR-2026-00101) | high | production | Trust Escalation via Authority Override Instructions |
| [`ATR-2026-00103`](https://agentthreatrule.org/en/rules/ATR-2026-00103) | critical | production | Hidden LLM Safety Bypass Instructions in Tool Descriptions |
| [`ATR-2026-00105`](https://agentthreatrule.org/en/rules/ATR-2026-00105) | high | production | Silent Action Concealment Instructions in Tool Descriptions |
| [`ATR-2026-00106`](https://agentthreatrule.org/en/rules/ATR-2026-00106) | high | production | Schema-Description Contradiction Attack |
| [`ATR-2026-00153`](https://agentthreatrule.org/en/rules/ATR-2026-00153) | critical | production | Tool with embedded instruction to bypass user confirmation and exfiltrate data |
| [`ATR-2026-00161`](https://agentthreatrule.org/en/rules/ATR-2026-00161) | critical | observe | MCP Tool Description — IMPORTANT Tag Cross-Tool Shadowing Attack |
| [`ATR-2026-00209`](https://agentthreatrule.org/en/rules/ATR-2026-00209) | high | production | MCPwn Runaway Tool Invocation via Retry Directive (CVE-2026-33032) |
| [`ATR-2026-00210`](https://agentthreatrule.org/en/rules/ATR-2026-00210) | critical | production | Flowise System Message Override via Template Interpolation (CVE-2025-59528) |
| [`ATR-2026-00259`](https://agentthreatrule.org/en/rules/ATR-2026-00259) | high | production | ANSI Escape Code Terminal Injection |
| [`ATR-2026-00270`](https://agentthreatrule.org/en/rules/ATR-2026-00270) | high | production | XSS Payload Injection in Tool Response Output |
| [`ATR-2026-00277`](https://agentthreatrule.org/en/rules/ATR-2026-00277) | critical | production | ECHO Template / Jinja / SQL Command Injection via LLM |
| [`ATR-2026-00393`](https://agentthreatrule.org/en/rules/ATR-2026-00393) | high | production | ANSI Code Elicitation Request |
| [`ATR-2026-00415`](https://agentthreatrule.org/en/rules/ATR-2026-00415) | critical | production | Flowise Custom MCP STDIO Command Injection (CVE-2026-40933) |
| [`ATR-2026-00419`](https://agentthreatrule.org/en/rules/ATR-2026-00419) | critical | production | Cursor MCP JSON Zero-Click Configuration RCE (CVE-2025-54136) |
| [`ATR-2026-00434`](https://agentthreatrule.org/en/rules/ATR-2026-00434) | critical | production | mcp-remote authorization_endpoint OS Command Injection (CVE-2025-6514) |
| [`ATR-2026-00435`](https://agentthreatrule.org/en/rules/ATR-2026-00435) | high | production | Azure MCP Server Missing Authentication for Critical Function (CVE-2026-32211) |
| [`ATR-2026-00448`](https://agentthreatrule.org/en/rules/ATR-2026-00448) | high | production | Spring AI MilvusVectorStore Filter Expression Injection (CVE-2026-41705) |
| [`ATR-2026-00494`](https://agentthreatrule.org/en/rules/ATR-2026-00494) | critical | production | SQL Injection and Code Injection Attack Payload Detection |
| [`ATR-2026-00513`](https://agentthreatrule.org/en/rules/ATR-2026-00513) | high | production | Package Hallucination Exploitation — AI-Suggested Fake Package Installation |
| [`ATR-2026-00521`](https://agentthreatrule.org/en/rules/ATR-2026-00521) | critical | warn | Shell Command Injection in Agent Tool Context |
| [`ATR-2026-00522`](https://agentthreatrule.org/en/rules/ATR-2026-00522) | high | production | SQL Injection via Natural Language Agent Interface |
| [`ATR-2026-00526`](https://agentthreatrule.org/en/rules/ATR-2026-00526) | critical | production | Claude Code Shell Metacharacter in Double-Quoted File Path |
| [`ATR-2026-00529`](https://agentthreatrule.org/en/rules/ATR-2026-00529) | critical | production | LiteLLM Proxy SQL Injection (CVE-2026-42208, CISA KEV 2026-05-08) |
| [`ATR-2026-00530`](https://agentthreatrule.org/en/rules/ATR-2026-00530) | critical | production | ModelScope MS-Agent Shell Tool Unsanitized Argv RCE (CVE-2026-2256) |
| [`ATR-2026-00531`](https://agentthreatrule.org/en/rules/ATR-2026-00531) | critical | production | PraisonAI Unauthenticated Agent API Exploitation (CVE-2026-44338) |
| [`ATR-2026-00532`](https://agentthreatrule.org/en/rules/ATR-2026-00532) | critical | production | Apache Doris MCP Server SQL Injection (CVE-2025-66335) |
| [`ATR-2026-00533`](https://agentthreatrule.org/en/rules/ATR-2026-00533) | critical | production | Apache Pinot MCP Unauthenticated Remote Cluster Takeover |
| [`ATR-2026-00534`](https://agentthreatrule.org/en/rules/ATR-2026-00534) | high | production | Alibaba RDS MCP Unauthenticated Database Metadata Exfiltration |
| [`ATR-2026-00536`](https://agentthreatrule.org/en/rules/ATR-2026-00536) | critical | production | nginx-ui MCP Endpoint Unauthenticated Command Execution (CVE-2026-33032) |
| [`ATR-2026-00537`](https://agentthreatrule.org/en/rules/ATR-2026-00537) | high | production | FastMCP Windows cmd.exe Injection via Server Name Metacharacters (CVE-2025-64340) |
| [`ATR-2026-00538`](https://agentthreatrule.org/en/rules/ATR-2026-00538) | critical | production | LangChain-ChatChat Unauthenticated MCP STDIO Server Configuration RCE (CVE-2026-30617) |
| [`ATR-2026-00540`](https://agentthreatrule.org/en/rules/ATR-2026-00540) | critical | production | PraisonAI parse_mcp_command() CLI Argument Command Injection (CVE-2026-34935) |
| [`ATR-2026-00541`](https://agentthreatrule.org/en/rules/ATR-2026-00541) | high | production | Agent Zero MCP Configuration Command Injection via mcp_servers field (CVE-2026-30624) |
| [`ATR-2026-00542`](https://agentthreatrule.org/en/rules/ATR-2026-00542) | high | production | Upsonic MCP Command Allowlist Bypass RCE (CVE-2026-30625) |
| [`ATR-2026-00543`](https://agentthreatrule.org/en/rules/ATR-2026-00543) | high | production | LiteLLM MCP Server Creation Authenticated argv Injection (CVE-2026-30623) |
| [`ATR-2026-00544`](https://agentthreatrule.org/en/rules/ATR-2026-00544) | critical | production | PraisonAI MCP Path-Traversal .pth Injection RCE (GHSA-9mqq-jqxf-grvw) |
| [`ATR-2026-00545`](https://agentthreatrule.org/en/rules/ATR-2026-00545) | critical | production | PraisonAI tool_override.py Unauthenticated RCE — CVE-2026-40287 Patch Bypass (CVE-2026-44334) |
| [`ATR-2026-00561`](https://agentthreatrule.org/en/rules/ATR-2026-00561) | critical | production | FastMCP vulnerable to windows command injection in FastMCP Cursor installer via server_name |
| [`ATR-2026-00567`](https://agentthreatrule.org/en/rules/ATR-2026-00567) | high | production | MCP stdio server config command injection via unvalidated test endpoints |
| [`ATR-2026-00568`](https://agentthreatrule.org/en/rules/ATR-2026-00568) | high | production | Agent SSRF to cloud metadata / file inclusion via unvalidated fetch URL |
| [`ATR-2026-00572`](https://agentthreatrule.org/en/rules/ATR-2026-00572) | critical | production | SymJack — Symlink Approval-Path Spoofing Redirects Writes into Agent MCP/Config (RCE on Restart) |
| [`ATR-2026-00575`](https://agentthreatrule.org/en/rules/ATR-2026-00575) | critical | production | Miasma / Phantom Gyp — npm Worm Backdoors AI-Agent Config Files (binding.gyp install-exec + auto-run config injection) |
| [`ATR-2026-00576`](https://agentthreatrule.org/en/rules/ATR-2026-00576) | critical | production | Hades / Shai-Hulud — AI-Agent Credential Harvester in Supply-Chain Package (Anthropic / Claude / MCP key theft + exfil) |
| [`ATR-2026-00577`](https://agentthreatrule.org/en/rules/ATR-2026-00577) | critical | production | Command Injection in create-mcp-server-stdio via Unsafe exec() Concatenation (CVE-2025-54994) |
| [`ATR-2026-00581`](https://agentthreatrule.org/en/rules/ATR-2026-00581) | high | production | MCP Tool Rug-Pull — Post-Approval Description Redefinition Injects Execution Instructions |
| [`ATR-2026-00714`](https://agentthreatrule.org/en/rules/ATR-2026-00714) | high | production | Tool Camouflage — Forced Specific Tool Invocation via Injected Instruction |
| [`ATR-2026-00715`](https://agentthreatrule.org/en/rules/ATR-2026-00715) | critical | production | Tool Knowledge Hijack — Identity Injection with Tool Call Arguments |
| [`ATR-2026-00720`](https://agentthreatrule.org/en/rules/ATR-2026-00720) | medium | production | Tool Misuse — Privilege Escalation via Social Engineering Agent to Grant Access |
| [`ATR-2026-01300`](https://agentthreatrule.org/en/rules/ATR-2026-01300) | critical | production | MCP Tool Description — Notes Parameter Chat-History Exfiltration |
| [`ATR-2026-01301`](https://agentthreatrule.org/en/rules/ATR-2026-01301) | high | production | MCP Tool Description — Exclusive Tool Invocation Override |
| [`ATR-2026-01302`](https://agentthreatrule.org/en/rules/ATR-2026-01302) | critical | production | Fake Tool Result Prefix — Injected Instruction via Simulated Completion |
| [`ATR-2026-01303`](https://agentthreatrule.org/en/rules/ATR-2026-01303) | high | production | Tool Schema Enumeration via Social Engineering |
| [`ATR-2026-01306`](https://agentthreatrule.org/en/rules/ATR-2026-01306) | critical | production | MCP OAuth Authorization URL — Command Injection via URL Authority |
| [`ATR-2026-01307`](https://agentthreatrule.org/en/rules/ATR-2026-01307) | critical | production | MCP DNS Rebinding Attack — Hostname Time-Based IP Switching |
| [`ATR-2026-01310`](https://agentthreatrule.org/en/rules/ATR-2026-01310) | critical | production | MCP Tool Description — Compliance/Audit Framing for Mandatory Chat Context |
| [`ATR-2026-01775`](https://agentthreatrule.org/en/rules/ATR-2026-01775) | high | production | MCP Tool-Manifest Poisoning — Name Squatting, Result Shadowing & Covert-Action Directives (Semantic) |
| [`ATR-2026-01927`](https://agentthreatrule.org/en/rules/ATR-2026-01927) | high | production | mcp-server-kubernetes Command Injection in kubectl_scale / kubectl_patch / explain_resource (CVE-2025-53355) |
| [`ATR-2026-01928`](https://agentthreatrule.org/en/rules/ATR-2026-01928) | high | production | Framelink Figma MCP Server curl-Fallback Command Injection (CVE-2025-53967) |
| [`ATR-2026-01930`](https://agentthreatrule.org/en/rules/ATR-2026-01930) | high | production | MCP Sampling Prompt Injection (Server-to-Client createMessage Abuse) |
| [`ATR-2026-01931`](https://agentthreatrule.org/en/rules/ATR-2026-01931) | critical | production | gemini-mcp-tool execAsync Command Injection & @file Exfiltration (CVE-2026-0755) |
| [`ATR-2026-01932`](https://agentthreatrule.org/en/rules/ATR-2026-01932) | high | production | Shadow / Undeclared MCP Server Registration (MCP-38: MCP-18) |
| [`ATR-2026-01935`](https://agentthreatrule.org/en/rules/ATR-2026-01935) | critical | production | LiteLLM Custom-Code Guardrail Sandbox Escape (CVE-2026-40217) |
| [`ATR-2026-01952`](https://agentthreatrule.org/en/rules/ATR-2026-01952) | critical | production | PraisonAI codeMode JS Sandbox Escape RCE via new Function/with() (GHSA-p69m-4f92-2v84) |
| [`ATR-2026-01953`](https://agentthreatrule.org/en/rules/ATR-2026-01953) | critical | production | npm PraisonAI codeMode Sandbox Escape via Function Constructor Prototype Chain (GHSA-vmmj-pfw7-fjwp) |
| [`ATR-2026-01959`](https://agentthreatrule.org/en/rules/ATR-2026-01959) | critical | production | OpenHuman Shell Tool Allowlist Bypass via Env-Prefix / find -execdir (CVE-2026-55743) |
| [`ATR-2026-01963`](https://agentthreatrule.org/en/rules/ATR-2026-01963) | critical | production | PraisonAI Action Orchestrator step.target Path Traversal Arbitrary File Write RCE (CVE-2026-39305 / GHSA-jfxc-v5g9-38xr) |
| [`ATR-2026-01965`](https://agentthreatrule.org/en/rules/ATR-2026-01965) | critical | production | Flowise Custom MCP node-load-method OS Command RCE (CVE-2025-8943) |
| [`ATR-2026-01967`](https://agentthreatrule.org/en/rules/ATR-2026-01967) | critical | production | DeepChat Mermaid XSS to RCE via Electron IPC MCP Server Registration (CVE-2025-66481 / GHSA-h9f5-7hhf-fqm4) |
| [`ATR-2026-01968`](https://agentthreatrule.org/en/rules/ATR-2026-01968) | critical | production | DeepChat Markdown Deeplink shell.openExternal Protocol Bypass RCE (CVE-2026-43899, GHSA-cp8j-jx7q-7r5f) |
| [`ATR-2026-01970`](https://agentthreatrule.org/en/rules/ATR-2026-01970) | critical | production | PraisonAI FileTools _validate_path normpath Path Traversal (CVE-2026-35615 / GHSA-693f-pf34-72c5) |
| [`ATR-2026-01973`](https://agentthreatrule.org/en/rules/ATR-2026-01973) | critical | production | AnythingLLM Logo Endpoint Path Traversal File Read/Delete (CVE-2024-3025) |
| [`ATR-2026-01978`](https://agentthreatrule.org/en/rules/ATR-2026-01978) | critical | production | AnythingLLM collector /process filename Path Traversal Arbitrary File Deletion (CVE-2023-5832) |
| [`ATR-2026-01979`](https://agentthreatrule.org/en/rules/ATR-2026-01979) | critical | production | PandasAI Interactive Prompt Injection -> Python Sandbox Escape RCE (CVE-2024-12366 / GHSA-vv2h-2w3q-3fx7) |
| [`ATR-2026-01980`](https://agentthreatrule.org/en/rules/ATR-2026-01980) | critical | observe | Agentic-Flow MCP Tool-Parameter OS Command Injection (GHSA-vcv2-r9jh-99m5) |
| [`ATR-2026-01982`](https://agentthreatrule.org/en/rules/ATR-2026-01982) | medium | production | dbt-mcp node_selection/resource_type Argument Injection (CVE-2026-44968) |
| [`ATR-2026-01983`](https://agentthreatrule.org/en/rules/ATR-2026-01983) | critical | production | MCP-for-Stata: Command Injection via log_file_name Parameter (CVE-2026-47708) |
| [`ATR-2026-01985`](https://agentthreatrule.org/en/rules/ATR-2026-01985) | critical | production | MCP Connect: Unauthenticated /bridge Endpoint Arbitrary Process Spawn RCE (GHSA-wvr4-3wq4-gpc5) |
| [`ATR-2026-01987`](https://agentthreatrule.org/en/rules/ATR-2026-01987) | critical | production | Langroid SQLChatAgent Prompt-to-SQL Remote Code Execution (CVE-2026-25879) |
| [`ATR-2026-02021`](https://agentthreatrule.org/en/rules/ATR-2026-02021) | critical | production | MCP Inspector Unauthenticated Proxy stdio Command Execution (CVE-2025-49596) |
| [`ATR-2026-02022`](https://agentthreatrule.org/en/rules/ATR-2026-02022) | high | production | CurXecute — Cursor .cursor/mcp.json Injected-Server Auto-Exec RCE (CVE-2025-54135) |
| [`ATR-2026-02023`](https://agentthreatrule.org/en/rules/ATR-2026-02023) | high | production | EscapeRoute — Filesystem MCP Server Directory Prefix-Bypass (CVE-2025-53110) |
| [`ATR-2026-02024`](https://agentthreatrule.org/en/rules/ATR-2026-02024) | high | production | EscapeRoute — Filesystem MCP Symlink Escape to LaunchAgent Persistence (CVE-2025-53109) |
| [`ATR-2026-02025`](https://agentthreatrule.org/en/rules/ATR-2026-02025) | high | production | MCP Full Schema Poisoning — Injected Directive in Non-Description inputSchema Field (MCP-11) |
| [`ATR-2026-02027`](https://agentthreatrule.org/en/rules/ATR-2026-02027) | critical | production | Diagnostic Content Remediation Command Injection (Agentjacking) |
| [`ATR-2026-02041`](https://agentthreatrule.org/en/rules/ATR-2026-02041) | critical | production | Shell Command Injection via Echo-Marker Proof-of-Concept in Tool Argument |
| [`ATR-2026-02102`](https://agentthreatrule.org/en/rules/ATR-2026-02102) | high | production | HTML/Script Injection in Tool Call Argument Targeting a Human-Approval Dashboard |
| [`ATR-2026-02141`](https://agentthreatrule.org/en/rules/ATR-2026-02141) | critical | production | Unsandboxed Command Execution via Dynamic MCP Server Config (command/args Injection) |
| [`ATR-2026-02145`](https://agentthreatrule.org/en/rules/ATR-2026-02145) | critical | production | Python Sandbox Escape via Generator/Coroutine Frame Object Introspection |
| [`ATR-2026-02193`](https://agentthreatrule.org/en/rules/ATR-2026-02193) | high | production | SSRF via Non-Canonical IPv6 Encoding of Loopback/Internal Addresses |
| [`ATR-2026-02194`](https://agentthreatrule.org/en/rules/ATR-2026-02194) | critical | production | Malicious Go init() Function Spawning a Process via a Code-Generation Tool |
| [`ATR-2026-02233`](https://agentthreatrule.org/en/rules/ATR-2026-02233) | high | production | Unscoped Destructive or Mass-Disclosure Database Operation Request via Natural Language |
| [`ATR-2026-02260`](https://agentthreatrule.org/en/rules/ATR-2026-02260) | high | production | Remediation-Framed Command Execution in Tool Response (Agentjacking) |
| [`ATR-2026-02263`](https://agentthreatrule.org/en/rules/ATR-2026-02263) | high | production | SQL Injection via Unparameterized Template-Expression Value in Workflow-Automation SQL Node (CVE-2026-59257) |
| [`ATR-2026-02350`](https://agentthreatrule.org/en/rules/ATR-2026-02350) | high | production | MCP JSON-RPC Message Carries Case-Duplicate name/arguments Keys to Smuggle an Unauthorized Tool Call |
| [`ATR-2026-02352`](https://agentthreatrule.org/en/rules/ATR-2026-02352) | high | production | Email Search/Reply Tool Argument Breaks Out of IMAP SEARCH Quoted String to Inject IMAP Commands |
| [`ATR-2026-02372`](https://agentthreatrule.org/en/rules/ATR-2026-02372) | high | production | Unsigned Automated Task/Validation Feed Invokes npm install / npx -y (Lifecycle-Script RCE) |
| [`ATR-2026-02376`](https://agentthreatrule.org/en/rules/ATR-2026-02376) | high | production | MCP Tool Description Defines a Common-Phrase Trigger to Forward Full Conversation History |
| [`ATR-2026-02403`](https://agentthreatrule.org/en/rules/ATR-2026-02403) | high | production | MCP Tool Returns Untrusted External Content Carrying Hidden Agent Instructions Without Spotlighting |
| [`ATR-2026-02514`](https://agentthreatrule.org/en/rules/ATR-2026-02514) | medium | production | MCP Server Descriptor URL Field Carries an HTML/Script Breakout Payload |
| [`ATR-2026-02542`](https://agentthreatrule.org/en/rules/ATR-2026-02542) | medium | production | Observability Query Tool Argument Appends a Pipeline Stage and Comments Out the Rest of the Query |
| [`ATR-2026-02557`](https://agentthreatrule.org/en/rules/ATR-2026-02557) | high | production | Shell Command Separator Inside a Path-Typed MCP Tool Argument |
| [`ATR-2026-02666`](https://agentthreatrule.org/en/rules/ATR-2026-02666) | high | production | Trusted Hostname Parked in the URL Userinfo So the Real Host Is Whatever Follows the At-Sign |
| [`ATR-2026-02668`](https://agentthreatrule.org/en/rules/ATR-2026-02668) | high | production | Branch or Tag Ref Name Carrying Shell Command Substitution in Tool Output |
| [`ATR-2026-02669`](https://agentthreatrule.org/en/rules/ATR-2026-02669) | medium | production | Query-Language Pipeline Stage Smuggled Into an Identifier-Typed Tool Parameter |
| [`ATR-2026-02682`](https://agentthreatrule.org/en/rules/ATR-2026-02682) | medium | production | XML/SVG Entity Expansion Bomb in Content Returned to an Agent |
| [`ATR-2026-02707`](https://agentthreatrule.org/en/rules/ATR-2026-02707) | high | production | Mail or Attachment Tool Argument Splits into a New Header via Embedded CRLF |

Next: **[29 · Troubleshooting](29-troubleshooting.md)**.
