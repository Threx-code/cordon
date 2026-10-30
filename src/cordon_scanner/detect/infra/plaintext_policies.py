"""The plaintext policies: resources configured to carry data unencrypted -- HTTP listeners, plain
protocols, unencrypted endpoints -- by resource type.
"""

from __future__ import annotations

from cordon_scanner.detect.infra.iac_model import IacPolicy
from cordon_scanner.detect.infra.policy_terms import HIGH, LOW, MEDIUM
from cordon_scanner.foundation.models import Category, Confidence

PLAINTEXT: tuple[IacPolicy, ...] = (
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
        severity=MEDIUM,
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
        severity=HIGH,
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
        severity=HIGH,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=HIGH,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=HIGH,
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
        severity=HIGH,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
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
        severity=LOW,
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
        severity=MEDIUM,
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
        severity=MEDIUM,
        confidence=Confidence.HIGH,
        category=Category.SUSPICIOUS,
        resources=("aws_sagemaker_notebook_instance",),
        forbid=(r"root_access\s*=\s*\"Enabled\"",),
        bad='  name = "example"\n  root_access = "Enabled"\n',
        good='  name = "example"\n  root_access = "Disabled"\n',
    ),
)


__all__ = ["PLAINTEXT"]
