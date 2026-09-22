# 08 · Containers, Kubernetes and infrastructure as code

Thirteen rules and a policy table of 139 controls, over the files that
describe *where your code runs*. Cordon reads the definitions -- it never
contacts a cluster, a cloud account or a registry to do it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   WHAT THIS TUTORIAL COVERS        WHAT IT DOES NOT                      │
├──────────────────────────────────────────────────────────────────────────┤
│   Dockerfile, Containerfile        a built image's layers                │
│   docker-compose / compose         a running container                   │
│   Kubernetes manifests             a live cluster                        │
│   Helm charts and values           OS packages inside an image           │
│   Terraform (.tf, .tfvars)         a cloud account's real state          │
│   CloudFormation templates                                               │
│   Ansible playbooks and roles      For image contents, Trivy and         │
│                                    Grype are the right tools.            │
└──────────────────────────────────────────────────────────────────────────┘
```

## How a file is identified -- content, not location

```
┌──────────────────────────────────────────────────────────────────────────┐
│   A path glob is a guess about somebody's naming convention.             │
│                                                                          │
│      **/k8s/**/*.yaml    finds  k8s/prod/pod.yaml                        │
│                          misses deploy/pod.yaml                          │
│                          misses manifests/pod.yaml                       │
│                          misses deployment.yaml at the root              │
│                                                                          │
│   So the globs are a FAST PATH and the marker is the answer:             │
│                                                                          │
│      any .yaml/.yml  ──▶  does the first 4 KB contain                    │
│                           `apiVersion`     ──▶ Kubernetes                │
│                           `AWSTemplateFormatVersion` ──▶ CloudFormation  │
│                           `hosts:` + a task key       ──▶ Ansible        │
│                                                                          │
│   A byte-identical privileged pod manifest is therefore found            │
│   wherever it sits, which is the thing most tools get wrong.             │
└──────────────────────────────────────────────────────────────────────────┘
```


## The policy table, and why it is separate

The thirteen rules above match a pattern against a file: they answer "does
this contain something alarming". Most infrastructure policy is the other
question -- *this* resource is missing *that* setting -- and a regex cannot
express absence over a region it has no notion of.

```
   A FILE IS READ INTO BLOCKS FIRST

     resource "aws_db_instance" "prod" { ... }      one block
     kind: Deployment                               one block
     Resources: { Bucket: { Type: AWS::S3::Bucket   one block
     services: { web: ...                           one block

   AND EACH POLICY ASKS ONE OF TWO THINGS INSIDE IT

     forbid    the block says something insecure     acl = "public-read"
     require   the block does not say something it   storage_encrypted
               must -- which is the provider's       absent means false
               default, and is written nowhere
```

`storage_encrypted` absent from an `aws_db_instance` is an unencrypted
database, and the file does not mention it. That is the half the pattern rules
could not reach, and it is where most of the 139 controls live: encryption at
rest and in transit, public exposure, logging, backups, deletion protection,
obsolete TLS, and the Kubernetes and Compose settings that hand a container
the node.

Every policy ships with the block it must report and the block it must not,
and the suite runs both on every push -- a control that stops matching fails
the build rather than quietly reporting nothing.

```bash
cordon-scanner rules list | grep IAC     # the pattern rules and the policies
```

## Containers -- 8 rules

```
┌──────────────────────────────────────────────────────────────────────────┐
│   POLICY.CONTAINER.UNPINNED_BASE.001                                     │
│       FROM node:20            a tag the publisher can move               │
│       FROM node@sha256:...    a digest they cannot                       │
│                                                                          │
│   SUSPECT.CONTAINER.FETCH_EXEC.001                                       │
│       RUN curl -sL https://x | sh                                        │
│       unreviewed code, baked into the image, as root                     │
│                                                                          │
│   SUSPECT.CONTAINER.BUILD_SECRET.001                                     │
│       ARG NPM_TOKEN / ENV AWS_SECRET_ACCESS_KEY=...                      │
│       a build arg lands in the layer history and ships with it           │
│                                                                          │
│   SUSPECT.K8S.CAPABILITIES.001      SYS_ADMIN, NET_RAW, SYS_PTRACE       │
│   SUSPECT.K8S.RBAC_WILDCARD.001     verbs: ["*"] on resources: ["*"]     │
│   POLICY.K8S.NET_ADMIN.001          hostNetwork / NET_ADMIN              │
│   POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001                                   │
│                                     automount of a token nothing needs   │
│   SUSPECT.HELM.UNTRUSTED_REPOSITORY.001                                  │
│                                     a chart from a repo nobody pinned    │
└──────────────────────────────────────────────────────────────────────────┘
```

## Infrastructure as code -- 5 rules

```
┌──────────────────────────────────────────────────────────────────────────┐
│   SUSPECT.IAC.PRIVILEGED.001        privileged: true                     │
│                                     the container boundary, removed      │
│                                                                          │
│   SUSPECT.IAC.HOST_MOUNT.001        hostPath: /  or  /var/run/docker.sock│
│                                     the host filesystem, or the daemon   │
│                                     that can start a container as root   │
│                                                                          │
│   SUSPECT.IAC.IAM_WILDCARD.001      Action: "*"  Resource: "*"           │
│                                     a role that can do anything          │
│                                                                          │
│   SUSPECT.IAC.PUBLIC_INGRESS.001    0.0.0.0/0 to a port that is not      │
│                                     80 or 443 -- a public service on     │
│                                     443 is a website; on 22 it is not    │
│                                                                          │
│   SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001                                     │
│                                     get_url/uri then command/shell       │
└──────────────────────────────────────────────────────────────────────────┘
```

## These are POSTURE, and that changes the default

```
  Cordon's default gate fails a build on compromise, and reports
  posture without failing it.
```

Every rule in this tutorial sits in the `container` or `infrastructure` threat
domain, and both are in `policy.advisory_domains` by default. You will see them
in the report; they will not turn the build red. That is deliberate -- these
findings are frequently correct *and* intentional, and a gate that fails on them
gets a blanket exception added, at which point it protects nothing.

Two lines make them blocking:

```yaml
policy:
  advisory_domains: []
```

## Run it

```bash
# everything, including manifests wherever they live
cordon-scanner scan .

# just this ground
cordon-scanner scan . -f json:out.json
jq '.findings[] | select(.rule_id | test("CONTAINER|K8S|IAC|HELM")) |
    {rule_id, path: .location.path}' out.json

# make posture blocking -- config only, there is no CLI flag
#   cordon.yaml:
#     policy:
#       advisory_domains: []
cordon-scanner scan . --config strict.yaml --fail-on medium
```

## A worked example

```
┌──────────────────────────────────────────────────────────────────────────┐
│   deploy/api.yaml            (not in a k8s/ directory)                   │
├──────────────────────────────────────────────────────────────────────────┤
│   apiVersion: apps/v1        ◀── the marker. This is a manifest.         │
│   kind: Deployment                                                       │
│   spec:                                                                  │
│     template:                                                            │
│       spec:                                                              │
│         hostNetwork: true                ──▶ POLICY.K8S.NET_ADMIN.001    │
│         containers:                                                      │
│           - image: internal/api:latest   ──▶ POLICY.CONTAINER.           │
│                                              UNPINNED_BASE.001           │
│             securityContext:                                             │
│               privileged: true           ──▶ SUSPECT.IAC.PRIVILEGED.001  │
│               capabilities:                                              │
│                 add: ["SYS_ADMIN"]       ──▶ SUSPECT.K8S.CAPABILITIES.001│
│             volumeMounts:                                                │
│               - mountPath: /host         ──▶ SUSPECT.IAC.HOST_MOUNT.001  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

Next: **[09 · The advisory database](09-advisory-database.md)**.
