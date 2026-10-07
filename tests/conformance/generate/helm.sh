#!/bin/sh
# Regenerates the real-world Helm conformance case: a chart whose dependencies come from an OCI
# registry (with a version range, an alias and a condition), an HTTPS repository (with tags), and a
# chart in the repository (file://), resolved by `helm dependency update` into Chart.lock and the
# downloaded archives in charts/. Helm's own `helm show chart` over each downloaded archive is the
# authoritative inventory. Nothing is installed or templated against a cluster. Run inside Docker
# only:
#
#   docker run --rm --entrypoint sh -v "$PWD/tests/conformance:/conformance" alpine/helm:3.16.2 /conformance/generate/helm.sh
set -eu
OUT=/conformance/cases/helm/real-chart
rm -rf /tmp/h && mkdir -p /tmp/h/app/templates /tmp/h/common/templates && cd /tmp/h
cat > common/Chart.yaml <<'EOF'
apiVersion: v2
name: acme-common
version: 0.3.0
type: library
EOF
cat > app/Chart.yaml <<'EOF'
apiVersion: v2
name: acme-app
description: A conformance fixture
type: application
version: 1.4.0
appVersion: "2.7.1"
kubeVersion: ">= 1.27.0-0"
dependencies:
  - name: postgresql
    version: "~15.5.0"
    repository: oci://registry-1.docker.io/bitnamicharts
    alias: database
    condition: database.enabled
  - name: prometheus-node-exporter
    version: ">=4.30.0 <5.0.0"
    repository: https://prometheus-community.github.io/helm-charts
    tags:
      - monitoring
  - name: acme-common
    version: 0.3.0
    repository: file://../common
EOF
cat > app/values.yaml <<'EOF'
database:
  enabled: true
replicaCount: 2
image:
  repository: ghcr.io/acme/app
  tag: "2.7.1"
EOF
cat > app/templates/deployment.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}
    spec:
      containers:
        - name: app
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
EOF
cd app
helm dependency update >/tmp/dep.log 2>&1 || { tail -20 /tmp/dep.log; exit 1; }
cd ..
rm -rf "$OUT" && mkdir -p "$OUT"
cp -r app common "$OUT/"
{
  printf '{\n "tool": "helm show chart over the downloaded archives in charts/",\n "packages": ['
  first=1
  for archive in app/charts/*.tgz; do
    name=$(helm show chart "$archive" | sed -n 's/^name: //p' | head -1)
    version=$(helm show chart "$archive" | sed -n 's/^version: //p' | head -1)
    [ "$first" = 1 ] || printf ', '
    printf '"%s@%s"' "$name" "$version"
    first=0
  done
  printf ']\n}\n'
} > "$OUT/authoritative.json"
cat "$OUT/authoritative.json"; cat app/Chart.lock; ls -la app/charts
echo done
