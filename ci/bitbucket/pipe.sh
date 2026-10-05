#!/bin/sh
# Bitbucket pipe entry point. Variables arrive from the pipe's `variables:` block.
set -eu

case "${SEVERITY:-low}" in info|low|medium|high|critical) ;; *) echo "SEVERITY must be a severity" >&2; exit 3 ;; esac
case "${FAIL_ON:-high}" in info|low|medium|high|critical|none) ;; *) echo "FAIL_ON must be a severity" >&2; exit 3 ;; esac

set -- scan "${BITBUCKET_CLONE_DIR:-.}" --severity "${SEVERITY:-low}" --fail-on "${FAIL_ON:-high}" --no-color \
  --format text \
  --format "sarif:${BITBUCKET_CLONE_DIR:-.}/cordon.sarif" \
  --format "junit:${BITBUCKET_CLONE_DIR:-.}/test-results/cordon-junit.xml"

if [ "${UPLOAD:-false}" = "true" ]; then
  # `oidc: true` on the step provides this token; Cordon exchanges it for a short-lived one.
  if [ -z "${BITBUCKET_STEP_OIDC_TOKEN:-}" ]; then
    echo "UPLOAD needs \`oidc: true\` on the step" >&2
    exit 3
  fi
  set -- "$@" --upload
fi

mkdir -p "${BITBUCKET_CLONE_DIR:-.}/test-results"
exec cordon-scanner "$@"
