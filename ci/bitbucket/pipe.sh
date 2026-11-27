#!/bin/sh
# Bitbucket pipe entry point. Variables arrive from the pipe's `variables:` block.
set -eu

case "${SEVERITY:-low}" in info|low|medium|high|critical) ;; *) echo "SEVERITY must be a severity" >&2; exit 3 ;; esac
case "${FAIL_ON:-high}" in info|low|medium|high|critical) ;; *) echo "FAIL_ON must be a severity" >&2; exit 3 ;; esac

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
status=0
cordon-scanner "$@" || status=$?

# On a pull request: what the dependency update adds, compared with the destination branch. Each change that
# blocks is a Code Insights annotation titled with its reason code (R100, R404, R400, R401), at the lockfile that
# declares it; the report fails the pull request's check. Posted through Pipelines' own authenticating proxy.
if [ "${DEPENDENCY_REVIEW:-true}" = "true" ] && [ -n "${BITBUCKET_PR_ID:-}" ]; then
  case "${BITBUCKET_PR_DESTINATION_BRANCH:-}" in
    ""|-*|*..*) echo "no usable destination branch for the review" >&2; exit 3 ;;
  esac
  cd "${BITBUCKET_CLONE_DIR:-.}"
  git fetch --quiet origin "refs/heads/${BITBUCKET_PR_DESTINATION_BRANCH}:refs/remotes/origin/${BITBUCKET_PR_DESTINATION_BRANCH}"
  base=$(git merge-base HEAD "origin/${BITBUCKET_PR_DESTINATION_BRANCH}")
  set -- review . --base "$base" --format bitbucket --quiet
  [ "${DEPENDENCY_REVIEW_ONLINE:-false}" = "true" ] && set -- "$@" --online
  review=0
  cordon-scanner "$@" > cordon-review.json || review=$?
  if [ "$review" -le 1 ]; then
    python /insights.py cordon-review.json || echo "Code Insights could not be posted" >&2
  fi
  [ "$review" -gt "$status" ] && status=$review
fi
exit "$status"
