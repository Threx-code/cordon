# Contracts between the package and Cordon Cloud

The package owns these. The cloud codes against a released version, pinned by hash, never against
unreleased engine code. A breaking change is a new version (`v2`) served alongside the old one.

| # | Contract | File | Package's side |
|---|---|---|---|
| K1 | Scan results and the finding fingerprint | `cordon-findings-v1.schema.json` | `cordon scan --format json` writes it |
| K2 | Signed results upload | `cordon-upload-v1.schema.json` | `cordon scan --upload` sends it |
| K3 | Organisation policy bundle | `cordon-policy-bundle-v1.schema.json` | `cordon scan --cloud-policy` verifies and applies it |
| K4 | Intel feed | `src/cordon_scanner/intel/feed.py` (`cordon-feed/1`) | the scan verifies and applies it |
| K5 | Events and webhooks | `cordon-event-v1.schema.json` | `cordon scan --notify webhook` sends it |
| K6 | Runner job protocol | this file, below | `cordon runner` leases, runs and reports jobs |
| K7 | Sign-in and token exchange | this file, below | `cordon login`, and CI uploads |
| K8 | AI bill of materials | this file, below (CycloneDX 1.6) | `cordon sbom generate --ai` writes it |
| K9 | Agent judge | `cordon-judge-v1.schema.json` | `cordon scan --judge cordon-cloud` sends agent-facing text, one piece per request |

## K9: what the cloud judge implements

`POST {CORDON_CLOUD_URL}/v1/judge`, bearer token from `cordon login` (the same one uploads use).

1. **Request** (`$defs.request`): `{prompt_version, kind, path, text}`. One piece of one file, at
   most 6,000 characters, cut at paragraph breaks. `kind` is `agent instruction file`, `agent hook
   command` or `MCP tool description`. Nothing else from the repository is ever sent.
2. **Response** (`$defs.response`): `{"verdict": {verdict, category, evidence, reason}}`, HTTP 200.
   `verdict` is `malicious`, `suspicious` or `benign`; `evidence` an exact quote from `text`, empty
   when benign. Any other status is reported by the package as the judge being unavailable, and
   the scan is marked incomplete.
3. **What the package checks.** It discards a verdict whose `evidence` is not in the `text` it sent
   (whitespace and case aside), so a wrong or tampered answer cannot add a finding. It reports
   `malicious` at MEDIUM (HIGH with `--judge-blocks`), `suspicious` at LOW, and nothing for `benign`.
4. **What the cloud is free to do.** Run its own prompt and model; cache by
   `sha256(prompt_version, kind, text)` across organisations; rate-limit per organisation; record
   verdicts for audit. It must treat `text` as data -- the repository's author wrote it, and it may
   be written to steer the judge -- and must not log it beyond what the organisation has agreed to.
5. **Versioning.** A change to the request or response shape is `cordon-judge-v2`, served alongside
   v1. A change of prompt or model is not a contract change; `prompt_version` names the package's
   prompt so the cloud can key caches and reports by it.

## K1: the fingerprint

`sha256(rule_id NUL (package or path) NUL symbol NUL match)`, first 16 hex characters, where
`match` is the evidence snippet with whitespace runs collapsed, or the evidence hash when no
snippet is kept. Line and column are not inputs, so a finding keeps its identity when code above
it moves. Suppressions, baselines, SARIF `partialFingerprints` and the cloud's finding history all
key on it.

## K2: what the cloud checks

1. `sha256(base64decode(results))` equals the statement's only subject digest.
2. With `signing: sigstore`: the bundle verifies, its certificate identity (issuer, repository,
   workflow, ref) matches a trust rule of `org`, and it signs this same statement.
3. With `signing: none`: the bearer token belongs to `org`. The scan is stored as unsigned.
4. `predicate.fingerprints` equals the set of `fingerprint` values in the results.
5. With `ai_inventory`: `sha256(base64decode(ai_inventory))` equals `predicate.ai_inventory.sha256`,
   and either both are present or neither. The AI-BOM holds names, paths, hashes and package ids,
   never file contents.

## K3: what the client checks

1. At least one signature verifies (Ed25519 over the payload bytes) under a key pinned at sign-in.
2. `type` is `cordon.policy-bundle/v1`, `org` is the signed-in organisation.
3. `version` is not lower than the cached bundle's. `expires_at` is in the future.
4. Unreachable cloud: the cached bundle applies until it expires, then the scan refuses to run.
5. Suppressions pass the same rules as a repository's (rule and path together, justification,
   expiry within the organisation's ceiling, malware never suppressible).

## K7: sign-in

Endpoints, all under the API base (`https://api.cordon.dev` by default, `CORDON_CLOUD_URL`):

| Request | Standard | Body (form-encoded) | Success |
|---|---|---|---|
| `POST /v1/auth/device/code` | RFC 8628 §3.1 | `client_id=cordon-cli`, `scope` | `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval` |
| `POST /v1/auth/token` (device) | RFC 8628 §3.4 | `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id` | token response |
| `POST /v1/auth/token` (CI) | RFC 8693 | `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` (the CI OIDC JWT, audience `cordon`), `subject_token_type=urn:ietf:params:oauth:token-type:jwt`, `audience=cordon`, `scope` | token response |
| `POST /v1/auth/token` (refresh) | RFC 6749 §6 | `grant_type=refresh_token`, `refresh_token`, `client_id` | token response |
| `POST /v1/auth/revoke` (`cordon logout`) | RFC 7009 | `token` (the refresh token, else the access token), `token_type_hint`, `client_id` | `200 {}`, whether or not the token was known; the sign-in's whole token family ends |

The token response is RFC 6749's (`access_token`, `token_type`, `expires_in`, `refresh_token`,
`scope`) plus `org`, `subject`, and `policy_keys` (key id to hex Ed25519 public key). Pending and
failure responses use RFC 8628's error codes: `authorization_pending`, `slow_down`,
`access_denied`, `expired_token`.

Scopes: `scans:write` (upload results), `policy:read` (fetch the bundle). A CI token lives fifteen
minutes and has no refresh token.

## K8: the AI bill of materials

Standard CycloneDX 1.6, validated against the official schema. Every component or service Cordon
adds carries `cordon:ai:kind`:

| kind | CycloneDX shape | Notable properties |
|---|---|---|
| `agent-instructions`, `skill`, `command`, `subagent`, `prompt` | `data` component, SHA-256 hashed | `cordon:ai:agent` (claude-code, cursor, github-copilot, ...) |
| `agent-settings` | `data` component, hashed | `cordon:ai:hooks`, `cordon:ai:permissions-allow` |
| `mcp-server` (local) | `application` component with the launched package's purl | `cordon:mcp:transport=stdio`, `cordon:mcp:package`, `cordon:mcp:pinned`, `cordon:mcp:config` |
| `mcp-server` (remote) | `service` with `endpoints` (no credentials or query), `authenticated`, `x-trust-boundary: true` | `cordon:mcp:transport` |
| `model` | `machine-learning-model`: a weight file (hashed up to 512 MB), `pkg:huggingface/...` the code loads, or a hosted model with its `supplier` | `cordon:ai:source` (file, huggingface, hosted-api), `cordon:ai:format` |
| `ci-agent` | `application` with `pkg:github/<action>@<ref>` | `cordon:ci:workflow` |
| `ai-sdk` | `library` from the dependency graph | |

`metadata.properties` carries `cordon:ai:count:<kind>` for each kind present.

## K6: the runner job protocol

The runner only makes outbound requests, authenticated with a runner token
(`CORDON_RUNNER_TOKEN`, scope `runner`):

| Request | Body | Answer |
|---|---|---|
| `POST /v1/runner/jobs/lease` | `runner_id`, `labels`, `capabilities` (`scan:git`, `scan:artifact`) | `204` when there is no work; otherwise `job_id`, `lease_id`, `lease_expires_in` (seconds), `target`, `options` |
| `POST /v1/runner/jobs/{job_id}/heartbeat` | `lease_id` | `200` extends the lease; anything else means the job was taken back |
| `POST /v1/runner/jobs/{job_id}/result` | `lease_id`, `status` (`succeeded`, `failed`, `refused`, `abandoned`), `exit_code`, `scan_id` or `error` | `200`/`202`/`204` |

`target` is `{"type": "git", "url": "https://...", "ref": "main", "token": "<short-lived clone token>"}`
or `{"type": "artifact", "url": "https://...", "sha256": "<hex>"}`. `options` may set `online` and
`org`. Results are uploaded through `POST /v1/scans` (K2) before the job result is reported.

The runner refuses a job whose target host is not on its operator's `--allow-host` list, whose
URL carries credentials, or that is not https. It heartbeats every third of the lease, and stops
treating a job as its own once a heartbeat is refused.
