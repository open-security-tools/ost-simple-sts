# Architecture

```text
HTTP / Lambda
  └── src/main.rs              route requests and map responses
      └── src/exchange.rs      verify OIDC claims, prevent replay, and mint a token
          ├── src/jwks.rs      cache GitHub Actions signing keys
          ├── src/replay.rs    conditionally claim the OIDC jti in DynamoDB
          └── src/github/
              ├── api.rs       validated API base, headers, and bounded GET retries
              ├── permissions.rs
              │                validated repository permissions and access levels
              ├── repositories.rs
              │                validated repository and jti types
              └── tokens.rs    App JWT, installation lookup, and token creation

src/config.rs                  validated policy and runtime configuration
src/error.rs                   stable error codes and HTTP status mapping
src/response.rs                no-store JSON responses and token redaction
```

## Data flow

1. `/exchange` receives a GitHub Actions OIDC JWT.
1. The JWT is validated against the Actions JWKS and configured policy.
1. The `jti` is claimed in DynamoDB to prevent replay.
1. A GitHub App JWT is minted from the configured App ID and private key.
1. The matched target repository installation is resolved.
1. A target-repository-scoped installation token is minted and returned to the caller.

## Exchange API

The service exposes two routes:

- `GET /health`
- `POST /exchange`

The bundled action requires `exchange-url` to be the configured HTTPS `audience` URL followed by
`/exchange`, preventing an unexpected endpoint from receiving the OIDC token. Non-URL audiences are
not supported. The action safely writes returned values, masks both the OIDC and installation
tokens, and exposes `token`, `expires-at`, `repository` or `repositories`, and `ref` outputs. It revokes the
installation token when the job finishes; if revocation cannot complete, the action emits a warning
and the token expires after one hour.

The exchange receives an OIDC token in `Authorization: Bearer <oidc-jwt>` and an optional bounded
JSON body of the form `{"repository":"OWNER/REPO","permissions":{"contents":"write"}}` or
`{"repositories":["OWNER/REPO","OWNER/OTHER"],"permissions":{"contents":"write"}}`. It
validates the token signature against the cached GitHub Actions JWKS and validates its issuer,
audience, subject, expiry,
not-before, and issued-at claims. The caller's `workflow_ref` must match the selected rule's
repository, workflow path, and ref. If the job runs in a reusable workflow, its
`job_workflow_ref` must match too; a trusted caller cannot delegate token minting to a different
reusable workflow. The event must be listed in the matched rule's `allowed_events`. If a target
repository or target set is configured, the request body is required and must exactly match that
target. Singular and plural requests cannot be mixed. Installation lookup and token minting use only
the matched targets and never an implicit calling repository; every plural target must resolve to
the rule's pinned installation ID, and the repositories returned by GitHub must exactly match the
configured names and IDs. A legacy empty body remains supported for same-repository rules.
Requested repository permissions must be a subset of the matching rule's configured permissions.
The service rejects unknown, duplicate, or broader permissions.

GitHub applies one permission map to every repository selected for an installation token. A
cross-repository pull-request publisher therefore needs source-branch write access (typically
`contents: write`) as well as `pull_requests: write`; `workflows: write` is needed only if it
actually pushes workflow-file changes.

The JWKS cache refreshes at most once every 30 seconds for an unknown key ID, allowing key rotation
without letting unauthenticated requests amplify outbound traffic. The OIDC `jti` is claimed with
a conditional DynamoDB write to prevent replay.

Requests to the following GitHub routes are expected:

- `GET /repos/{owner}/{repo}/installation`
- `POST /app/installations/{installation_id}/access_tokens`

The installation lookup retries transient failures and secondary rate limits once with bounded
backoff. Token creation is deliberately not retried because the POST is not idempotent. Private
keys and installation tokens are redacted from debug output. Outbound requests require HTTPS and
never follow redirects. GitHub API requests are restricted to `api.github.com`, so credentials and
token-request payloads cannot be forwarded to an unexpected destination.

Errors return a stable machine-readable code and a human-readable message:

```json
{
  "code": "repository_not_allowed",
  "error": "repository is not allowed"
}
```

Policy denials return `403`, invalid exchange bodies return `400`, invalid or expired OIDC tokens
return `401`, replayed tokens return `409`, GitHub App configuration or permission failures return
`422` or `424`, and upstream outages return `502` or `503`.

## Deployment

The SAM template provisions one Lambda, one HTTP API, and one DynamoDB table with TTL for OIDC
replay protection. The Lambda has permission to write replay records, read the App ID from SSM
Parameter Store, and read only the named App private key from Secrets Manager. The public API is
limited to 100 requests per second with a burst of 200, and Lambda concurrency is capped at 100.
Metadata-only HTTP access logs and Lambda logs are retained for 30 days. The stack creates alarms
for Lambda errors and throttles, API 5xx responses, GitHub App dependency failures (HTTP 422 and
424), and sustained API 4xx spikes; set the optional `AlarmTopicArn` parameter to an SNS topic to
receive notifications. Access logs deliberately omit request headers, OIDC claims, and response
bodies.

`make deploy-secrets` stores the App ID and private key in AWS. `make deploy` compacts the local
policy and deploys the SAM stack. `POLICY_FILE`, `STACK_NAME`, `APP_ID_PARAMETER`,
`JTI_TABLE_NAME`, and the optional `ALARM_TOPIC_ARN` can be overridden in `.env`.

## Validated domain types

- `Policy`, `PolicyRule`, `Audience`, `Subject`, `GitRef`, `WorkflowPath`, `EnvironmentName`
- `RepositoryFullName`, `RepositoryOwner`, `RepositoryNamePart`, `RepositoryId`
- `GithubApiBase`, `JtiTableName`, `Jti`, `Token`

These types keep validation and redaction close to the request boundary.
