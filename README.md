# ost-simple-sts

GitHub Actions workflows sometimes need more access than the built-in `GITHUB_TOKEN` can provide.
Keeping a GitHub App private key in every repository that needs that access creates a long-lived
secret with a wide blast radius.

`ost-simple-sts` is a small AWS Lambda that exchanges a GitHub Actions OIDC token for a
repository-scoped GitHub App installation token. The App private key stays in AWS Secrets Manager,
and the exchange succeeds only for the configured repository, workflow, ref, environment, and OIDC
subject.

## GitHub Actions workflow

A minimal release workflow would look like this:

```yaml
name: Release

on:
  workflow_dispatch:

permissions: {}

jobs:
  release:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: read
      id-token: write
    steps:
      - id: app-token
        uses: open-security-tools/ost-simple-sts@<commit-sha>
        with:
          exchange-url: https://example.execute-api.us-east-1.amazonaws.com/exchange
          audience: https://example.execute-api.us-east-1.amazonaws.com
      - uses: actions/checkout@<commit-sha>
        with:
          token: ${{ steps.app-token.outputs.token }}
      - run: echo "Use the scoped GitHub App token to release"
```

The exchange action requires `exchange-url` to be the configured HTTPS `audience` URL followed by
`/exchange`. This prevents a misleading or attacker-controlled endpoint from receiving the OIDC
token. Set the policy `expected_audience` to that base URL; non-URL audiences are not supported by
the bundled action. The action masks both the OIDC token and the returned installation token and
exposes `token`, `expires-at`, `repository`, and `ref` outputs. The action revokes the installation
token when the job finishes, including after a failed step. Do not pass the token to another job.
If revocation cannot complete, the action emits a warning and GitHub installation tokens expire
after one hour. Pin actions to a commit SHA in production.

## GitHub App

The GitHub App needs the following repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

Install the App on each repository allowed by the policy. The broker requests an installation token
for exactly the matched repository ID and only the `contents: write` permission.

## Policy

The checked-in [`policy-example.json`](./policy-example.json) is an example only. Copy it to the
ignored `policy.json` and replace every example value for the calling repository:

```json
{
  "expected_audience": "https://example.execute-api.us-east-1.amazonaws.com",
  "rules": [
    {
      "subject": "repo:example-org@123456/example-repo@789012:environment:release",
      "repository": "example-org/example-repo",
      "repository_id": 789012,
      "ref": "refs/heads/main",
      "workflow_path": ".github/workflows/release.yml",
      "environment": "release"
    }
  ]
}
```

`expected_audience` and a non-empty `rules` list are required. Within each rule, all fields except
`environment` are required, and unknown fields are rejected. Each rule binds both the mutable
repository name and immutable repository ID; the ID can be obtained with
`gh api repos/OWNER/REPO --jq .id`.

Every claim must match the same rule. Repositories, refs, workflows, and environments from
different rules are never combined.

`subject` must exactly match the `sub` claim emitted by the calling job. Jobs using an
environment have an environment subject. New repositories use GitHub's immutable subject format,
shown above; repositories using the previous format would use
`repo:example-org/example-repo:environment:release` instead. Keep the environment's deployment
rules restricted to the intended ref.

The caller's `workflow_ref` must match the selected rule's repository, workflow path, and ref. If
the job runs in a reusable workflow, its `job_workflow_ref` must match too; a trusted caller cannot
delegate token minting to a different reusable workflow.

## Exchange

The broker exposes two routes:

- `GET /health`
- `POST /exchange`

The exchange lifecycle is roughly:

1. Receive an OIDC token in `Authorization: Bearer <oidc-jwt>`
1. Validate the JWT signature against the cached GitHub Actions JWKS
1. Validate issuer, audience, subject, expiry, not-before, and issued-at claims
1. Match one configured rule's repository name and ID, ref, workflow path, and environment
1. Require a `workflow_dispatch` event
1. Claim the OIDC `jti` with a conditional DynamoDB write to prevent replay
1. Mint a GitHub App JWT and resolve the repository installation
1. Mint and return a repository-scoped installation token

The JWKS cache refreshes at most once every 30 seconds for an unknown key ID, allowing key rotation
without letting unauthenticated requests amplify outbound traffic.

Requests to the following GitHub routes are expected:

- `GET /repos/{owner}/{repo}/installation`
- `POST /app/installations/{installation_id}/access_tokens`

The installation lookup retries transient failures and secondary rate limits once with bounded
backoff. Token creation is deliberately not retried because the POST is not idempotent. Private
keys and installation tokens are redacted from debug output.

Errors return a stable machine-readable code and a human-readable message:

```json
{
  "code": "repository_not_allowed",
  "error": "repository is not allowed"
}
```

Policy denials return `403`, invalid or expired OIDC tokens return `401`, replayed tokens return
`409`, and upstream failures return `502` or `503`.

## Deploy

The included SAM template provisions one Lambda, one HTTP API, and one DynamoDB table with TTL for
OIDC replay protection. The Lambda has permission to write replay records, read the App ID from SSM
Parameter Store, and read only the named App private key from Secrets Manager. The public API is
limited to 100 requests per second with a burst of 200, and Lambda concurrency is capped at 100.

Create the local configuration, set the App ID and private-key location in `.env`, and edit the
policy for the calling repositories:

```bash
cp .env.example .env
cp policy-example.json policy.json
mkdir -p .secrets
# place the App PEM at .secrets/github-app-private-key.pem
make deploy-secrets
make deploy
```

`make deploy-secrets` stores the App ID and private key in AWS. `make deploy` compacts the local
policy and deploys the SAM stack. `POLICY_FILE`, `STACK_NAME`, `APP_ID_PARAMETER`, and
`JTI_TABLE_NAME` can be overridden in `.env`; `ENV_FILE=/path/to/.env make deploy` selects another
environment file.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
```

For a module-by-module map, see [`OVERVIEW.md`](./OVERVIEW.md).
