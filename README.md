# ost-simple-sts

`ost-simple-sts` is a Rust AWS Lambda service that exchanges a GitHub Actions
OIDC token for a short-lived GitHub App installation token.

It is intended for workflows that should not carry long-lived GitHub App
credentials, and instead mint narrowly scoped installation tokens only after
policy checks pass.

## Endpoints

- `GET /health`
- `POST /exchange`

## Exchange lifecycle

`POST /exchange` performs the following checks and actions:

1. Read bearer token from `Authorization: Bearer <oidc-jwt>`
2. Verify OIDC JWT signature with GitHub Actions JWKS (`RS256`)
3. Enforce issuer: `https://token.actions.githubusercontent.com`
4. Enforce configured OIDC audience
5. Enforce configured ref (for example `refs/heads/main`)
6. Optionally enforce configured environment
7. Enforce `workflow_dispatch` event
8. Enforce workflow identity (`workflow_ref` or `job_workflow_ref`)
9. Claim the OIDC `jti` in DynamoDB to prevent replay
10. Authenticate as GitHub App and resolve repository installation
11. Mint a repository-scoped installation token (`contents: write`)

## Policy configuration

`POLICY_JSON` is required and defines exchange policy.

Example policy:

```json
{
  "expected_audience": "https://example.execute-api.us-east-1.amazonaws.com",
  "allowed_ref": "refs/heads/main",
  "allowed_workflow_path": ".github/workflows/release.yml",
  "allowed_environment": "release"
}
```

`allowed_environment` is optional.

## Runtime configuration

Values are loaded from env / AWS stores:

- `POLICY_JSON`
- `APP_ID` or `APP_ID_PARAMETER` (SSM)
- `APP_PRIVATE_KEY` or `APP_PRIVATE_KEY_SECRET_NAME` / `APP_PRIVATE_KEY_SECRET_ARN` (Secrets Manager)
- `JTI_TABLE_NAME`
- optional `GITHUB_API_URL` (defaults to `https://api.github.com/`)

## GitHub App requirements

Repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

The App must be installed on repositories that are allowed to exchange tokens.

## Security notes

- OIDC verification uses cached GitHub JWKS keys
- replay protection uses DynamoDB conditional writes + TTL
- all external GitHub API requests use short timeouts and retry transient failures
- sensitive values (private key/token) are redacted in debug output

## Local development

```bash
cargo test
cargo fmt
```

## Deployment (AWS SAM + cargo-lambda)

Recommended workflow:

```bash
cp .env.example .env
mkdir -p .secrets
# place your PEM at .secrets/github-app-private-key.pem
make deploy-secrets
make deploy
```

- `make deploy-secrets` syncs App ID + private key into AWS
- `make deploy` compacts policy JSON and deploys the SAM stack

Supported `.env` key sources:

- preferred: `APP_PRIVATE_KEY_FILE=.secrets/github-app-private-key.pem`
- fallback: inline `APP_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----\n...'`

Optional `.env` overrides:

- `APP_ID_PARAMETER=/ost/app-id`
- `JTI_TABLE_NAME=ost-jti-replay`
- `STACK_NAME=ost-simple-sts`
- `POLICY_FILE=policy.json`

Use a different env file when needed:

```bash
ENV_FILE=/path/to/.env make deploy-secrets
ENV_FILE=/path/to/.env make deploy
```

The included `template.yaml` provisions:

- one Lambda function
- one HTTP API (`/health`, `/exchange`)
- one DynamoDB table for OIDC `jti` replay protection

## GitHub Actions caller requirements

Workflows calling `/exchange` must request an OIDC token:

```yaml
permissions:
  id-token: write
  contents: read
```

The exchange route only accepts identity from `workflow_dispatch` runs whose
`ref`, workflow path, and (optionally) environment match policy.

## Error response contract

All errors return JSON with this shape:

```json
{
  "code": "machine_readable_error_code",
  "error": "human readable message"
}
```

Examples:

- missing bearer token: `401 missing_bearer_token`
- wrong ref/environment/workflow: `403 ref_not_allowed|environment_not_allowed|workflow_not_allowed`
- replayed token: `409 oidc_token_replayed`
- GitHub upstream failure: `502 github_installation_lookup_failed|github_access_token_request_failed`

## Action usage

Point `ost-simple-sts-action` at the deployed exchange endpoint:

```yaml
- uses: your-org/ost-simple-sts-action@main
  id: app-token
  with:
    url: https://<api-id>.execute-api.<region>.amazonaws.com/exchange
```

## Architecture notes

For a module-by-module map, see [`OVERVIEW.md`](./OVERVIEW.md).
