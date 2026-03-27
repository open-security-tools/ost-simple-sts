# ost-simple-sts

Rust AWS Lambda service that exchanges a GitHub Actions OIDC token for a
short-lived GitHub App installation token.

## Endpoints

- `GET /health`
- `POST /exchange`

## Security model

`POST /exchange`:

- verifies the GitHub Actions OIDC JWT against GitHub's JWKS
- requires `iss = https://token.actions.githubusercontent.com`
- requires the configured OIDC audience
- requires a specific git ref
- optionally requires a specific GitHub Actions environment
- requires a specific workflow identity via `workflow_ref` or `job_workflow_ref`
- rejects replayed `jti` values via DynamoDB conditional writes + TTL
- looks up the GitHub App installation for the caller repository
- mints a repository-scoped installation token with `contents: write`

## Configuration

Runtime configuration comes from:

- `POLICY_JSON`
- `APP_ID` or `APP_ID_PARAMETER`
- `APP_PRIVATE_KEY` or `APP_PRIVATE_KEY_SECRET_NAME`
- `JTI_TABLE_NAME`
- optional `GITHUB_API_URL`

Example policy:

```json
{
  "expected_audience": "https://example.execute-api.us-east-1.amazonaws.com",
  "allowed_ref": "refs/heads/main",
  "allowed_workflow_path": ".github/workflows/release.yml",
  "allowed_environment": "release"
}
```

## Secrets

Recommended AWS storage:

- `APP_ID` → SSM SecureString
- `APP_PRIVATE_KEY` → Secrets Manager

Direct environment variables are also supported for local development.

## GitHub App permissions

The GitHub App needs:

- **Contents**: read and write
- **Metadata**: read-only

## Local development

```bash
cargo test
cargo fmt
```

## Deployment

This repo uses AWS SAM and `cargo-lambda`.

```bash
sam build --beta-features --no-use-container
```

Recommended workflow:

```bash
cp .env.example .env
mkdir -p .secrets
# place your PEM at .secrets/github-app-private-key.pem
make deploy-secrets
make deploy
```

- `make deploy-secrets` syncs the SSM parameter and Secrets Manager secret from `.env`
- `make deploy` reads `.env`, compacts `POLICY_FILE` with `jq -c`, and runs `sam deploy`

The preferred `.env` input is `APP_PRIVATE_KEY_FILE=.secrets/github-app-private-key.pem`.
A fallback inline `APP_PRIVATE_KEY='-----BEGIN PRIVATE KEY-----\n...` value also works.

Optional overrides in `.env`:

- `APP_ID_PARAMETER=/ost/app-id`
- `JTI_TABLE_NAME=ost-jti-replay`
- `STACK_NAME=ost-simple-sts`
- `POLICY_FILE=policy.json`

You can also point to a different env file:

```bash
ENV_FILE=/path/to/.env make deploy-secrets
ENV_FILE=/path/to/.env make deploy
```

The included `template.yaml` provisions:

- one Lambda function
- one HTTP API
- one DynamoDB table for OIDC `jti` replay protection

## Action usage

Point `ost-simple-sts-action` at the deployed exchange endpoint:

```yaml
- uses: your-org/ost-simple-sts-action@main
  id: app-token
  with:
    url: https://<api-id>.execute-api.<region>.amazonaws.com/exchange
```
