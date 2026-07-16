# ost-simple-sts

GitHub Actions workflows sometimes need more access than the built-in `GITHUB_TOKEN` can provide.
Keeping a GitHub App private key in every repository that needs that access creates a long-lived
secret with a wide blast radius.

`ost-simple-sts` lets an approved GitHub Actions workflow obtain a short-lived GitHub App token
without storing the App's private key in the repository. Only the configured repository, workflow,
branch or tag, and environment can request a token.

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
          persist-credentials: false
      - run: echo "Use the scoped GitHub App token to release"
```

Set `audience` and the policy `expected_audience` to the deployed API URL, and `exchange-url` to
the same URL followed by `/exchange`. The action returns a short-lived token and revokes it when the
job finishes, including after a failed step. Do not pass the token to another job. Pin actions to a
commit SHA in production.

## GitHub App

The GitHub App needs the following repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

Install the App on each repository allowed by the policy. The service requests a token with only
`contents: write` for the matched repository.

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

The exchange succeeds only when all of these checks pass:

1. The repository name and ID
1. The workflow file and Git ref
1. The OIDC subject, including the environment when one is configured
1. The `workflow_dispatch` event
1. The reusable workflow, if one is used

`expected_audience` and a non-empty `rules` list are required. All rule fields except `environment`
are required, and unknown fields are rejected. Values from different rules are never combined.

`subject` must exactly match the OIDC subject emitted by the calling job. New repositories use the
immutable subject format shown above, which includes both the owner and repository IDs. Find them
with:

```bash
gh api repos/OWNER/REPO --jq '{owner_id: .owner.id, repository_id: .id}'
```

Repositories using the previous subject format would use
`repo:example-org/example-repo:environment:release` instead. Keep the environment's deployment
rules restricted to the intended branch.

## Deploy

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

The stack provisions the exchange API, Lambda, replay protection, logging, and alarms. The App ID
and private key are stored in AWS. Deployment settings can be overridden in `.env`;
`ENV_FILE=/path/to/.env make deploy` selects another environment file.

## How it works

The exchange lifecycle is roughly:

1. Receive a GitHub Actions OIDC token
1. Validate the token and match one configured policy rule
1. Reject tokens that have already been exchanged
1. Mint and return a repository-scoped GitHub App token

See [`OVERVIEW.md`](./OVERVIEW.md) for the security, API, and deployment details.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
```
