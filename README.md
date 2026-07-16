# ost-simple-sts

GitHub Actions workflows sometimes need more access than the built-in `GITHUB_TOKEN` can provide.
Keeping a GitHub App private key in every repository that needs that access creates a long-lived
secret with a wide blast radius.

`ost-simple-sts` lets an approved GitHub Actions workflow obtain a short-lived GitHub App token
without storing the App's private key in the repository. Only the configured repository, workflow,
branch or tag, event, and environment can request a token. A rule can optionally issue access to a
different, explicitly configured target repository.

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
          repository: example-org/example-repo
          permissions: |
            contents: write
      - uses: actions/checkout@<commit-sha>
        with:
          token: ${{ steps.app-token.outputs.token }}
          persist-credentials: false
      - run: echo "Use the scoped GitHub App token to release"
```

Set `audience` and the policy `expected_audience` to the deployed API URL, and `exchange-url` to
the same URL followed by `/exchange`. Set `repository` to the requested target repository and list
one GitHub App repository permission per line in `permissions`. The action returns a short-lived
token and revokes it when the job finishes, including after a failed step. Do not pass the token to
another job. Pin actions to a commit SHA in production.

## GitHub App

For the examples below, the GitHub App needs the following repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

Install the App on each target repository allowed by the policy; it does not need to be installed
on a separate calling repository. The service requests only the permissions selected by the caller
and allowed by the matched policy rule.

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
      "allowed_events": ["workflow_dispatch"],
      "permissions": { "contents": "write" },
      "environment": "release"
    }
  ]
}
```

The exchange succeeds only when all of these checks pass:

1. The repository name and ID
1. The workflow file and Git ref
1. The OIDC subject, including the environment when one is configured
1. An event allowed by the matched rule
1. The reusable workflow, if one is used

`expected_audience` and a non-empty `rules` list are required. `allowed_events` can contain only
`issues`, `push`, `pull_request`, and `workflow_dispatch`; if omitted, it defaults to `["workflow_dispatch"]`. An empty
allowlist is rejected. `permissions` is the maximum set of repository permissions the rule may
issue; if omitted, it defaults to `{"contents":"write"}` for compatibility. Requests can select a
subset or lower level, but never an additional or broader permission. `environment`,
`job_workflow_path`, `target_repository`, and `target_repository_id` are optional; the two target
fields must either both be present or both be omitted. All other rule fields are required, unknown
fields and duplicate permissions are rejected, and values from different rules are never combined.

For `pull_request` runs, set `ref` to `refs/pull/*/merge` to match only canonical pull-request merge
refs. This pattern is valid only with `allowed_events: ["pull_request"]`. `workflow_path` always
binds the calling workflow's `workflow_ref`; set `job_workflow_path` when the token is requested by
a reusable workflow so its `job_workflow_ref` must match as well.

A workflow in one repository can be allowed to update a different repository without granting the
caller access. For example, an upstream fork-sync workflow can receive a token scoped only to the
fork:

```json
{
  "subject": "repo:astral-sh/uv:environment:automations",
  "repository": "astral-sh/uv",
  "repository_id": 699532645,
  "ref": "refs/heads/main",
  "workflow_path": ".github/workflows/sync-uv-dev.yml",
  "environment": "automations",
  "allowed_events": ["push", "workflow_dispatch"],
  "permissions": { "contents": "write" },
  "target_repository": "astral-sh/uv-dev",
  "target_repository_id": 1302176231
}
```

The workflow requests the target and permission explicitly:

```yaml
repository: astral-sh/uv-dev
permissions: |
  contents: write
```

The scalar spelling `permissions: contents:write` is also accepted for a single permission. The App
is installed on `astral-sh/uv-dev`, and the returned token has `contents: write` only for that
repository. The `repository` action output reports the target repository. A cross-repository rule
requires an explicit matching request; it cannot be exchanged using the legacy empty request.

A reusable security-review publisher that is called by CI on pull requests can be scoped separately:

```json
{
  "subject": "repo:astral-sh/uv:environment:automations",
  "repository": "astral-sh/uv",
  "repository_id": 699532645,
  "ref": "refs/pull/*/merge",
  "workflow_path": ".github/workflows/ci.yml",
  "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
  "environment": "automations",
  "allowed_events": ["pull_request"],
  "permissions": { "pull_requests": "write" },
  "target_repository": "astral-sh/uv",
  "target_repository_id": 699532645
}
```

This rule binds both the CI caller and the reusable publisher and issues only pull-request write
access for `astral-sh/uv`.

`subject` must exactly match the OIDC subject emitted by the calling job. The default subject format
for an environment-bound job is `repo:OWNER/REPO:environment:ENVIRONMENT`. Always bind the
immutable `repository_id` claim separately; find it with:

```bash
gh api repos/OWNER/REPO --jq '{repository_id: .id}'
```

Keep the environment's deployment rules restricted to the intended branch.

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
