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

Set `audience` and the deployment `POLICY_AUDIENCE` to the deployed API URL, and `exchange-url` to
the same URL followed by `/exchange`. Set `repository` to the requested target repository and list
one GitHub App repository permission per line in `permissions`. The action returns a short-lived
token and revokes it when the job finishes, including after a failed step. Do not pass the token to
another job. Pin actions to a commit SHA in production.

## GitHub App

For the examples below, the GitHub App needs the following repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

Install the App on the repository that owns the policy and each target repository allowed by the
policy; it does not need to be installed on a separate calling repository. The policy reader
requests only `contents: read` for the pinned policy repository. Exchanges request only the
permissions selected by the caller and allowed by the matched policy rule.

## Policy

The checked-in [`policy-example.json`](./policy-example.json) is an example only. Copy it to
`.github/ost-simple-sts.json` in the trusted policy repository and replace every example value for
the calling repository:

```json
{
  "version": 1,
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

`version: 1` and a non-empty `rules` list are required. `allowed_events` can contain only `issues`,
`push`, `pull_request`, and `workflow_dispatch`; if omitted, it defaults to
`["workflow_dispatch"]`. An empty
allowlist is rejected. `permissions` is the maximum set of repository permissions the rule may
issue; if omitted, it defaults to `{"contents":"write"}` for compatibility. Requests can select a
subset or lower level, but never an additional or broader permission. `environment`,
`job_workflow_path`, `target_repository`, and `target_repository_id` are optional; the two singular
target fields must either both be present or both be omitted. A multi-repository rule instead sets
`target_repositories` to an exact list of repository-name/ID pairs and `target_installation_id` to
their shared installation ID. Singular and plural targets are mutually exclusive; plural targets
must contain at least two unique names and IDs. All other rule fields are required, unknown fields
and duplicate permissions are rejected, and values from different rules are never combined. Rules
with the same caller identity, workflow paths, ref, environment, and an overlapping event are
rejected so a later target or permission grant cannot be silently shadowed.

For `pull_request` runs, set `ref` to `refs/pull/*/merge` to match only canonical pull-request merge
refs. This pattern is valid only with `allowed_events: ["pull_request"]`. `workflow_path` always
binds the calling workflow's `workflow_ref`; set `job_workflow_path` when the token is requested by
a reusable workflow so its `job_workflow_ref` must match as well.

See [`EXAMPLES.md`](./EXAMPLES.md) for cross-repository and reusable-workflow policy examples.

`subject` must exactly match the OIDC subject emitted by the calling job. The default subject format
for an environment-bound job is `repo:OWNER/REPO:environment:ENVIRONMENT`. Always bind the
immutable `repository_id` claim separately; find it with:

```bash
gh api repos/OWNER/REPO --jq '{repository_id: .id}'
```

Keep the environment's deployment rules restricted to the intended branch.

The policy is fetched from the configured repository name and immutable ID, the protected `main`
ref, and the configured path under `.github`. Protect the default branch with a pull-request
ruleset that cannot be bypassed by an issued token. A successfully parsed policy is cached for up
to five minutes; invalid, unavailable, or rate-limited refreshes fail closed and cannot authorize
an exchange.

## Deploy

Create the local configuration, set the policy repository identity and OIDC audience, and set the
App ID and private-key location in `.env`. Commit the policy to the trusted repository before
deploying:

```bash
cp .env.example .env
mkdir -p .secrets
# place the App PEM at .secrets/github-app-private-key.pem
make deploy-secrets
make deploy
```

The stack provisions the exchange API, Lambda, replay protection, logging, and alarms. The App ID
and private key are stored in AWS; the policy rules remain in the trusted repository. Deployment
settings can be overridden in `.env`;
`ENV_FILE=/path/to/.env make deploy` selects another environment file.

## How it works

The exchange lifecycle is roughly:

1. Receive a GitHub Actions OIDC token
1. Validate the token, fetch the trusted policy when the cache expires, and match one configured
   policy rule
1. Reject tokens that have already been exchanged
1. Mint and return a repository-scoped GitHub App token

See [`OVERVIEW.md`](./OVERVIEW.md) for the security, API, and deployment details.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
# Validate a hosted policy before a protected-branch update
HOSTED_POLICY_TEST_FILE=/path/to/.github/ost-simple-sts.json cargo test hosted_policy_example_or_override_is_valid --locked
```
