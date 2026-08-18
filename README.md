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

Set `audience` to the stack's `PolicyAudience` output and `exchange-url` to the same URL followed
by `/exchange`. The deployment uses its API URL as the OIDC audience by default; set
`POLICY_AUDIENCE` only when overriding it for a custom HTTPS endpoint. Set `repository` to the
requested target repository and list one GitHub App repository permission per line in
`permissions`. The action returns a short-lived token and revokes it when the job finishes,
including after a failed step. Do not pass the token to another job. Pin actions to a commit SHA in
production.

## GitHub App

For the examples below, the GitHub App needs the following repository permissions:

- **Contents**: read and write
- **Metadata**: read-only

Install the App on the repository that owns the policy and each target repository allowed by the
policy; it does not need to be installed on a separate calling repository. The policy reader
requests only `contents: read` for the pinned policy repository. Exchanges request only the
permissions selected by the caller and allowed by the matched policy rule.
`administration: write` is not supported because some GitHub endpoints apply it beyond
the selected existing repositories; `administration: read` remains available.

## Policy

The checked-in [`policy-example.json`](./policy-example.json) is an example only. Copy it to
`.github/ost-simple-sts.json` in the trusted policy repository and replace every example value for
the calling repository:

```json
{
  "version": 2,
  "repositories": {
    "example-repo": {
      "name": "example-org/example-repo",
      "id": 789012,
      "oidc_subject": "immutable",
      "owner_id": 123456
    }
  },
  "rules": [
    {
      "caller": "example-repo",
      "environment": "release",
      "caller_workflow": "release.yml",
      "on": ["workflow_dispatch"],
      "permissions": { "contents": "write" },
      "target": "example-repo"
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

`version: 2`, a non-empty `repositories` map, and a non-empty `rules` list are required. Each
repository alias pins its name and immutable ID and declares the OIDC subject format. Use
`oidc_subject: "legacy"` for `repo:OWNER/REPO` subjects and `oidc_subject: "immutable"` with an
`owner_id` for `repo:OWNER@OWNER_ID/REPO@REPOSITORY_ID` subjects. The broker derives the exact
subject from the caller repository, its configured format, and `environment` (or `caller_ref` when
no environment is set), so callers cannot accidentally mix the two formats.

Each rule names a `caller`, a `caller_workflow` filename under `.github/workflows`, a non-empty `on`
event list, and an explicit `permissions` ceiling. `caller_ref` defaults to `refs/heads/main`; set
`reusable_workflow` when the token is requested by a reusable workflow so its `job_workflow_ref`
must match as well. `on` can contain only `issue_comment`, `issues`, `push`, `pull_request`,
`schedule`, and `workflow_dispatch`; empty or duplicate event lists are rejected. Requests can
select a subset or lower permission level, but never an additional or broader permission.

`target` names one repository alias. A multi-repository rule instead sets `targets` to a list of at
least two authorized aliases and `installation` to an alias in the top-level `installations` map.
A request can select one authorized target with `repository` or a subset of at least two with
`repositories`; the issued token is scoped only to the requested repositories. Singular and plural
targets are mutually exclusive, and an explicit target always requires an explicit matching
exchange request, even when it is the caller repository. Unknown fields and aliases, duplicate
repository names or IDs, duplicate permissions, and overlapping identity rules are rejected so a
later target or permission grant cannot be silently shadowed.

For `pull_request` runs, set `caller_ref` to `refs/pull/*/merge` to match only canonical
pull-request merge refs. This pattern is valid only with `on: ["pull_request"]`.

See [`EXAMPLES.md`](./EXAMPLES.md) for cross-repository and reusable-workflow policy examples.

The derived subject must exactly match the OIDC subject emitted by the calling job. Always pin the
immutable repository ID; find repository and owner IDs with:

```bash
gh api repos/OWNER/REPO --jq '{repository_id: .id, owner_id: .owner.id}'
```

Keep the environment's deployment rules restricted to the intended branch.

The broker continues to accept `version: 1` policies during migration. Those policies retain the
explicit `subject`, repository name/ID pairs, workflow paths, `allowed_events`, and target fields;
the compatibility defaults for events and permissions are unchanged.

The policy is fetched from the configured repository name and immutable ID, the protected `main`
ref, and the configured path under `.github`. Protect the default branch with a pull-request
ruleset that cannot be bypassed by an issued token. A successfully parsed policy is cached for up
to five minutes; invalid, unavailable, or rate-limited refreshes fail closed and cannot authorize
an exchange.

## Deploy

Create the local configuration, set the policy repository identity, and set the App ID and
private-key location in `.env`. The OIDC audience defaults to the deployed API URL; set
`POLICY_AUDIENCE` only when using a custom HTTPS endpoint. Commit the policy to the trusted
repository before deploying:

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

## License

Licensed under either the Apache License, Version 2.0, or the MIT license, at
your option. See [LICENSE](LICENSE) for the full license texts.
