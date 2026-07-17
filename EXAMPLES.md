# Policy examples

These examples use fictional repositories and repository IDs. Replace them with the identities and
workflow paths from your installation.

## Cross-repository fork sync

A workflow in one repository can update a different repository without granting the caller access.
This rule lets a fork-sync workflow in `octo-org/widgets` receive a token scoped only to
`octo-org/widgets-dev`:

```json
{
  "subject": "repo:octo-org/widgets:environment:automations",
  "repository": "octo-org/widgets",
  "repository_id": 123456789,
  "ref": "refs/heads/main",
  "workflow_path": ".github/workflows/sync-fork.yml",
  "environment": "automations",
  "allowed_events": ["push", "workflow_dispatch"],
  "permissions": { "contents": "write" },
  "target_repository": "octo-org/widgets-dev",
  "target_repository_id": 987654321
}
```

The workflow requests the target and permission explicitly:

```yaml
repository: octo-org/widgets-dev
permissions: |
  contents: write
```

The scalar spelling `permissions: contents:write` is also accepted for a single permission. The App
is installed on `octo-org/widgets-dev`, and the returned token has `contents: write` only for that
repository. The `repository` action output reports the target repository. A cross-repository rule
requires an explicit matching request; it cannot be exchanged using the legacy empty request.

## Multi-repository pull-request publisher

A workflow can request one installation token scoped to an exact set of repositories when the
source branch and destination pull request live in different repositories. Both repositories must
belong to the same App installation. `permissions` is one permission ceiling applied to every
repository in `target_repositories`; it cannot grant different permissions per target:

```json
{
  "subject": "repo:octo-org/widgets-dev:environment:automations",
  "repository": "octo-org/widgets-dev",
  "repository_id": 987654321,
  "ref": "refs/heads/main",
  "workflow_path": ".github/workflows/promote-pull-request.yml",
  "environment": "automations",
  "allowed_events": ["workflow_dispatch"],
  "permissions": { "contents": "write", "pull_requests": "write" },
  "target_repositories": [
    { "repository": "octo-org/widgets", "repository_id": 123456789 },
    { "repository": "octo-org/widgets-dev", "repository_id": 987654321 }
  ],
  "target_installation_id": 24680
}
```

The workflow requests the complete target set and permission map explicitly:

```yaml
repositories: |
  octo-org/widgets
  octo-org/widgets-dev
permissions: |
  contents: write
  pull_requests: write
```

The `repositories` action output contains the authorized repositories, one per line. Singular
`repository` and plural `repositories` inputs are mutually exclusive, and a plural request must
exactly match its policy rule; a subset or a combination of targets from different rules is denied.

GitHub applies one permission map to every repository in an installation token. Creating a
cross-repository pull request requires write access to the source branch, so `pull_requests: write`
alone is insufficient: the practical grant is `contents: write` and `pull_requests: write` across
both repositories. Add `workflows: write` only when the workflow actually pushes a branch that can
change `.github/workflows`.

## Reusable pull-request publisher

A reusable workflow called by CI on pull requests can be scoped separately. This rule binds both the
CI caller and the reusable publisher and issues only pull-request write access for
`octo-org/widgets`:

```json
{
  "subject": "repo:octo-org/widgets:environment:automations",
  "repository": "octo-org/widgets",
  "repository_id": 123456789,
  "ref": "refs/pull/*/merge",
  "workflow_path": ".github/workflows/ci.yml",
  "job_workflow_path": ".github/workflows/publish-review.yml",
  "environment": "automations",
  "allowed_events": ["pull_request"],
  "permissions": { "pull_requests": "write" },
  "target_repository": "octo-org/widgets",
  "target_repository_id": 123456789
}
```
