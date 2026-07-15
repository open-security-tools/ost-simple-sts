# Architecture

```text
HTTP / Lambda
  └── src/main.rs              route requests and map responses
      └── src/exchange.rs      verify OIDC claims, prevent replay, and mint a token
          ├── src/jwks.rs      cache GitHub Actions signing keys
          ├── src/replay.rs    conditionally claim the OIDC jti in DynamoDB
          └── src/github/
              ├── api.rs       validated API base, headers, and bounded GET retries
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
1. The repository installation is resolved.
1. A repository-scoped installation token is minted and returned to the caller.

## Validated domain types

- `Policy`, `PolicyRule`, `Audience`, `Subject`, `GitRef`, `WorkflowPath`, `EnvironmentName`
- `RepositoryFullName`, `RepositoryOwner`, `RepositoryNamePart`, `RepositoryId`
- `GithubApiBase`, `JtiTableName`, `Jti`, `Token`

These types keep validation and redaction close to the request boundary.
