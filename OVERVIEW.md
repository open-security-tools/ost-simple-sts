┌──────────────────────────────────────────────────────────────────────┐
│                             ost-simple-sts                           │
└──────────────────────────────────────────────────────────────────────┘

                                 HTTP / Lambda
                                       │
                                       ▼
                              ┌────────────────┐
                              │   src/main.rs  │
                              │----------------│
                              │ route request  │
                              │ map response   │
                              └───────┬────────┘
                                      │
                                      ▼
                            ┌────────────────────┐
                            │ src/exchange.rs    │
                            │--------------------│
                            │ verify OIDC claims │
                            │ replay guard       │
                            │ mint app token     │
                            └───────┬────────────┘
                                    │
            ┌───────────────────────┼──────────────────────────────┐
            ▼                       ▼                              ▼
 ┌──────────────────┐   ┌──────────────────────┐      ┌─────────────────────┐
 │ src/jwks.rs      │   │ src/replay.rs        │      │ src/github.rs       │
 │------------------│   │----------------------│      │---------------------│
 │ JWKS cache + TTL │   │ DynamoDB jti claim   │      │ app jwt auth        │
 │ kid -> key       │   │ conditional put_item │      │ installation lookup │
 │ OIDC key fetch   │   │ replay detection     │      │ token minting       │
 └─────────┬────────┘   └──────────┬───────────┘      └───────────┬─────────┘
           │                       │                               │
           ▼                       ▼                               ▼
  ┌──────────────────┐   ┌──────────────────┐           ┌──────────────────┐
  │ src/config.rs    │   │ src/error.rs     │           │ src/response.rs  │
  │------------------│   │------------------│           │------------------│
  │ validated policy │   │ stable error code│           │ JSON success/err │
  │ app id / key     │   │ + HTTP status    │           │ no-store headers │
  │ api base / client│   └──────────────────┘           └──────────────────┘
  └──────────────────┘


Data flow summary
=================

1. `/exchange` receives GitHub Actions OIDC JWT
2. JWT is validated against Actions JWKS + policy constraints
3. `jti` is claimed in DynamoDB to prevent replay
4. GitHub App JWT is minted from configured app id/private key
5. App installation is resolved for repository
6. Installation token is minted and returned to caller


Key validated domain types
==========================

- `Policy`, `Audience`, `GitRef`, `WorkflowPath`, `EnvironmentName`
- `RepositoryFullName`, `RepositoryOwner`, `RepositoryNamePart`, `RepositoryId`
- `GithubApiBase`, `JtiTableName`, `Jti`, `ExpiresInMinutes`

These types reduce stringly-typed checks across the request path.
