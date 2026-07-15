use lambda_http::http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("policy is not configured")]
    PolicyNotConfigured,
    #[error("policy is invalid")]
    InvalidPolicy,
    #[error("app id is not configured")]
    AppIdNotConfigured,
    #[error("app private key is not configured")]
    AppPrivateKeyNotConfigured,
    #[error("jti table name is not configured")]
    JtiTableNotConfigured,
    #[error("github api url is invalid")]
    InvalidGithubApiUrl,
    #[error("not found")]
    NotFound,
    #[error("missing bearer token")]
    MissingBearerToken,
    #[error("invalid expires_in")]
    InvalidExpiresIn,
    #[error("oidc token expired")]
    OidcTokenExpired,
    #[error("invalid oidc token")]
    InvalidOidcToken,
    #[error("oidc verification unavailable")]
    OidcVerificationUnavailable,
    #[error("oidc token missing jti")]
    OidcTokenMissingJti,
    #[error("oidc token missing exp")]
    OidcTokenMissingExp,
    #[error("oidc token replayed")]
    OidcTokenReplayed,
    #[error("jti replay guard unavailable")]
    JtiReplayGuardUnavailable,
    #[error("ref is not allowed")]
    RefNotAllowed,
    #[error("environment is not allowed")]
    EnvironmentNotAllowed,
    #[error("repository claim missing")]
    RepositoryClaimMissing,
    #[error("invalid repository claim")]
    RepositoryClaimInvalid,
    #[error("only workflow_dispatch events are allowed")]
    EventNotAllowed,
    #[error("workflow is not allowed")]
    WorkflowNotAllowed,
    #[error("repository_id claim missing or invalid")]
    RepositoryIdClaimInvalid,
    #[error("github app authentication failed")]
    GithubAppAuthInvalid,
    #[error("github rejected installation lookup")]
    GithubInstallationLookupForbidden,
    #[error("app is not installed on repository")]
    AppNotInstalled,
    #[error("github installation lookup failed")]
    GithubInstallationLookupFailed,
    #[error("github rejected access token request")]
    GithubAccessTokenRequestForbidden,
    #[error("repository installation is not available")]
    InstallationNotFound,
    #[error("repository or permissions are not allowed for this installation")]
    InstallationTokenRequestInvalid,
    #[error("github access token request failed")]
    GithubAccessTokenRequestFailed,
    #[error("token exchange failed")]
    TokenExchangeFailed,
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PolicyNotConfigured => "policy_not_configured",
            Self::InvalidPolicy => "invalid_policy",
            Self::AppIdNotConfigured => "app_id_not_configured",
            Self::AppPrivateKeyNotConfigured => "app_private_key_not_configured",
            Self::JtiTableNotConfigured => "jti_table_not_configured",
            Self::InvalidGithubApiUrl => "invalid_github_api_url",
            Self::NotFound => "not_found",
            Self::MissingBearerToken => "missing_bearer_token",
            Self::InvalidExpiresIn => "invalid_expires_in",
            Self::OidcTokenExpired => "oidc_token_expired",
            Self::InvalidOidcToken => "invalid_oidc_token",
            Self::OidcVerificationUnavailable => "oidc_verification_unavailable",
            Self::OidcTokenMissingJti => "oidc_token_missing_jti",
            Self::OidcTokenMissingExp => "oidc_token_missing_exp",
            Self::OidcTokenReplayed => "oidc_token_replayed",
            Self::JtiReplayGuardUnavailable => "jti_replay_guard_unavailable",
            Self::RefNotAllowed => "ref_not_allowed",
            Self::EnvironmentNotAllowed => "environment_not_allowed",
            Self::RepositoryClaimMissing => "repository_claim_missing",
            Self::RepositoryClaimInvalid => "repository_claim_invalid",
            Self::EventNotAllowed => "event_not_allowed",
            Self::WorkflowNotAllowed => "workflow_not_allowed",
            Self::RepositoryIdClaimInvalid => "repository_id_claim_invalid",
            Self::GithubAppAuthInvalid => "github_app_auth_invalid",
            Self::GithubInstallationLookupForbidden => "github_installation_lookup_forbidden",
            Self::AppNotInstalled => "app_not_installed",
            Self::GithubInstallationLookupFailed => "github_installation_lookup_failed",
            Self::GithubAccessTokenRequestForbidden => "github_access_token_request_forbidden",
            Self::InstallationNotFound => "installation_not_found",
            Self::InstallationTokenRequestInvalid => "installation_token_request_invalid",
            Self::GithubAccessTokenRequestFailed => "github_access_token_request_failed",
            Self::TokenExchangeFailed => "token_exchange_failed",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::PolicyNotConfigured
            | Self::InvalidPolicy
            | Self::AppIdNotConfigured
            | Self::AppPrivateKeyNotConfigured
            | Self::JtiTableNotConfigured
            | Self::InvalidGithubApiUrl
            | Self::TokenExchangeFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MissingBearerToken
            | Self::OidcTokenExpired
            | Self::OidcTokenMissingJti
            | Self::OidcTokenMissingExp
            | Self::InvalidOidcToken => StatusCode::UNAUTHORIZED,
            Self::InvalidExpiresIn => StatusCode::BAD_REQUEST,
            Self::OidcVerificationUnavailable | Self::JtiReplayGuardUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::OidcTokenReplayed => StatusCode::CONFLICT,
            Self::RefNotAllowed
            | Self::EnvironmentNotAllowed
            | Self::RepositoryClaimMissing
            | Self::RepositoryClaimInvalid
            | Self::EventNotAllowed
            | Self::WorkflowNotAllowed
            | Self::RepositoryIdClaimInvalid
            | Self::AppNotInstalled
            | Self::InstallationNotFound => StatusCode::FORBIDDEN,
            Self::GithubAppAuthInvalid
            | Self::GithubInstallationLookupForbidden
            | Self::GithubAccessTokenRequestForbidden => StatusCode::FAILED_DEPENDENCY,
            Self::GithubInstallationLookupFailed | Self::GithubAccessTokenRequestFailed => {
                StatusCode::BAD_GATEWAY
            }
            Self::InstallationTokenRequestInvalid => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}
