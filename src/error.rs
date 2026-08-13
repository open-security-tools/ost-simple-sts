use lambda_http::http::StatusCode;

#[derive(Debug, Clone, thiserror::Error)]
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
    #[error("subject is not allowed")]
    SubjectNotAllowed,
    #[error("repository claim missing")]
    RepositoryClaimMissing,
    #[error("invalid repository claim")]
    RepositoryClaimInvalid,
    #[error("repository is not allowed")]
    RepositoryNotAllowed,
    #[error("event is not allowed")]
    EventNotAllowed,
    #[error("workflow is not allowed")]
    WorkflowNotAllowed,
    #[error("repository_id claim missing or invalid")]
    RepositoryIdClaimInvalid,
    #[error("repository_id is not allowed")]
    RepositoryIdNotAllowed,
    #[error("exchange request is invalid")]
    InvalidExchangeRequest,
    #[error("proxy capability delivery is not configured")]
    ProxyCapabilityNotConfigured,
    #[error("proxy delivery is required")]
    ProxyDeliveryRequired,
    #[error("proxy branch is not allowed")]
    ProxyBranchNotAllowed,
    #[error("proxy capability encryption failed")]
    ProxyCapabilityEncryptionFailed,
    #[error("target repository is not allowed")]
    TargetRepositoryNotAllowed,
    #[error("target installation is not allowed")]
    TargetInstallationNotAllowed,
    #[error("requested permissions are not allowed")]
    PermissionsNotAllowed,
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
    #[error("github policy lookup failed")]
    PolicyLookupFailed,
    #[error("github request was rate limited")]
    GithubRateLimited { retry_after: std::time::Duration },
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
            Self::OidcTokenExpired => "oidc_token_expired",
            Self::InvalidOidcToken => "invalid_oidc_token",
            Self::OidcVerificationUnavailable => "oidc_verification_unavailable",
            Self::OidcTokenMissingJti => "oidc_token_missing_jti",
            Self::OidcTokenMissingExp => "oidc_token_missing_exp",
            Self::OidcTokenReplayed => "oidc_token_replayed",
            Self::JtiReplayGuardUnavailable => "jti_replay_guard_unavailable",
            Self::RefNotAllowed => "ref_not_allowed",
            Self::EnvironmentNotAllowed => "environment_not_allowed",
            Self::SubjectNotAllowed => "subject_not_allowed",
            Self::RepositoryClaimMissing => "repository_claim_missing",
            Self::RepositoryClaimInvalid => "repository_claim_invalid",
            Self::RepositoryNotAllowed => "repository_not_allowed",
            Self::EventNotAllowed => "event_not_allowed",
            Self::WorkflowNotAllowed => "workflow_not_allowed",
            Self::RepositoryIdClaimInvalid => "repository_id_claim_invalid",
            Self::RepositoryIdNotAllowed => "repository_id_not_allowed",
            Self::InvalidExchangeRequest => "invalid_exchange_request",
            Self::ProxyCapabilityNotConfigured => "proxy_capability_not_configured",
            Self::ProxyDeliveryRequired => "proxy_delivery_required",
            Self::ProxyBranchNotAllowed => "proxy_branch_not_allowed",
            Self::ProxyCapabilityEncryptionFailed => "proxy_capability_encryption_failed",
            Self::TargetRepositoryNotAllowed => "target_repository_not_allowed",
            Self::TargetInstallationNotAllowed => "target_installation_not_allowed",
            Self::PermissionsNotAllowed => "permissions_not_allowed",
            Self::GithubAppAuthInvalid => "github_app_auth_invalid",
            Self::GithubInstallationLookupForbidden => "github_installation_lookup_forbidden",
            Self::AppNotInstalled => "app_not_installed",
            Self::GithubInstallationLookupFailed => "github_installation_lookup_failed",
            Self::GithubAccessTokenRequestForbidden => "github_access_token_request_forbidden",
            Self::InstallationNotFound => "installation_not_found",
            Self::InstallationTokenRequestInvalid => "installation_token_request_invalid",
            Self::GithubAccessTokenRequestFailed => "github_access_token_request_failed",
            Self::PolicyLookupFailed => "policy_lookup_failed",
            Self::GithubRateLimited { .. } => "github_rate_limited",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::PolicyNotConfigured
            | Self::InvalidPolicy
            | Self::AppIdNotConfigured
            | Self::AppPrivateKeyNotConfigured
            | Self::JtiTableNotConfigured
            | Self::InvalidGithubApiUrl => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MissingBearerToken
            | Self::OidcTokenExpired
            | Self::OidcTokenMissingJti
            | Self::OidcTokenMissingExp
            | Self::InvalidOidcToken => StatusCode::UNAUTHORIZED,
            Self::OidcVerificationUnavailable | Self::JtiReplayGuardUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::ProxyCapabilityNotConfigured => StatusCode::NOT_IMPLEMENTED,
            Self::OidcTokenReplayed => StatusCode::CONFLICT,
            Self::RefNotAllowed
            | Self::EnvironmentNotAllowed
            | Self::SubjectNotAllowed
            | Self::RepositoryClaimMissing
            | Self::RepositoryClaimInvalid
            | Self::RepositoryNotAllowed
            | Self::EventNotAllowed
            | Self::WorkflowNotAllowed
            | Self::RepositoryIdClaimInvalid
            | Self::RepositoryIdNotAllowed
            | Self::TargetRepositoryNotAllowed
            | Self::TargetInstallationNotAllowed
            | Self::PermissionsNotAllowed
            | Self::ProxyDeliveryRequired
            | Self::ProxyBranchNotAllowed
            | Self::AppNotInstalled
            | Self::InstallationNotFound => StatusCode::FORBIDDEN,
            Self::GithubAppAuthInvalid
            | Self::GithubInstallationLookupForbidden
            | Self::GithubAccessTokenRequestForbidden => StatusCode::FAILED_DEPENDENCY,
            Self::GithubInstallationLookupFailed
            | Self::GithubAccessTokenRequestFailed
            | Self::PolicyLookupFailed
            | Self::ProxyCapabilityEncryptionFailed
            | Self::GithubRateLimited { .. } => StatusCode::BAD_GATEWAY,
            Self::InstallationTokenRequestInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::InvalidExchangeRequest => StatusCode::BAD_REQUEST,
        }
    }
}
