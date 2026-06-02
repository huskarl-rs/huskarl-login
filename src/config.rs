//! Login flow configuration.
//!
//! [`LoginConfig`] holds the settings that govern how the login middleware
//! handles the OAuth 2.0 Authorization Code Grant: callback and logout paths,
//! cookie attributes, session lifetime policies, and URL reconstruction for
//! proxied deployments.

use std::time::Duration;

/// Errors that can occur when building a [`LoginConfig`].
#[derive(Debug)]
pub enum ConfigError {
    /// The `callback_path` is invalid.
    InvalidCallbackPath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// The `cookie_path` is invalid.
    InvalidCookiePath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// The `base_url` is invalid.
    InvalidBaseUrl {
        /// The offending URL.
        url: String,
        /// Why the URL was rejected.
        reason: &'static str,
    },
    /// The `strip_prefix` is invalid.
    InvalidStripPrefix {
        /// The offending prefix.
        prefix: String,
        /// Why the prefix was rejected.
        reason: &'static str,
    },
    /// The `logout_path` is invalid.
    InvalidLogoutPath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCallbackPath { path, reason } => {
                write!(f, "invalid callback_path {path:?}: {reason}")
            }
            Self::InvalidCookiePath { path, reason } => {
                write!(f, "invalid cookie_path {path:?}: {reason}")
            }
            Self::InvalidBaseUrl { url, reason } => {
                write!(f, "invalid base_url {url:?}: {reason}")
            }
            Self::InvalidStripPrefix { prefix, reason } => {
                write!(f, "invalid strip_prefix {prefix:?}: {reason}")
            }
            Self::InvalidLogoutPath { path, reason } => {
                write!(f, "invalid logout_path {path:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validates that a path starts with `/`, does not contain `?`, `#`, or `;`,
/// and contains no ASCII control characters (CR/LF/NUL/etc). The control-char
/// check is defense-in-depth against header-injection attempts via misconfigured
/// paths that are later interpolated into `Set-Cookie` values.
fn validate_path(
    path: &str,
    make_error: impl FnOnce(String, &'static str) -> ConfigError,
) -> Result<(), ConfigError> {
    if !path.starts_with('/') {
        return Err(make_error(path.to_owned(), "must start with '/'"));
    }
    if path.contains('?') || path.contains('#') || path.contains(';') {
        return Err(make_error(
            path.to_owned(),
            "must not contain '?', '#', or ';'",
        ));
    }
    if path.bytes().any(|b| b.is_ascii_control()) {
        return Err(make_error(
            path.to_owned(),
            "must not contain ASCII control characters",
        ));
    }
    Ok(())
}

/// Computes the browser-facing callback path used for cookie scoping: the
/// `base_url` path joined to `callback_path` with `strip_prefix` removed.
fn compute_browser_callback_path(
    callback_path: &str,
    strip_prefix: Option<&str>,
    base_url: &http::Uri,
) -> String {
    let stripped_callback = match strip_prefix {
        Some(prefix) => callback_path.strip_prefix(prefix).unwrap_or(callback_path),
        None => callback_path,
    };
    let base_path = base_url.path().trim_end_matches('/');
    if stripped_callback.starts_with('/') {
        format!("{base_path}{stripped_callback}")
    } else {
        format!("{base_path}/{stripped_callback}")
    }
}

/// Configuration for the login middleware.
///
/// Authorization server endpoints, client credentials, and redirect URI are
/// configured on the [`LoginGrant`](crate::LoginGrant) (i.e. [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant))
/// directly.
///
/// Cookie naming for sessions is the responsibility of the [`SessionDriver`](crate::session::SessionDriver)
/// implementation.
#[derive(Debug)]
pub struct LoginConfig {
    /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
    pub callback_path: String,
    /// OAuth 2.0 scopes to request (e.g. `vec!["openid".to_owned()]`).
    pub scopes: Vec<String>,
    /// Whether to set the `Secure` flag on login-state cookies.
    ///
    /// When `true`, cookies are only sent over HTTPS connections. This should
    /// be enabled in production and may only need to be disabled for local
    /// HTTP development.
    ///
    /// Defaults to `true`.
    pub secure: bool,
    /// Absolute session cap. Sessions older than this are expired regardless
    /// of activity. `None` means no limit.
    pub max_lifetime: Option<Duration>,
    /// Kill session after inactivity. `None` means no idle timeout.
    pub idle_timeout: Option<Duration>,
    /// How early to refresh before actual token expiry.
    ///
    /// When a request arrives within this margin of the access token's expiry,
    /// the middleware will attempt a token refresh (if a refresh token is available).
    ///
    /// Defaults to 30 seconds.
    pub token_refresh_margin: Duration,
    /// Lifetime assumed when the authorization server's token response omits
    /// `expires_in`. The session's `token_expiry` is computed as
    /// `received_at + default_token_lifetime` in that case.
    ///
    /// Defaults to 1 hour.
    pub default_token_lifetime: Duration,
    /// Lifetime of the per-flow login-state cookie set during the redirect to
    /// the authorization server.
    ///
    /// The user has this long to complete authentication (including any IdP-side
    /// MFA prompts, tenant pickers, or password resets) before the callback
    /// will fail with a missing-state error.
    ///
    /// Defaults to 600 seconds (10 minutes).
    pub login_state_ttl: Duration,
    /// Minimum interval between activity "touches" for an active session.
    ///
    /// On each authenticated request, the middleware updates `last_active` and
    /// asks the adapter to persist it (`SessionPersistence::Touch`) — but only
    /// if `last_active` is older than this interval. For cookie sessions a
    /// touch re-encrypts the session and emits `Set-Cookie`; for store-backed
    /// sessions it is one write to the external store.
    ///
    /// The skipped activity is lost — pick a value comfortably below
    /// [`idle_timeout`](Self::idle_timeout) so idle expiry still fires on time.
    ///
    /// Defaults to 1 hour.
    pub touch_min_interval: Duration,
    /// `Path` attribute for login-state cookies.
    ///
    /// Restricts the browser to sending login-state cookies only on requests
    /// under this path. Defaults to `"/"`.
    ///
    /// When set to `"/"` and `secure` is `true`, the `__Host-` cookie name
    /// prefix is used for the strongest security guarantees. For sub-paths with
    /// `secure` enabled the `__Secure-` prefix is used instead.
    pub cookie_path: String,
    /// Canonical client-facing base URL of this application
    /// (e.g. `"https://app.example.com"` or `"https://app.example.com/base"`).
    ///
    /// Used to construct the absolute URL to redirect back to after login,
    /// using the scheme and authority from `base_url` with the request path
    /// appended (after stripping `strip_prefix` if configured). This is
    /// necessary when a front proxy rewrites URLs before they reach this proxy.
    pub base_url: http::Uri,
    /// Path prefix added by a front proxy that is not part of the
    /// client-facing URL (e.g. `"/internal"`).
    ///
    /// Stripped from the request path before constructing the original URL.
    /// Only used when `base_url` is set.
    pub strip_prefix: Option<String>,
    /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
    ///
    /// When set, requests to this path clear the local session and redirect,
    /// either to the authorization server's `end_session_endpoint` (if
    /// configured) or to `post_logout_redirect_uri` (or `base_url` if that is
    /// also absent). When `None`, no logout endpoint is mounted.
    pub logout_path: Option<String>,
    /// Authorization server's end-session endpoint for RP-initiated logout
    /// (OIDC RP-Initiated Logout 1.0).
    ///
    /// When set, the logout endpoint redirects here after deleting the local
    /// session. The `id_token_hint` parameter is included if the session holds
    /// an ID token, and `post_logout_redirect_uri` is appended when configured.
    ///
    /// Typically available as the `end_session_endpoint` field in the
    /// authorization server's discovery document.
    pub end_session_endpoint: Option<http::Uri>,
    /// URI to redirect to after the local session is cleared.
    ///
    /// Sent as the `post_logout_redirect_uri` query parameter when redirecting
    /// to `end_session_endpoint`. When no `end_session_endpoint` is set, used
    /// as the redirect target directly. When `None`, defaults to `base_url`.
    pub post_logout_redirect_uri: Option<String>,
    /// Prefix for login-state cookie names. Defaults to `"huskarl_login"`.
    ///
    /// The full cookie name is `{security_prefix}{login_cookie_prefix}_{state}`,
    /// where `security_prefix` is `__Host-` or `__Secure-` when `secure` is
    /// enabled. Change this to avoid conflicts with other apps on the same domain.
    pub login_cookie_prefix: String,
    /// The browser-facing callback path, computed from `base_url`, `strip_prefix`,
    /// and `callback_path`. Used as the `Path` attribute on login-state cookies
    /// so they are scoped to only the callback endpoint.
    pub browser_callback_path: String,
}

#[bon::bon]
impl LoginConfig {
    /// Builds a [`LoginConfig`] from individual settings, validating paths and
    /// the `base_url`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any path is malformed (must start with `/`,
    /// must not contain `?`, `#`, `;`, or ASCII control characters) or if
    /// `base_url` lacks a scheme/authority.
    #[builder]
    pub fn new(
        /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
        callback_path: String,
        /// OAuth 2.0 scopes to request (e.g. `vec!["openid".to_owned()]`).
        scopes: Vec<String>,
        /// Whether to set the `Secure` flag on login-state cookies. Defaults to `true`.
        #[builder(default = true)]
        secure: bool,
        /// Absolute session cap. `None` means no limit.
        max_lifetime: Option<Duration>,
        /// Kill session after inactivity. `None` means no idle timeout.
        idle_timeout: Option<Duration>,
        /// How early to refresh before actual token expiry. Defaults to 30 seconds.
        #[builder(default = Duration::from_secs(30))]
        token_refresh_margin: Duration,
        /// Lifetime assumed when the token response omits `expires_in`.
        /// Defaults to 1 hour.
        #[builder(default = Duration::from_hours(1))]
        default_token_lifetime: Duration,
        /// Lifetime of the per-flow login-state cookie. Defaults to 10 minutes.
        #[builder(default = Duration::from_mins(10))]
        login_state_ttl: Duration,
        /// Minimum interval between activity touches. Defaults to 1 hour.
        #[builder(default = Duration::from_hours(1))]
        touch_min_interval: Duration,
        /// `Path` attribute for login-state cookies. Defaults to `"/"`.
        #[builder(default = "/".to_owned())]
        cookie_path: String,
        /// Canonical client-facing base URL (e.g. `"https://app.example.com"`).
        base_url: http::Uri,
        /// Path prefix added by a front proxy to strip before constructing the original URL.
        #[builder(into)]
        strip_prefix: Option<String>,
        /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
        /// When `None`, no logout endpoint is mounted.
        #[builder(into)]
        logout_path: Option<String>,
        /// Authorization server's end-session endpoint for RP-initiated logout.
        end_session_endpoint: Option<http::Uri>,
        /// URI to redirect to after logout. Defaults to `base_url`.
        #[builder(into)]
        post_logout_redirect_uri: Option<String>,
        /// Prefix for login-state cookie names. Defaults to `"huskarl_login"`.
        #[builder(default = crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX.to_owned())]
        login_cookie_prefix: String,
    ) -> Result<Self, ConfigError> {
        validate_path(&callback_path, |path, reason| {
            ConfigError::InvalidCallbackPath { path, reason }
        })?;
        validate_path(&cookie_path, |path, reason| {
            ConfigError::InvalidCookiePath { path, reason }
        })?;
        if base_url.scheme().is_none() || base_url.authority().is_none() {
            return Err(ConfigError::InvalidBaseUrl {
                url: base_url.to_string(),
                reason: "must be an absolute URL with scheme and authority",
            });
        }
        if let Some(ref prefix) = strip_prefix {
            validate_path(prefix, |prefix, reason| ConfigError::InvalidStripPrefix {
                prefix,
                reason,
            })?;
        }
        if let Some(ref path) = logout_path {
            validate_path(path, |path, reason| ConfigError::InvalidLogoutPath {
                path,
                reason,
            })?;
        }
        let browser_callback_path =
            compute_browser_callback_path(&callback_path, strip_prefix.as_deref(), &base_url);

        Ok(Self {
            callback_path,
            scopes,
            secure,
            max_lifetime,
            idle_timeout,
            token_refresh_margin,
            default_token_lifetime,
            login_state_ttl,
            touch_min_interval,
            cookie_path,
            base_url,
            strip_prefix,
            logout_path,
            end_session_endpoint,
            post_logout_redirect_uri,
            login_cookie_prefix,
            browser_callback_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn default_policy_config() -> LoginConfig {
        LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn login_config_secure_defaults_true() {
        assert!(default_policy_config().secure);
    }

    #[test]
    fn login_config_secure_override_false() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .secure(false)
            .build()
            .unwrap();
        assert!(!config.secure);
    }

    #[test]
    fn login_config_max_lifetime_defaults_none() {
        assert!(default_policy_config().max_lifetime.is_none());
    }

    #[test]
    fn login_config_idle_timeout_defaults_none() {
        assert!(default_policy_config().idle_timeout.is_none());
    }

    #[test]
    fn login_config_token_refresh_margin_defaults_30s() {
        assert_eq!(
            default_policy_config().token_refresh_margin,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn login_config_default_token_lifetime_defaults_1h() {
        assert_eq!(
            default_policy_config().default_token_lifetime,
            Duration::from_hours(1)
        );
    }

    #[test]
    fn login_config_login_state_ttl_defaults_600s() {
        assert_eq!(
            default_policy_config().login_state_ttl,
            Duration::from_mins(10)
        );
    }

    #[test]
    fn login_config_touch_min_interval_defaults_one_hour() {
        assert_eq!(
            default_policy_config().touch_min_interval,
            Duration::from_hours(1)
        );
    }

    #[test]
    fn login_config_lifetime_fields_override() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .max_lifetime(Duration::from_hours(1))
            .idle_timeout(Duration::from_mins(15))
            .token_refresh_margin(Duration::from_mins(1))
            .default_token_lifetime(Duration::from_hours(2))
            .login_state_ttl(Duration::from_mins(30))
            .touch_min_interval(Duration::from_mins(1))
            .build()
            .unwrap();
        assert_eq!(config.max_lifetime, Some(Duration::from_hours(1)));
        assert_eq!(config.idle_timeout, Some(Duration::from_mins(15)));
        assert_eq!(config.token_refresh_margin, Duration::from_mins(1));
        assert_eq!(config.default_token_lifetime, Duration::from_hours(2));
        assert_eq!(config.login_state_ttl, Duration::from_mins(30));
        assert_eq!(config.touch_min_interval, Duration::from_mins(1));
    }

    #[test]
    fn login_config_callback_path_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
    }

    #[test]
    fn login_config_callback_path_must_not_contain_query_or_fragment() {
        for path in ["/callback?foo=bar", "/callback#section", "/callback;Secure"] {
            let err = LoginConfig::builder()
                .callback_path(path.into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .build()
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
        }
    }

    #[test]
    fn login_config_cookie_path_defaults_to_root() {
        assert_eq!(default_policy_config().cookie_path, "/");
    }

    #[test]
    fn login_config_cookie_path_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .cookie_path("app".into())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCookiePath { .. }));
    }

    #[test]
    fn login_config_cookie_path_must_not_contain_query_fragment_or_semicolon() {
        for path in ["/app?foo=bar", "/app#section", "/app;Secure"] {
            let err = LoginConfig::builder()
                .callback_path("/callback".into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .cookie_path(path.into())
                .build()
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidCookiePath { .. }));
        }
    }

    #[test]
    fn login_config_paths_reject_control_characters() {
        for path in ["/app\r\nSet-Cookie: x=y", "/app\0", "/app\n", "/app\t"] {
            let err = LoginConfig::builder()
                .callback_path("/callback".into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .cookie_path(path.into())
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidCookiePath { .. }),
                "expected reject for {path:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn login_config_base_url_must_have_scheme_and_authority() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("/just-a-path".parse().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBaseUrl { .. }));
    }

    #[test]
    fn login_config_strip_prefix_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("internal")
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidStripPrefix { .. }));
    }

    #[test]
    fn login_config_strip_prefix_must_not_contain_query_fragment_or_semicolon() {
        for prefix in ["/internal?foo", "/internal#bar", "/internal;baz"] {
            let err = LoginConfig::builder()
                .callback_path("/callback".into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .strip_prefix(prefix)
                .build()
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidStripPrefix { .. }));
        }
    }

    #[test]
    fn login_config_logout_path_defaults_none() {
        assert!(default_policy_config().logout_path.is_none());
    }

    #[test]
    fn login_config_logout_path_accepted() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout_path("/logout")
            .build()
            .unwrap();
        assert_eq!(config.logout_path.as_deref(), Some("/logout"));
    }

    #[test]
    fn login_config_logout_path_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout_path("logout")
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
    }

    #[test]
    fn login_config_logout_path_must_not_contain_query_fragment_or_semicolon() {
        for path in ["/logout?foo=bar", "/logout#section", "/logout;Secure"] {
            let err = LoginConfig::builder()
                .callback_path("/callback".into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .logout_path(path)
                .build()
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
        }
    }

    // -- browser_callback_path tests --

    #[test]
    fn browser_callback_path_simple() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }

    #[test]
    fn browser_callback_path_with_base_path() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com/base".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/base/callback");
    }

    #[test]
    fn browser_callback_path_with_strip_prefix() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }

    #[test]
    fn browser_callback_path_with_base_path_and_strip_prefix() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com/base".parse().unwrap())
            .strip_prefix("/internal")
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/base/callback");
    }

    // -- ConfigError Display tests --

    #[test]
    fn config_error_display_callback_path() {
        let err = ConfigError::InvalidCallbackPath {
            path: "foo".into(),
            reason: "must start with '/'",
        };
        let s = err.to_string();
        assert!(s.contains("callback_path"));
        assert!(s.contains("foo"));
        assert!(s.contains("must start with '/'"));
    }

    #[test]
    fn config_error_display_cookie_path() {
        let err = ConfigError::InvalidCookiePath {
            path: "bar".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("cookie_path"));
    }

    #[test]
    fn config_error_display_base_url() {
        let err = ConfigError::InvalidBaseUrl {
            url: "x".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn config_error_display_strip_prefix() {
        let err = ConfigError::InvalidStripPrefix {
            prefix: "p".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("strip_prefix"));
    }

    #[test]
    fn config_error_display_logout_path() {
        let err = ConfigError::InvalidLogoutPath {
            path: "p".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("logout_path"));
    }

    #[test]
    fn browser_callback_path_strip_prefix_no_match_uses_callback_as_is() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/other")
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }
}
