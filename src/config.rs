//! Login flow configuration.
//!
//! [`LoginConfig`] holds the settings that govern how the login middleware
//! handles the OAuth 2.0 Authorization Code Grant: callback and logout paths,
//! cookie attributes, session lifetime policies, and URL reconstruction for
//! proxied deployments.

use std::time::Duration;

use http::HeaderMap;

use crate::engine::{is_cross_site_request, is_navigation_request};

/// Which requests count as user "activity" for server-side liveness tracking.
///
/// Idle timeout should approximate "the human stopped interacting," but not
/// every authenticated request reflects a human: background polling, prefetch,
/// service-worker fetches, and cross-site embeds all generate traffic that
/// would otherwise keep an abandoned session alive. This policy classifies each
/// request — from its fetch-metadata headers — as activity or not; only
/// activity advances `last_active`. Idle *expiry* is enforced on every request
/// regardless of this policy.
///
/// Defaults to [`FirstParty`](Self::FirstParty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ActivityPolicy {
    /// Only top-level browser navigations count (`Sec-Fetch-Mode: navigate` or
    /// `Sec-Fetch-Dest: document`). Tightest idle semantics — suitable for
    /// multi-page apps, but breaks fetch-driven SPAs: an active user who only
    /// triggers XHR/fetch generates no navigations and would idle out.
    NavigationsOnly,
    /// First-party requests count: everything *except* cross-site requests that
    /// are not themselves top-level navigations. Excludes cross-site embeds,
    /// beacons, and other origins' CORS calls, while still counting same-origin
    /// SPA fetches and genuine inbound link navigations. Requests without
    /// fetch-metadata (older clients, non-browser agents) are treated as
    /// first-party and count.
    ///
    /// Note: this cannot distinguish same-origin background polling from human
    /// interaction — the browser sends no user-activation signal on fetch — so
    /// a continuously-polling SPA still registers as active.
    #[default]
    FirstParty,
    /// Every authenticated request counts as activity.
    AllRequests,
}

impl ActivityPolicy {
    /// Returns whether a request with these headers should advance the
    /// session's `last_active` timestamp under this policy.
    #[must_use]
    pub fn counts_as_activity(self, headers: &HeaderMap) -> bool {
        match self {
            Self::NavigationsOnly => is_navigation_request(headers),
            Self::FirstParty => !is_cross_site_request(headers) || is_navigation_request(headers),
            Self::AllRequests => true,
        }
    }
}

/// Errors that can occur when building a [`LoginConfig`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    /// The `callback_path` is invalid.
    InvalidCallbackPath {
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
    /// The logout `path` is invalid.
    InvalidLogoutPath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// The `post_logout_redirect_uri` is invalid.
    InvalidPostLogoutRedirectUri {
        /// The offending URL.
        url: String,
        /// Why the URL was rejected.
        reason: &'static str,
    },
    /// The `login_cookie_prefix` is invalid.
    InvalidLoginCookiePrefix {
        /// The offending prefix.
        prefix: String,
        /// Why the prefix was rejected.
        reason: &'static str,
    },
    /// A duration setting holds a nonsensical value (e.g. zero, or a refresh
    /// margin that meets or exceeds the assumed token lifetime).
    InvalidDuration {
        /// The name of the offending field.
        field: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCallbackPath { path, reason } => {
                write!(f, "invalid callback_path {path:?}: {reason}")
            }
            Self::InvalidBaseUrl { url, reason } => {
                write!(f, "invalid base_url {url:?}: {reason}")
            }
            Self::InvalidStripPrefix { prefix, reason } => {
                write!(f, "invalid strip_prefix {prefix:?}: {reason}")
            }
            Self::InvalidLogoutPath { path, reason } => {
                write!(f, "invalid logout path {path:?}: {reason}")
            }
            Self::InvalidPostLogoutRedirectUri { url, reason } => {
                write!(f, "invalid post_logout_redirect_uri {url:?}: {reason}")
            }
            Self::InvalidLoginCookiePrefix { prefix, reason } => {
                write!(f, "invalid login_cookie_prefix {prefix:?}: {reason}")
            }
            Self::InvalidDuration { field, reason } => {
                write!(f, "invalid {field}: {reason}")
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

/// Validates the lifetime/interval settings against each other. A zero value
/// silently breaks the flow it governs (`default_token_lifetime` /
/// `login_state_ttl` of zero expire on issue, `Some(ZERO)` `max_lifetime` locks
/// every session out immediately), and a refresh margin at or above the assumed
/// token lifetime classifies tokens as expiring the instant they're issued —
/// refreshing on every request.
fn validate_durations(
    max_lifetime: Option<Duration>,
    token_refresh_margin: Duration,
    default_token_lifetime: Duration,
    login_state_ttl: Duration,
) -> Result<(), ConfigError> {
    let zero = |field| ConfigError::InvalidDuration {
        field,
        reason: "must be greater than zero",
    };
    if default_token_lifetime.is_zero() {
        return Err(zero("default_token_lifetime"));
    }
    if login_state_ttl.is_zero() {
        return Err(zero("login_state_ttl"));
    }
    if max_lifetime == Some(Duration::ZERO) {
        return Err(ConfigError::InvalidDuration {
            field: "max_lifetime",
            reason: "must be greater than zero (use None for no limit)",
        });
    }
    if token_refresh_margin >= default_token_lifetime {
        return Err(ConfigError::InvalidDuration {
            field: "token_refresh_margin",
            reason: "must be less than default_token_lifetime",
        });
    }
    Ok(())
}

/// Computes the browser-facing callback path used for cookie scoping: the
/// `base_url` path joined to `callback_path` with `strip_prefix` removed.
///
/// `LoginConfig::new` has already rejected a `callback_path` that doesn't
/// start with `strip_prefix`, so the `unwrap_or` fallback is unreachable —
/// kept only for totality.
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

/// Logout endpoint configuration.
///
/// Grouped under [`LoginConfig::logout`] so the dependency is structural: an
/// end-session endpoint or post-logout redirect cannot be configured without
/// the logout endpoint they belong to.
///
/// Validation (path shape, absolute redirect URI, `strip_prefix`
/// consistency) happens when the value is passed to [`LoginConfig::builder`].
#[derive(Debug)]
#[non_exhaustive]
pub struct LogoutConfig {
    /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
    ///
    /// Requests to this path clear the local session and redirect: to
    /// [`end_session_endpoint`](Self::end_session_endpoint) when configured,
    /// otherwise to
    /// [`post_logout_redirect_uri`](Self::post_logout_redirect_uri) (or
    /// `base_url` when that is also absent).
    pub path: String,
    /// Authorization server's end-session endpoint for RP-initiated logout
    /// (OIDC RP-Initiated Logout 1.0).
    ///
    /// When set, the logout endpoint redirects here after deleting the local
    /// session. The request includes the `client_id` (from the grant, so the
    /// OP can identify this RP and validate the redirect target) and an
    /// `id_token_hint` when the session holds an ID token; the
    /// `post_logout_redirect_uri` is appended when configured.
    ///
    /// Typically available as the `end_session_endpoint` field in the
    /// authorization server's discovery document.
    pub end_session_endpoint: Option<http::Uri>,
    /// Absolute URI to redirect to after the local session is cleared.
    ///
    /// Sent as the `post_logout_redirect_uri` query parameter when
    /// redirecting to `end_session_endpoint`. When no `end_session_endpoint`
    /// is set, used as the redirect target directly. When `None`, defaults
    /// to `base_url`.
    ///
    /// # Must be registered at the authorization server
    ///
    /// Per OIDC RP-Initiated Logout 1.0 §3, the OP performs post-logout
    /// redirection only if this value *exactly matches* one of the RP's
    /// previously registered `post_logout_redirect_uris`. Register it — and
    /// the `base_url` default, if you rely on it — at the authorization
    /// server, or the OP will drop the redirect and strand the user on its own
    /// logout page, regardless of the `client_id` / `id_token_hint` the engine
    /// sends.
    pub post_logout_redirect_uri: Option<http::Uri>,
}

#[bon::bon]
impl LogoutConfig {
    /// Creates a logout configuration.
    #[builder]
    pub fn new(
        /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
        #[builder(into)]
        path: String,
        /// Authorization server's end-session endpoint for RP-initiated logout.
        end_session_endpoint: Option<http::Uri>,
        /// Absolute URI to redirect to after logout. Defaults to `base_url`.
        post_logout_redirect_uri: Option<http::Uri>,
    ) -> Self {
        Self {
            path,
            end_session_endpoint,
            post_logout_redirect_uri,
        }
    }
}

/// Configuration for the login middleware.
///
/// Authorization server endpoints, client credentials, and redirect URI are
/// configured on the
/// [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant)
/// directly.
///
/// Cookie naming and the `Path` attribute for session cookies are the
/// responsibility of the [`SessionDriver`](crate::session::SessionDriver)
/// implementation — see the `cookie_path` builder setting on
/// [`CookieSessionStore`](crate::CookieSessionStore) and
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore). Login-state
/// cookies are scoped automatically to
/// [`browser_callback_path`](Self::browser_callback_path).
///
/// This struct is `#[non_exhaustive]`: it can only be constructed through
/// [`builder`](Self::builder), so a value of this type always carries the
/// builder's validation as an invariant (cookie-safe paths, absolute URLs,
/// `strip_prefix` consistency, derived `browser_callback_path`).
#[derive(Debug)]
#[non_exhaustive]
pub struct LoginConfig {
    /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
    pub callback_path: String,
    /// OAuth 2.0 scopes to request (e.g. `vec!["openid".to_owned()]`).
    pub scopes: Vec<String>,
    /// Whether to set the `Secure` flag (and `__Host-`/`__Secure-` cookie name
    /// prefixes) on the cookies this deployment issues.
    ///
    /// Not set directly — **derived** from [`base_url`](Self::base_url): `true`
    /// when its scheme is `https`, `false` for `http`. The `Secure` attribute
    /// and `__Host-` prefix are statements about the browser-facing connection,
    /// which is exactly what `base_url`'s scheme describes, so this is the
    /// single source of truth. The engine stamps the same value onto the
    /// session store at construction (see
    /// [`SessionDriver::apply_cookie_secure`](crate::SessionDriver::apply_cookie_secure)),
    /// so login-state and session cookies can never disagree.
    ///
    /// Use an `http://` base URL for local development; it yields unprefixed,
    /// non-`Secure` cookies that the browser will send over plain HTTP.
    pub secure: bool,
    /// Absolute session cap. Sessions older than this are expired regardless
    /// of activity. `None` means no limit.
    ///
    /// This is the only lifetime bound enforced for cookie sessions. Idle
    /// timeout is server-side only and configured separately on the liveness
    /// store — see [`LivenessConfig`](crate::LivenessConfig) and
    /// [`StoreBackedSessionStore::with_liveness`](crate::StoreBackedSessionStore::with_liveness).
    pub max_lifetime: Option<Duration>,
    /// Which requests count as user activity for server-side liveness tracking.
    ///
    /// Only affects sessions with a liveness store; idle expiry is always
    /// enforced regardless. Defaults to [`ActivityPolicy::FirstParty`].
    pub activity_policy: ActivityPolicy,
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
    /// This is also what bounds the accumulation of abandoned flows: each
    /// login redirect sets a per-flow cookie named by its `state` (scoped to
    /// the callback path) with `Max-Age` set to this TTL, so a tab the user
    /// never completes clears itself from the browser within this window.
    /// There is no separate server-side cap — the `Max-Age` is the bound.
    ///
    /// Defaults to 600 seconds (10 minutes).
    pub login_state_ttl: Duration,
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
    /// Logout endpoint configuration. When `None`, no logout endpoint is
    /// mounted — and structurally, no logout-dependent settings (end-session
    /// endpoint, post-logout redirect) can exist without it.
    pub logout: Option<LogoutConfig>,
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
        /// Absolute session cap. `None` means no limit.
        max_lifetime: Option<Duration>,
        /// Which requests count as user activity for liveness. Defaults to
        /// [`ActivityPolicy::FirstParty`].
        #[builder(default)]
        activity_policy: ActivityPolicy,
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
        /// Canonical client-facing base URL (e.g. `"https://app.example.com"`).
        base_url: http::Uri,
        /// Path prefix added by a front proxy to strip before constructing the original URL.
        #[builder(into)]
        strip_prefix: Option<String>,
        /// Logout endpoint configuration. When `None`, no logout endpoint is
        /// mounted.
        logout: Option<LogoutConfig>,
        /// Prefix for login-state cookie names. Defaults to `"huskarl_login"`.
        #[builder(default = crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX.to_owned())]
        login_cookie_prefix: String,
    ) -> Result<Self, ConfigError> {
        validate_path(&callback_path, |path, reason| {
            ConfigError::InvalidCallbackPath { path, reason }
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
        if let Some(ref logout) = logout {
            validate_path(&logout.path, |path, reason| {
                ConfigError::InvalidLogoutPath { path, reason }
            })?;
            if let Some(ref uri) = logout.post_logout_redirect_uri
                && (uri.scheme().is_none() || uri.authority().is_none())
            {
                return Err(ConfigError::InvalidPostLogoutRedirectUri {
                    url: uri.to_string(),
                    reason: "must be an absolute URL with scheme and authority",
                });
            }
        }
        // Engine-side paths carry the front proxy's prefix; a path outside it
        // would silently never match a real request (and, for the callback,
        // corrupt the derived cookie scope) — reject the contradiction.
        if let Some(ref prefix) = strip_prefix {
            if !callback_path.starts_with(prefix.as_str()) {
                return Err(ConfigError::InvalidCallbackPath {
                    path: callback_path,
                    reason: "must start with strip_prefix when strip_prefix is set",
                });
            }
            if let Some(ref logout) = logout
                && !logout.path.starts_with(prefix.as_str())
            {
                return Err(ConfigError::InvalidLogoutPath {
                    path: logout.path.clone(),
                    reason: "must start with strip_prefix when strip_prefix is set",
                });
            }
        }
        if login_cookie_prefix.is_empty() {
            return Err(ConfigError::InvalidLoginCookiePrefix {
                prefix: login_cookie_prefix,
                reason: "must not be empty",
            });
        }
        // The prefix is interpolated into cookie names; anything outside this
        // set either breaks Set-Cookie syntax or fails to round-trip.
        if !login_cookie_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(ConfigError::InvalidLoginCookiePrefix {
                prefix: login_cookie_prefix,
                reason: "must contain only ASCII letters, digits, '_', or '-'",
            });
        }
        validate_durations(
            max_lifetime,
            token_refresh_margin,
            default_token_lifetime,
            login_state_ttl,
        )?;

        let browser_callback_path =
            compute_browser_callback_path(&callback_path, strip_prefix.as_deref(), &base_url);
        // Single source of truth for cookie security: the browser-facing scheme.
        // `base_url` is validated above to have a scheme, so this is decisive.
        let secure = base_url.scheme_str() == Some("https");

        Ok(Self {
            callback_path,
            scopes,
            secure,
            max_lifetime,
            activity_policy,
            token_refresh_margin,
            default_token_lifetime,
            login_state_ttl,
            base_url,
            strip_prefix,
            logout,
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
    fn login_config_secure_derived_true_for_https_base_url() {
        assert!(default_policy_config().secure);
    }

    #[test]
    fn login_config_secure_derived_false_for_http_base_url() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("http://localhost:6188".parse().unwrap())
            .build()
            .unwrap();
        assert!(!config.secure);
    }

    #[test]
    fn login_config_max_lifetime_defaults_none() {
        assert!(default_policy_config().max_lifetime.is_none());
    }

    #[test]
    fn rejects_zero_default_token_lifetime() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .default_token_lifetime(Duration::ZERO)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidDuration {
                field: "default_token_lifetime",
                ..
            }
        ));
    }

    #[test]
    fn rejects_zero_login_state_ttl() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .login_state_ttl(Duration::ZERO)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidDuration {
                field: "login_state_ttl",
                ..
            }
        ));
    }

    #[test]
    fn rejects_zero_max_lifetime_but_allows_none() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .max_lifetime(Duration::ZERO)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidDuration {
                field: "max_lifetime",
                ..
            }
        ));
        // None (the default) stays valid — it means "no absolute cap".
        assert!(default_policy_config().max_lifetime.is_none());
    }

    #[test]
    fn rejects_refresh_margin_at_or_above_token_lifetime() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .default_token_lifetime(Duration::from_secs(60))
            .token_refresh_margin(Duration::from_secs(60))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidDuration {
                field: "token_refresh_margin",
                ..
            }
        ));
    }

    #[test]
    fn login_config_activity_policy_defaults_first_party() {
        assert_eq!(
            default_policy_config().activity_policy,
            ActivityPolicy::FirstParty
        );
    }

    fn req(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn first_party_counts_same_origin_fetch() {
        let h = req(&[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
        ]);
        assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
    }

    #[test]
    fn first_party_excludes_cross_site_fetch() {
        let h = req(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]);
        assert!(!ActivityPolicy::FirstParty.counts_as_activity(&h));
    }

    #[test]
    fn first_party_counts_cross_site_navigation() {
        // A genuine inbound link click — cross-site but a top-level navigation.
        let h = req(&[
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "navigate"),
        ]);
        assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
    }

    #[test]
    fn first_party_counts_requests_without_fetch_metadata() {
        // Non-browser / legacy client: treated as first-party, counts.
        assert!(ActivityPolicy::FirstParty.counts_as_activity(&http::HeaderMap::new()));
    }

    #[test]
    fn navigations_only_excludes_same_origin_fetch() {
        let h = req(&[
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
        ]);
        assert!(!ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
    }

    #[test]
    fn navigations_only_counts_navigation() {
        let h = req(&[("sec-fetch-mode", "navigate")]);
        assert!(ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
    }

    #[test]
    fn all_requests_counts_cross_site_fetch() {
        let h = req(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]);
        assert!(ActivityPolicy::AllRequests.counts_as_activity(&h));
    }

    #[test]
    fn first_party_counts_legacy_xhr_without_fetch_metadata() {
        // An old browser / jQuery XHR sends no Sec-Fetch-* — it cannot be
        // classified cross-site, so an active user on such a client must still
        // count as activity and never idle out under the default policy.
        let h = req(&[
            ("x-requested-with", "XMLHttpRequest"),
            ("accept", "application/json"),
        ]);
        assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
    }

    #[test]
    fn navigations_only_counts_legacy_navigation_via_accept() {
        // Even the strict policy must keep counting genuine page loads from
        // old browsers: with no Sec-Fetch-*, `Accept: text/html` is the
        // navigation signal.
        let h = req(&[("accept", "text/html,application/xhtml+xml")]);
        assert!(ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
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
    fn login_config_lifetime_fields_override() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .max_lifetime(Duration::from_hours(1))
            .token_refresh_margin(Duration::from_mins(1))
            .default_token_lifetime(Duration::from_hours(2))
            .login_state_ttl(Duration::from_mins(30))
            .build()
            .unwrap();
        assert_eq!(config.max_lifetime, Some(Duration::from_hours(1)));
        assert_eq!(config.token_refresh_margin, Duration::from_mins(1));
        assert_eq!(config.default_token_lifetime, Duration::from_hours(2));
        assert_eq!(config.login_state_ttl, Duration::from_mins(30));
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
    fn login_config_paths_reject_control_characters() {
        for path in [
            "/callback\r\nSet-Cookie: x=y",
            "/callback\0",
            "/callback\n",
            "/callback\t",
        ] {
            let err = LoginConfig::builder()
                .callback_path(path.into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidCallbackPath { .. }),
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
    fn login_config_logout_defaults_none() {
        assert!(default_policy_config().logout.is_none());
    }

    #[test]
    fn login_config_logout_accepted() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout(LogoutConfig::builder().path("/logout").build())
            .build()
            .unwrap();
        assert_eq!(config.logout.unwrap().path, "/logout");
    }

    #[test]
    fn login_config_logout_path_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout(LogoutConfig::builder().path("logout").build())
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
                .logout(LogoutConfig::builder().path(path).build())
                .build()
                .unwrap_err();
            assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
        }
    }

    #[test]
    fn login_config_post_logout_redirect_uri_must_be_absolute() {
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout(
                LogoutConfig::builder()
                    .path("/logout")
                    .post_logout_redirect_uri("/signed-out".parse().unwrap())
                    .build(),
            )
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidPostLogoutRedirectUri { .. }
        ));
    }

    #[test]
    fn login_config_post_logout_redirect_uri_absolute_accepted() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .logout(
                LogoutConfig::builder()
                    .path("/logout")
                    .post_logout_redirect_uri("https://app.example.com/signed-out".parse().unwrap())
                    .build(),
            )
            .build()
            .unwrap();
        let logout = config.logout.unwrap();
        assert_eq!(
            logout.post_logout_redirect_uri.unwrap().to_string(),
            "https://app.example.com/signed-out"
        );
    }

    #[test]
    fn login_config_cookie_prefix_rejects_unsafe_characters() {
        for prefix in ["bad prefix", "bad;prefix", "bad=prefix", "préfixe", ""] {
            let err = LoginConfig::builder()
                .callback_path("/callback".into())
                .scopes(vec![])
                .base_url("https://app.example.com".parse().unwrap())
                .login_cookie_prefix(prefix.to_owned())
                .build()
                .unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidLoginCookiePrefix { .. }),
                "expected reject for {prefix:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn login_config_cookie_prefix_accepts_safe_characters() {
        let config = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .login_cookie_prefix("my-app_2".to_owned())
            .build()
            .unwrap();
        assert_eq!(config.login_cookie_prefix, "my-app_2");
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
        assert!(err.to_string().contains("logout path"));
    }

    #[test]
    fn config_error_display_post_logout_redirect_uri() {
        let err = ConfigError::InvalidPostLogoutRedirectUri {
            url: "u".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("post_logout_redirect_uri"));
    }

    #[test]
    fn config_error_display_login_cookie_prefix() {
        let err = ConfigError::InvalidLoginCookiePrefix {
            prefix: "p".into(),
            reason: "reason",
        };
        assert!(err.to_string().contains("login_cookie_prefix"));
    }

    #[test]
    fn strip_prefix_not_matching_callback_path_is_rejected() {
        // The engine sees prefixed paths, so a callback_path outside the
        // prefix is contradictory — previously this fell back silently and
        // produced a mis-scoped login cookie.
        let err = LoginConfig::builder()
            .callback_path("/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/other")
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
    }

    #[test]
    fn strip_prefix_not_matching_logout_path_is_rejected() {
        let err = LoginConfig::builder()
            .callback_path("/internal/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .logout(LogoutConfig::builder().path("/logout").build())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
    }

    #[test]
    fn strip_prefix_matching_both_paths_is_accepted() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback".into())
            .scopes(vec![])
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .logout(LogoutConfig::builder().path("/internal/logout").build())
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }
}
