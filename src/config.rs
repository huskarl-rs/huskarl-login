//! Login flow configuration.
//!
//! [`LoginConfig`] holds the settings governing the OAuth 2.0 Authorization
//! Code Grant login middleware.

use std::time::Duration;

use http::HeaderMap;
use huskarl::core::EndpointUrl;
use snafu::Snafu;

use crate::{
    cookie::CookieName,
    engine::{is_cross_site_request, is_navigation_request},
};

/// Which requests count as user activity for liveness tracking; only activity
/// advances `last_active` (idle expiry runs regardless). Classified from
/// fetch-metadata headers. Defaults to [`FirstParty`](Self::FirstParty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ActivityPolicy {
    /// Only top-level browser navigations count.
    NavigationsOnly,
    /// Everything except cross-site requests that are not top-level
    /// navigations. Requests without fetch-metadata count as first-party.
    #[default]
    FirstParty,
    /// Every authenticated request counts as activity.
    AllRequests,
}

impl ActivityPolicy {
    /// Returns whether a request with these headers advances `last_active`.
    #[must_use]
    pub fn counts_as_activity(self, headers: &HeaderMap) -> bool {
        match self {
            Self::NavigationsOnly => is_navigation_request(headers),
            Self::FirstParty => !is_cross_site_request(headers) || is_navigation_request(headers),
            Self::AllRequests => true,
        }
    }
}

/// Which party bounds the session's absolute lifetime. Required by
/// [`LoginConfig::builder`] — there is no default, so every deployment states
/// its choice in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifetime {
    /// The **authorization server** bounds the session: it lives exactly as
    /// long as the AS keeps honoring the refresh token (re-verified on every
    /// token refresh), and this crate imposes no cap of its own. Provides no
    /// re-authentication freshness, no cookie-theft containment, and no
    /// storage TTL hint — see [the session
    /// model](crate::_docs::explanation::session_model) for when to choose
    /// delegation and what to verify about the AS first.
    DelegatedToAuthorizationServer,
    /// This crate bounds the session: it is torn down this long after login
    /// ([`MaxLifetime`](crate::TeardownReason::MaxLifetime)), regardless of
    /// activity or AS policy. Must be non-zero. The only crate-side lifetime
    /// bound for cookie sessions.
    ///
    /// The deadline is frozen into each session at login
    /// ([`SessionState::expire_at`](crate::SessionState)), making cap changes
    /// one-directional for existing sessions: lowering applies immediately,
    /// raising reaches new logins only — see [the session
    /// model](crate::_docs::explanation::session_model).
    Bounded(Duration),
}

impl SessionLifetime {
    /// The crate-enforced cap: `Some` for [`Bounded`](Self::Bounded), `None`
    /// for
    /// [`DelegatedToAuthorizationServer`](Self::DelegatedToAuthorizationServer).
    #[must_use]
    pub fn bound(self) -> Option<Duration> {
        match self {
            Self::DelegatedToAuthorizationServer => None,
            Self::Bounded(d) => Some(d),
        }
    }
}

/// Errors that can occur when building a [`LoginConfig`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConfigError {
    /// The `callback_path` is invalid.
    #[snafu(display("invalid callback_path {path:?}: {reason}"))]
    InvalidCallbackPath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// The `base_url` is invalid.
    #[snafu(display("invalid base_url {url:?}: {reason}"))]
    InvalidBaseUrl {
        /// The offending URL.
        url: String,
        /// Why the URL was rejected.
        reason: &'static str,
    },
    /// The `strip_prefix` is invalid.
    #[snafu(display("invalid strip_prefix {prefix:?}: {reason}"))]
    InvalidStripPrefix {
        /// The offending prefix.
        prefix: String,
        /// Why the prefix was rejected.
        reason: &'static str,
    },
    /// The logout `path` is invalid.
    #[snafu(display("invalid logout path {path:?}: {reason}"))]
    InvalidLogoutPath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
        reason: &'static str,
    },
    /// The `post_logout_redirect_uri` is invalid.
    #[snafu(display("invalid post_logout_redirect_uri {url:?}: {reason}"))]
    InvalidPostLogoutRedirectUri {
        /// The offending URL.
        url: String,
        /// Why the URL was rejected.
        reason: &'static str,
    },
    /// The `login_cookie_prefix` is invalid.
    #[snafu(display("invalid login_cookie_prefix {prefix:?}: {reason}"))]
    InvalidLoginCookiePrefix {
        /// The offending prefix.
        prefix: String,
        /// Why the prefix was rejected.
        reason: &'static str,
    },
    /// A duration setting holds an invalid value (e.g. zero).
    #[snafu(display("invalid {field}: {reason}"))]
    InvalidDuration {
        /// The name of the offending field.
        field: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
}

/// A validated request path or path prefix, cookie- and header-safe by
/// construction: starts with `/` and contains no `?`, `#`, `;`, or ASCII
/// control characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath(String);

impl RoutePath {
    /// Validates `path` (must start with `/`; no `?`, `#`, `;`, or control
    /// chars) and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRoutePath`] with the offending value and reason.
    pub fn new(path: impl Into<String>) -> Result<Self, InvalidRoutePath> {
        let path = path.into();
        if !path.starts_with('/') {
            return Err(InvalidRoutePath {
                path,
                reason: "must start with '/'",
            });
        }
        if path.contains('?') || path.contains('#') || path.contains(';') {
            return Err(InvalidRoutePath {
                path,
                reason: "must not contain '?', '#', or ';'",
            });
        }
        if path.bytes().any(|b| b.is_ascii_control()) {
            return Err(InvalidRoutePath {
                path,
                reason: "must not contain ASCII control characters",
            });
        }
        Ok(Self(path))
    }

    /// Validates `path`, mapping a rejection through `make_error`.
    fn validated(
        path: String,
        make_error: impl FnOnce(String, &'static str) -> ConfigError,
    ) -> Result<Self, ConfigError> {
        Self::new(path).map_err(|InvalidRoutePath { path, reason }| make_error(path, reason))
    }

    /// The validated path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error returned by [`RoutePath::new`] when a path fails validation.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(display("invalid route path {path:?}: {reason}"))]
pub struct InvalidRoutePath {
    /// The offending path.
    pub path: String,
    /// Why the path was rejected.
    pub reason: &'static str,
}

// `TryFrom`, not `From`: validation is fallible, so an infallible `From` would
// have to panic. These mirror [`RoutePath::new`] for `?`/`try_into()` callers.
impl TryFrom<String> for RoutePath {
    type Error = InvalidRoutePath;
    fn try_from(path: String) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<&str> for RoutePath {
    type Error = InvalidRoutePath;
    fn try_from(path: &str) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

// Enables `"/scope".parse::<RoutePath>()` and inference at call sites that
// expect a `RoutePath` (e.g. the `cookie_path` builder setters).
impl std::str::FromStr for RoutePath {
    type Err = InvalidRoutePath;
    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}

impl std::fmt::Display for RoutePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RoutePath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RoutePath {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for RoutePath {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Joins the path component of `base_url` with `segment`, inserting exactly
/// one `/` between them.
pub(crate) fn join_base_path(base_url: &http::Uri, segment: &str) -> String {
    let base_path = base_url.path().trim_end_matches('/');
    if segment.starts_with('/') {
        format!("{base_path}{segment}")
    } else {
        format!("{base_path}/{segment}")
    }
}

/// Validates the lifetime/interval settings against each other.
fn validate_durations(
    session_lifetime: SessionLifetime,
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
    if session_lifetime == SessionLifetime::Bounded(Duration::ZERO) {
        return Err(ConfigError::InvalidDuration {
            field: "session_lifetime",
            reason: "Bounded lifetime must be greater than zero (use \
                     DelegatedToAuthorizationServer to delegate the cap)",
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

/// Computes the browser-facing callback path: `base_url` path joined to
/// `callback_path` with `strip_prefix` removed.
fn compute_browser_callback_path(
    callback_path: &RoutePath,
    strip_prefix: Option<&RoutePath>,
    base_url: &http::Uri,
) -> String {
    let callback_path = callback_path.as_str();
    let stripped_callback = match strip_prefix {
        Some(prefix) => callback_path
            .strip_prefix(prefix.as_str())
            .unwrap_or(callback_path),
        None => callback_path,
    };
    join_base_path(base_url, stripped_callback)
}

/// Logout endpoint configuration. Grouped under [`LoginConfig::logout`].
#[derive(Debug)]
#[non_exhaustive]
pub struct LogoutConfig {
    /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
    pub path: RoutePath,
    /// Authorization server's end-session endpoint for RP-initiated logout
    /// (OIDC RP-Initiated Logout 1.0).
    pub end_session_endpoint: Option<EndpointUrl>,
    /// Absolute URI to redirect to after the local session is cleared; defaults
    /// to `base_url`. Held as the exact string supplied, as the OP matches it
    /// byte-for-byte (OIDC RP-Initiated Logout 1.0 §3): it (and the `base_url`
    /// default, if relied on) must be registered at the authorization server,
    /// or the OP silently drops the redirect and strands the user on its logout
    /// page.
    pub post_logout_redirect_uri: Option<String>,
}

#[bon::bon]
impl LogoutConfig {
    /// Creates a logout configuration, validating the `path` shape.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidLogoutPath`] if `path` is malformed.
    #[builder]
    pub fn new(
        /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
        #[builder(into)]
        path: String,
        /// Authorization server's end-session endpoint for RP-initiated logout.
        end_session_endpoint: Option<EndpointUrl>,
        /// Absolute URL to redirect to after logout, preserved exactly as
        /// supplied. Defaults to `base_url`.
        #[builder(into)]
        post_logout_redirect_uri: Option<String>,
    ) -> Result<Self, ConfigError> {
        let path = RoutePath::validated(path, |path, reason| ConfigError::InvalidLogoutPath {
            path,
            reason,
        })?;
        Ok(Self {
            path,
            end_session_endpoint,
            post_logout_redirect_uri,
        })
    }
}

/// Configuration for the login middleware; constructed via
/// [`builder`](Self::builder). Authorization server endpoints, client
/// credentials, and redirect URI are configured on the
/// [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant)
/// directly.
#[derive(Debug)]
#[non_exhaustive]
pub struct LoginConfig {
    /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
    pub callback_path: RoutePath,
    /// OAuth 2.0 scopes to request (e.g. `bon::vec!["openid"]`).
    pub scopes: Vec<String>,
    /// Whether to set the `Secure` flag and `__Host-`/`__Secure-` cookie name
    /// prefixes. Derived from [`base_url`](Self::base_url): `true` when its
    /// scheme is `https`.
    pub secure: bool,
    /// Which party bounds the session's absolute lifetime — see
    /// [`SessionLifetime`]. Idle timeout is configured separately, on the
    /// liveness store.
    pub session_lifetime: SessionLifetime,
    /// Which requests count as user activity. Only affects sessions with a
    /// liveness store. Defaults to [`ActivityPolicy::FirstParty`].
    pub activity_policy: ActivityPolicy,
    /// How early to refresh before token expiry. Defaults to 30 seconds.
    pub token_refresh_margin: Duration,
    /// Lifetime assumed when the token response omits `expires_in`. Defaults
    /// to 1 hour.
    pub default_token_lifetime: Duration,
    /// Lifetime (and `Max-Age`) of the per-flow login-state cookie; the user
    /// has this long to complete authentication. Defaults to 10 minutes.
    pub login_state_ttl: Duration,
    /// Canonical client-facing base URL (e.g. `"https://app.example.com"`),
    /// used to reconstruct the post-login redirect URL behind a front proxy.
    pub base_url: EndpointUrl,
    /// Path prefix added by a front proxy, stripped from the request path
    /// before constructing the original URL (e.g. `"/internal"`).
    pub strip_prefix: Option<RoutePath>,
    /// Logout endpoint configuration. When `None`, no logout endpoint is
    /// mounted.
    pub logout: Option<LogoutConfig>,
    /// Prefix for login-state cookie names. The full name is
    /// `{security_prefix}{login_cookie_prefix}_{state}`. Defaults to
    /// `"huskarl_login"`.
    pub login_cookie_prefix: CookieName,
    /// Browser-facing callback path, derived from `base_url`, `strip_prefix`,
    /// and `callback_path`; used as the `Path` scope on login-state cookies.
    pub browser_callback_path: RoutePath,
}

#[bon::bon]
impl LoginConfig {
    /// Builds a [`LoginConfig`], validating paths and the `base_url`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any path is malformed, the durations are
    /// invalid, or the cookie `Path` derived from `base_url` and
    /// `callback_path` is not cookie-safe.
    #[builder]
    pub fn new(
        /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
        #[builder(into)]
        callback_path: String,
        /// OAuth 2.0 scopes to request (e.g. `bon::vec!["openid"]`, which
        /// converts each element via `Into<String>`).
        scopes: Vec<String>,
        /// Which party bounds the session's absolute lifetime; see
        /// [`SessionLifetime`] for what each choice implies. Required — there
        /// is no default.
        session_lifetime: SessionLifetime,
        /// Which requests count as user activity. Defaults to
        /// [`ActivityPolicy::FirstParty`].
        #[builder(default)]
        activity_policy: ActivityPolicy,
        /// How early to refresh before token expiry. Defaults to 30 seconds.
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
        base_url: EndpointUrl,
        /// Front-proxy path prefix to strip before reconstructing the URL.
        #[builder(into)]
        strip_prefix: Option<String>,
        /// Logout endpoint configuration. When `None`, no logout endpoint is
        /// mounted.
        logout: Option<LogoutConfig>,
        /// Prefix for login-state cookie names. Defaults to `"huskarl_login"`.
        #[builder(
            into,
            default = crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX.to_owned()
        )]
        login_cookie_prefix: String,
    ) -> Result<Self, ConfigError> {
        let callback_path = RoutePath::validated(callback_path, |path, reason| {
            ConfigError::InvalidCallbackPath { path, reason }
        })?;
        let strip_prefix = strip_prefix
            .map(|prefix| {
                RoutePath::validated(prefix, |prefix, reason| ConfigError::InvalidStripPrefix {
                    prefix,
                    reason,
                })
            })
            .transpose()?;
        // `logout.path`'s shape was validated by `LogoutConfig::builder`; the
        // redirect URI still needs an absolute-URL check. It is parsed only to
        // validate — the stored value stays the exact string, since the OP
        // matches it byte-for-byte (OIDC RP-Initiated Logout 1.0 §3).
        if let Some(ref logout) = logout
            && let Some(ref uri) = logout.post_logout_redirect_uri
        {
            let absolute = uri
                .parse::<http::Uri>()
                .is_ok_and(|parsed| parsed.scheme().is_some() && parsed.authority().is_some());
            if !absolute {
                return Err(ConfigError::InvalidPostLogoutRedirectUri {
                    url: uri.clone(),
                    reason: "must be an absolute URL with scheme and authority",
                });
            }
        }
        // Engine-side paths carry the front proxy's prefix; a path outside it
        // would silently never match a real request (and, for the callback,
        // corrupt the derived cookie scope) — reject the contradiction.
        if let Some(ref prefix) = strip_prefix {
            if !callback_path.as_str().starts_with(prefix.as_str()) {
                return Err(ConfigError::InvalidCallbackPath {
                    path: callback_path.as_str().to_owned(),
                    reason: "must start with strip_prefix when strip_prefix is set",
                });
            }
            if let Some(ref logout) = logout
                && !logout.path.as_str().starts_with(prefix.as_str())
            {
                return Err(ConfigError::InvalidLogoutPath {
                    path: logout.path.as_str().to_owned(),
                    reason: "must start with strip_prefix when strip_prefix is set",
                });
            }
        }
        // The prefix is interpolated into cookie names, so it carries the same
        // cookie-name invariant as the stores' `cookie_name`: validate it as a
        // `CookieName` rather than re-checking the charset by hand.
        let login_cookie_prefix = CookieName::new(login_cookie_prefix).map_err(|e| {
            ConfigError::InvalidLoginCookiePrefix {
                prefix: e.name,
                reason: e.reason,
            }
        })?;
        validate_durations(
            session_lifetime,
            token_refresh_margin,
            default_token_lifetime,
            login_state_ttl,
        )?;

        // Derived from `base_url`'s path joined to `callback_path`. The
        // callback is already a `RoutePath`, but `base_url`'s path is not — so
        // validate the joined result before it is emitted as a cookie `Path`,
        // closing the one route by which a `;`/control char could reach a
        // `Set-Cookie` header.
        let browser_callback_path =
            compute_browser_callback_path(&callback_path, strip_prefix.as_ref(), base_url.as_uri());
        let browser_callback_path =
            RoutePath::new(browser_callback_path).map_err(|e| ConfigError::InvalidBaseUrl {
                url: base_url.as_uri().to_string(),
                reason: e.reason,
            })?;
        // Single source of truth for cookie security: the browser-facing scheme.
        // `base_url` is validated above to have a scheme, so this is decisive.
        let secure = base_url.as_uri().scheme_str() == Some("https");

        Ok(Self {
            callback_path,
            scopes,
            secure,
            session_lifetime,
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
    use crate::test_support::header_map as req;

    fn default_policy_config() -> LoginConfig {
        LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("http://localhost:6188".parse().unwrap())
            .build()
            .unwrap();
        assert!(!config.secure);
    }

    #[test]
    fn delegated_session_lifetime_has_no_crate_side_bound() {
        assert_eq!(
            default_policy_config().session_lifetime.bound(),
            None,
            "delegated lifetime imposes no crate-side cap"
        );
        assert_eq!(
            SessionLifetime::Bounded(Duration::from_hours(8)).bound(),
            Some(Duration::from_hours(8))
        );
    }

    #[test]
    fn rejects_zero_default_token_lifetime() {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
    fn rejects_zero_bounded_lifetime_but_allows_delegated() {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::Bounded(Duration::ZERO))
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidDuration {
                field: "session_lifetime",
                ..
            }
        ));
        // Delegation stays valid — the AS bounds the session instead.
        assert_eq!(default_policy_config().session_lifetime.bound(), None);
    }

    #[test]
    fn rejects_refresh_margin_at_or_above_token_lifetime() {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
            .base_url("https://app.example.com".parse().unwrap())
            .token_refresh_margin(Duration::from_mins(1))
            .default_token_lifetime(Duration::from_hours(2))
            .login_state_ttl(Duration::from_mins(30))
            .build()
            .unwrap();
        assert_eq!(
            config.session_lifetime,
            SessionLifetime::Bounded(Duration::from_hours(1))
        );
        assert_eq!(config.token_refresh_margin, Duration::from_mins(1));
        assert_eq!(config.default_token_lifetime, Duration::from_hours(2));
        assert_eq!(config.login_state_ttl, Duration::from_mins(30));
    }

    #[test]
    fn login_config_callback_path_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
    }

    #[test]
    fn login_config_callback_path_must_not_contain_query_or_fragment() {
        for path in ["/callback?foo=bar", "/callback#section", "/callback;Secure"] {
            let err = LoginConfig::builder()
                .callback_path(path)
                .scopes(vec![])
                .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
                .callback_path(path)
                .scopes(vec![])
                .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
    fn login_config_strip_prefix_must_start_with_slash() {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
                .callback_path("/callback")
                .scopes(vec![])
                .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .logout(LogoutConfig::builder().path("/logout").build().unwrap())
            .build()
            .unwrap();
        assert_eq!(config.logout.unwrap().path, "/logout");
    }

    #[test]
    fn logout_config_path_must_start_with_slash() {
        // Path shape is now validated eagerly by LogoutConfig::builder.
        let err = LogoutConfig::builder().path("logout").build().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
    }

    #[test]
    fn logout_config_path_must_not_contain_query_fragment_or_semicolon() {
        for path in ["/logout?foo=bar", "/logout#section", "/logout;Secure"] {
            let err = LogoutConfig::builder().path(path).build().unwrap_err();
            assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
        }
    }

    #[test]
    fn logout_config_end_session_endpoint_absolute_accepted() {
        let config = LogoutConfig::builder()
            .path("/logout")
            .end_session_endpoint("https://auth.example.com/logout".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(
            config.end_session_endpoint.unwrap().as_uri().to_string(),
            "https://auth.example.com/logout"
        );
    }

    #[test]
    fn login_config_post_logout_redirect_uri_must_be_absolute() {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .logout(
                LogoutConfig::builder()
                    .path("/logout")
                    .post_logout_redirect_uri("/signed-out")
                    .build()
                    .unwrap(),
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .logout(
                LogoutConfig::builder()
                    .path("/logout")
                    .post_logout_redirect_uri("https://app.example.com/signed-out")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let logout = config.logout.unwrap();
        assert_eq!(
            logout.post_logout_redirect_uri.unwrap(),
            "https://app.example.com/signed-out"
        );
    }

    #[test]
    fn login_config_cookie_prefix_rejects_unsafe_characters() {
        for prefix in ["bad prefix", "bad;prefix", "bad=prefix", "préfixe", ""] {
            let err = LoginConfig::builder()
                .callback_path("/callback")
                .scopes(vec![])
                .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
                .base_url("https://app.example.com".parse().unwrap())
                .login_cookie_prefix(prefix)
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .login_cookie_prefix("my-app_2")
            .build()
            .unwrap();
        assert_eq!(config.login_cookie_prefix.as_str(), "my-app_2");
    }

    // -- browser_callback_path tests --

    #[test]
    fn browser_callback_path_simple() {
        let config = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }

    #[test]
    fn browser_callback_path_with_base_path() {
        let config = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com/base".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/base/callback");
    }

    #[test]
    fn browser_callback_path_with_strip_prefix() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }

    #[test]
    fn browser_callback_path_with_base_path_and_strip_prefix() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com/base".parse().unwrap())
            .strip_prefix("/internal")
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/base/callback");
    }

    // -- RoutePath tests --

    #[test]
    fn route_path_new_accepts_and_rejects() {
        assert_eq!(RoutePath::new("/callback").unwrap(), "/callback");
        assert_eq!(
            RoutePath::new("no-leading-slash").unwrap_err().reason,
            "must start with '/'"
        );
        assert!(RoutePath::new("/a;b").is_err());
        assert!(RoutePath::new("/a?b").is_err());
        assert!(RoutePath::new("/a\r\nb").is_err());
    }

    #[test]
    fn route_path_try_from() {
        assert!(RoutePath::try_from("/ok").is_ok());
        assert!(RoutePath::try_from("/bad;x".to_owned()).is_err());
        // `?`/`try_into()` ergonomics for callers.
        let p: RoutePath = "/scope".try_into().unwrap();
        assert_eq!(p, "/scope");
    }

    #[test]
    fn base_url_path_with_semicolon_rejected_as_unsafe_cookie_scope() {
        // The derived browser_callback_path becomes a cookie `Path`; a `;` in
        // base_url's path would inject a stray cookie attribute, so the build
        // must reject it rather than emit an unsafe Set-Cookie.
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com/a;b".parse().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBaseUrl { .. }));
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
            .callback_path("/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/other")
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
    }

    #[test]
    fn strip_prefix_not_matching_logout_path_is_rejected() {
        let err = LoginConfig::builder()
            .callback_path("/internal/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .logout(LogoutConfig::builder().path("/logout").build().unwrap())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
    }

    #[test]
    fn strip_prefix_matching_both_paths_is_accepted() {
        let config = LoginConfig::builder()
            .callback_path("/internal/callback")
            .scopes(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .base_url("https://app.example.com".parse().unwrap())
            .strip_prefix("/internal")
            .logout(
                LogoutConfig::builder()
                    .path("/internal/logout")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path, "/callback");
    }
}
