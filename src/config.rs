//! Login behavior and route configuration.
//!
//! [`LoginConfig`] holds the settings governing the OAuth 2.0 Authorization
//! Code flow after the client itself has been configured. Authorization-server
//! endpoints, client credentials, and the redirect URI belong to
//! [`AuthorizationCodeGrant`](crate::client::grant::authorization_code::AuthorizationCodeGrant);
//! persistence belongs to the selected session store; server-side idle
//! tracking belongs to [`LivenessConfig`](crate::LivenessConfig).

use std::time::Duration;

use http::HeaderMap;
use snafu::Snafu;

use crate::{
    cookie::CookieName,
    core::EndpointUrl,
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
    /// The **authorization server (AS)** bounds the session: it lives exactly
    /// as long as the AS keeps honoring the refresh token (re-verified on every
    /// token refresh), and this crate imposes no cap of its own; storage
    /// stays bounded by the external-store activity horizon.
    /// Provides no re-authentication freshness and no cookie-theft
    /// containment — see [the session
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
    /// The `base_path` is invalid.
    #[snafu(display("invalid base_path {path:?}: {reason}"))]
    InvalidBasePath {
        /// The offending path.
        path: String,
        /// Why the path was rejected.
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
    /// The session cookie's `Path` does not cover an engine route that needs
    /// to observe or clear it.
    #[snafu(display(
        "invalid session cookie path {path:?}: it must cover the browser-facing {route} path {route_path:?}"
    ))]
    InvalidSessionCookiePath {
        /// The configured session-cookie path.
        path: String,
        /// The engine route the cookie must cover (`"callback"` or `"logout"`).
        route: &'static str,
        /// The browser-facing route path.
        route_path: String,
    },
    /// A duration setting holds an invalid value (e.g. zero).
    #[snafu(display("invalid {field}: {reason}"))]
    InvalidDuration {
        /// The name of the offending field.
        field: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// The grant's `redirect_uri` is not a usable absolute URL, so the engine
    /// cannot reconstruct the client-facing base URL from it. Checked when
    /// building a [`LoginEngine`](crate::engine::LoginEngine).
    #[snafu(display("invalid redirect_uri {url:?}: {reason}"))]
    InvalidRedirectUri {
        /// The offending URL.
        url: String,
        /// Why the URL was rejected.
        reason: &'static str,
    },
}

/// A validated ASCII request path or path prefix, cookie- and header-safe by
/// construction: starts with `/` and contains no `?`, `#`, `;`, control
/// characters, or non-ASCII bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath(String);

impl RoutePath {
    /// Validates `path` (must be ASCII and start with `/`; no `?`, `#`, `;`, or
    /// control chars) and wraps it.
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
        if !path.is_ascii() {
            return Err(InvalidRoutePath {
                path,
                reason: "must contain only ASCII characters; percent-encode non-ASCII path bytes",
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

    /// Removes this path prefix from `path` when it ends on a path-segment
    /// boundary. The returned path always starts with `/`.
    ///
    /// `/app` therefore matches `/app` and `/app/page`, but not
    /// `/application`. A root prefix is a no-op, while a trailing slash in the
    /// prefix is retained as the returned path's leading slash.
    pub(crate) fn strip_from<'a>(&self, path: &'a str) -> Option<&'a str> {
        let prefix = self.as_str();

        if prefix == "/" {
            return path.starts_with('/').then_some(path);
        }

        let remainder = path.strip_prefix(prefix)?;
        if prefix.ends_with('/') {
            return Some(&path[prefix.len() - 1..]);
        }
        if remainder.is_empty() {
            return Some(&path[..1]);
        }
        remainder.starts_with('/').then_some(remainder)
    }

    /// The root path `/`. Infallible — `/` is always cookie- and header-safe.
    #[must_use]
    pub fn root() -> Self {
        Self("/".to_owned())
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

/// Validates the configured post-logout redirect while preserving the exact
/// string supplied for the authorization server's byte-for-byte comparison.
fn validate_post_logout_redirect_uri(logout: Option<&LogoutConfig>) -> Result<(), ConfigError> {
    let Some(uri) = logout.and_then(|logout| logout.post_logout_redirect_uri.as_ref()) else {
        return Ok(());
    };
    let absolute = uri
        .parse::<http::Uri>()
        .is_ok_and(|parsed| parsed.scheme().is_some() && parsed.authority().is_some());
    if !absolute {
        return Err(ConfigError::InvalidPostLogoutRedirectUri {
            url: uri.clone(),
            reason: "must be an absolute URL with scheme and authority",
        });
    }
    Ok(())
}

/// Computes and validates a browser-facing route path: the `base_path` prefix
/// joined to `route_path` with `strip_prefix` removed. Independent of the
/// origin.
fn browser_path(
    route_path: &RoutePath,
    strip_prefix: Option<&RoutePath>,
    base_path: Option<&RoutePath>,
) -> Result<RoutePath, ConfigError> {
    let route_path = route_path.as_str();
    let stripped_route = match strip_prefix {
        // An exact non-root prefix maps to the public base without adding a
        // slash, just as PublicUrlMapping does.
        Some(prefix) if !prefix.as_str().ends_with('/') && prefix.as_str() == route_path => "",
        Some(prefix) => prefix.strip_from(route_path).unwrap_or(route_path),
        None => route_path,
    };
    let browser_path = match base_path {
        Some(base) => {
            let base = base.as_str().trim_end_matches('/');
            format!("{base}{stripped_route}")
        }
        None => stripped_route.to_owned(),
    };
    let browser_path = if browser_path.is_empty() {
        "/".to_owned()
    } else {
        browser_path
    };
    RoutePath::new(browser_path).map_err(|e| ConfigError::InvalidBasePath {
        path: base_path.map_or_else(String::new, |path| path.as_str().to_owned()),
        reason: e.reason,
    })
}

/// Logout endpoint configuration. Grouped under [`LoginConfig::logout`].
#[derive(Debug)]
#[non_exhaustive]
pub struct LogoutConfig {
    /// Path at which the logout endpoint is mounted (e.g. `"/logout"`).
    pub path: RoutePath,
    /// Authorization server's end-session endpoint for relying-party
    /// initiated logout (OIDC RP-Initiated Logout 1.0).
    pub end_session_endpoint: Option<EndpointUrl>,
    /// Absolute URI to redirect to after the local session is cleared; defaults
    /// to the reconstructed base URL (the grant's `redirect_uri` origin joined
    /// with `base_path`). Held as the exact string supplied, as the `OpenID`
    /// Provider (OP) matches
    /// it byte-for-byte (OIDC RP-Initiated Logout 1.0 §3): it (and the base-URL
    /// default, if relied on) must be registered at the authorization server, or
    /// the OP silently drops the redirect and strands the user on its logout
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
        /// Authorization server's end-session endpoint for relying-party
        /// initiated logout.
        end_session_endpoint: Option<EndpointUrl>,
        /// Absolute URL to redirect to after logout, preserved exactly as
        /// supplied. Defaults to the reconstructed base URL.
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
/// [`AuthorizationCodeGrant`](crate::client::grant::authorization_code::AuthorizationCodeGrant)
/// directly.
#[derive(Debug)]
#[non_exhaustive]
pub struct LoginConfig {
    /// Validated deployment mapping, when configured through the new API.
    /// Its origin must agree with the grant and its prefixes with these fields.
    pub url_mapping: Option<crate::core::url_mapping::PublicUrlMapping>,
    /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
    pub callback_path: RoutePath,
    /// OAuth 2.0 scopes to request (e.g. `bon::vec!["openid"]`).
    pub scope: Vec<String>,
    /// Which party bounds the session's absolute lifetime — see
    /// [`SessionLifetime`]. Idle timeout is configured separately, on the
    /// liveness store.
    pub session_lifetime: SessionLifetime,
    /// Which requests count as user activity. Only affects sessions with a
    /// liveness store. Defaults to [`ActivityPolicy::FirstParty`].
    pub activity_policy: ActivityPolicy,
    /// How early to refresh before token expiry. Defaults to 30 seconds.
    /// Without a refresh token, the access token remains usable until expiry,
    /// subject to the session's lifetime and idle-timeout checks.
    pub token_refresh_margin: Duration,
    /// Lifetime assumed when the token response omits `expires_in`. Defaults
    /// to 1 hour.
    pub default_token_lifetime: Duration,
    /// Lifetime (and `Max-Age`) of the per-flow login-state cookie; the user
    /// has this long to complete authentication. Defaults to 10 minutes.
    pub login_state_ttl: Duration,
    /// Public path prefix the app is mounted under behind a front proxy (e.g.
    /// `"/app"`), prepended when reconstructing the client-facing URL. The
    /// scheme and host come from the grant's `redirect_uri` at engine build, so
    /// only the path prefix is configured here. `None` means mounted at the
    /// origin root.
    pub base_path: Option<RoutePath>,
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
    /// Browser-facing callback path, derived from `base_path`, `strip_prefix`,
    /// and `callback_path`; used as the `Path` scope on login-state cookies.
    pub browser_callback_path: RoutePath,
    /// Browser-facing logout path, derived from `base_path`, `strip_prefix`,
    /// and [`LogoutConfig::path`]. `None` when logout is disabled.
    pub browser_logout_path: Option<RoutePath>,
}

#[bon::bon]
impl LoginConfig {
    /// Revalidates mutable settings and recomputes browser-facing paths from
    /// the canonical route configuration.
    ///
    /// `LoginConfig` exposes its fields for adapter inspection, so callers can
    /// mutate them after using the builder. The engine calls this before it
    /// derives cookie policy to ensure stale derived fields cannot bypass route
    /// visibility checks.
    pub(crate) fn validate_and_recompute(&mut self) -> Result<(), ConfigError> {
        if let Some(mapping) = &self.url_mapping {
            let (base, ingress) = mapping_paths(mapping);
            if self.base_path.as_ref().map(RoutePath::as_str) != base.as_deref()
                || self.strip_prefix.as_ref().map(RoutePath::as_str) != ingress.as_deref()
            {
                return Err(ConfigError::InvalidBasePath {
                    path: mapping.public_base().path().to_owned(),
                    reason: "mutable prefix fields disagree with url_mapping",
                });
            }
        }
        validate_durations(
            self.session_lifetime,
            self.token_refresh_margin,
            self.default_token_lifetime,
            self.login_state_ttl,
        )?;
        validate_post_logout_redirect_uri(self.logout.as_ref())?;

        if let Some(prefix) = &self.strip_prefix {
            if prefix.strip_from(self.callback_path.as_str()).is_none() {
                return Err(ConfigError::InvalidCallbackPath {
                    path: self.callback_path.as_str().to_owned(),
                    reason: "must be within strip_prefix when strip_prefix is set",
                });
            }
            if let Some(logout) = &self.logout
                && prefix.strip_from(logout.path.as_str()).is_none()
            {
                return Err(ConfigError::InvalidLogoutPath {
                    path: logout.path.as_str().to_owned(),
                    reason: "must be within strip_prefix when strip_prefix is set",
                });
            }
        }

        let browser_callback_path = browser_path(
            &self.callback_path,
            self.strip_prefix.as_ref(),
            self.base_path.as_ref(),
        )?;
        let browser_logout_path = self
            .logout
            .as_ref()
            .map(|logout| {
                browser_path(
                    &logout.path,
                    self.strip_prefix.as_ref(),
                    self.base_path.as_ref(),
                )
            })
            .transpose()?;
        self.browser_callback_path = browser_callback_path;
        self.browser_logout_path = browser_logout_path;
        Ok(())
    }

    /// Builds a [`LoginConfig`], validating paths.
    ///
    /// The client-facing origin (scheme + host) is **not** configured here: it
    /// is reconstructed from the grant's `redirect_uri` when the
    /// [`LoginEngine`](crate::engine::LoginEngine) is built. Only the callback
    /// path and, behind a front proxy, the public `base_path` prefix live here.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any path is malformed, the durations are
    /// invalid, or the cookie `Path` derived from `base_path` and
    /// `callback_path` is not cookie-safe.
    #[builder]
    pub fn new(
        /// Path at which the callback endpoint is mounted (e.g. `"/callback"`).
        #[builder(into)]
        callback_path: String,
        /// OAuth 2.0 scopes to request (e.g. `bon::vec!["openid"]`, which
        /// converts each element via `Into<String>`).
        scope: Vec<String>,
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
        /// Public path prefix the app is mounted under behind a front proxy
        /// (e.g. `"/app"`); the scheme and host come from the grant's
        /// `redirect_uri` at engine build. Omit when mounted at the origin root.
        #[builder(into)]
        base_path: Option<String>,
        /// Validated public/ingress mapping; cannot be combined with legacy
        /// `base_path` or `strip_prefix`. Derive the callback with `url::callback_path`.
        url_mapping: Option<crate::core::url_mapping::PublicUrlMapping>,
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
        let (base_path, strip_prefix) = if let Some(mapping) = &url_mapping {
            if base_path.is_some() || strip_prefix.is_some() {
                return Err(ConfigError::InvalidBasePath {
                    path: mapping.public_base().path().to_owned(),
                    reason: "url_mapping cannot be combined with base_path or strip_prefix",
                });
            }
            mapping_paths(mapping)
        } else {
            (base_path, strip_prefix)
        };
        let callback_path = RoutePath::validated(callback_path, |path, reason| {
            ConfigError::InvalidCallbackPath { path, reason }
        })?;
        let base_path = base_path
            .map(|prefix| {
                RoutePath::validated(prefix, |path, reason| ConfigError::InvalidBasePath {
                    path,
                    reason,
                })
            })
            .transpose()?;
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
        // validate — the stored value stays exact for the OP's byte comparison.
        validate_post_logout_redirect_uri(logout.as_ref())?;
        // Engine-side paths carry the front proxy's prefix; a path outside it
        // would silently never match a real request (and, for the callback,
        // corrupt the derived cookie scope) — reject the contradiction.
        if let Some(ref prefix) = strip_prefix {
            if prefix.strip_from(callback_path.as_str()).is_none() {
                return Err(ConfigError::InvalidCallbackPath {
                    path: callback_path.as_str().to_owned(),
                    reason: "must be within strip_prefix when strip_prefix is set",
                });
            }
            if let Some(ref logout) = logout
                && prefix.strip_from(logout.path.as_str()).is_none()
            {
                return Err(ConfigError::InvalidLogoutPath {
                    path: logout.path.as_str().to_owned(),
                    reason: "must be within strip_prefix when strip_prefix is set",
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

        // The `base_path` prefix joined to `callback_path` (minus any
        // `strip_prefix`). Both are already validated `RoutePath`s, but the
        // joined result is re-validated before it is emitted as a cookie `Path`,
        // closing the one route by which a `;`/control char could reach a
        // `Set-Cookie` header. Independent of the origin, so it's known here.
        let browser_callback_path =
            browser_path(&callback_path, strip_prefix.as_ref(), base_path.as_ref())?;
        let browser_logout_path = logout
            .as_ref()
            .map(|logout| browser_path(&logout.path, strip_prefix.as_ref(), base_path.as_ref()))
            .transpose()?;

        Ok(Self {
            url_mapping,
            callback_path,
            scope,
            session_lifetime,
            activity_policy,
            token_refresh_margin,
            default_token_lifetime,
            login_state_ttl,
            base_path,
            strip_prefix,
            logout,
            login_cookie_prefix,
            browser_callback_path,
            browser_logout_path,
        })
    }
}

fn mapping_paths(
    mapping: &crate::core::url_mapping::PublicUrlMapping,
) -> (Option<String>, Option<String>) {
    let base = mapping.public_base().path().trim_end_matches('/');
    let prefix = mapping.incoming_prefix();
    (
        (!base.is_empty()).then(|| base.to_owned()),
        (prefix != "/").then(|| prefix.to_owned()),
    )
}

#[cfg(test)]
mod tests;
