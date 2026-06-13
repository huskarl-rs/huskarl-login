//! Session state and lifecycle introspection.
//!
//! [`Session`] exposes the timing and token state that the login middleware
//! needs to enforce session policies (max lifetime, idle timeout, token-bound
//! expiry) and perform automatic token refresh.
//!
//! [`SessionState`] holds the common token/timing fields shared by all session
//! types. Session types embed `SessionState` and implement [`Session`] with
//! two methods — [`state`](Session::state) for reads and
//! [`set_state`](Session::set_state) for replacement. All other trait methods
//! have default implementations.
//!
//! State is never mutated in place. Events like [`refreshed`](SessionState::refreshed)
//! and [`with_activity`](SessionState::with_activity) produce a new `SessionState`
//! value, which is then set back via the trait. This matches the
//! load->transform->save model required for distributed session stores.

use huskarl::{
    core::{
        platform::{Duration, SystemTime},
        serde_utils::time::unix_secs,
    },
    grant::core::TokenResponse,
    token::{IdToken, RefreshToken},
};
use serde::{Deserialize, Serialize};

/// Common token and timing state shared by all session types.
///
/// Session types embed it and implement [`Session`] by providing read access
/// and a replacement method. State changes are produced by event methods
/// ([`refreshed`](Self::refreshed), [`with_activity`](Self::with_activity))
/// that return a new value rather than mutating in place.
///
/// The struct is `#[non_exhaustive]` so new fields can be added in a minor
/// release. For OAuth flows the framework constructs it from the completed
/// login; use [`SessionState::builder`] for tests and custom flows.
///
/// The raw `id_token` JWT is not stored here — see [`Session::id_token`]
/// for the rationale and the override hook.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct SessionState {
    /// Absolute expiry of the access token. Computed from the token response's
    /// `expires_in`, or from [`LoginConfig::default_token_lifetime`](crate::LoginConfig::default_token_lifetime)
    /// when `expires_in` is absent.
    #[serde(with = "unix_secs")]
    pub token_expiry: SystemTime,
    /// Refresh token issued alongside the access token, if any. Used by the
    /// middleware to obtain a new access token when `token_expiry` approaches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    /// Subject identifier from the ID token. Carried for back-channel logout
    /// revocation lookup (OIDC Back-Channel Logout 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Session ID from the ID token. Carried for front-channel and
    /// back-channel logout revocation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// When the session was created (initial login).
    #[serde(with = "unix_secs")]
    pub created_at: SystemTime,
    /// When the session was last active (last request that used this session).
    #[serde(with = "unix_secs")]
    pub last_active: SystemTime,
}

impl SessionState {
    /// Creates a `SessionState` from a completed login, extracting token data
    /// and computing the token expiry from `expires_in` (or `default_lifetime`
    /// when absent).
    pub(crate) fn from_completed(
        completed: &crate::CompletedLogin,
        default_lifetime: Duration,
    ) -> Self {
        let now = SystemTime::now();
        let token_response = completed.token_response();
        let lifetime = token_response
            .raw_token_response()
            .expires_in
            .map_or(default_lifetime, Duration::from_secs);
        let token_expiry = now + lifetime;
        let (sub, sid) = match completed.id_token_claims() {
            Some(claims) => (claims.sub.clone(), claims.sid.clone()),
            None => (None, None),
        };

        Self {
            token_expiry,
            refresh_token: token_response.refresh_token().cloned(),
            sub,
            sid,
            created_at: now,
            last_active: now,
        }
    }

    /// Produces a new `SessionState` with tokens updated from a refresh response.
    ///
    /// Replaces the raw token response and recomputes token expiry, falling
    /// back to `default_lifetime` when the refresh response omits `expires_in`.
    /// If the refresh response includes a rotated refresh token, it replaces
    /// the old one; otherwise the existing refresh token is preserved.
    #[must_use]
    pub fn refreshed(&self, token_response: &TokenResponse, default_lifetime: Duration) -> Self {
        let now = SystemTime::now();
        let mut new = self.clone();

        let lifetime = token_response
            .raw_token_response()
            .expires_in
            .map_or(default_lifetime, Duration::from_secs);
        new.token_expiry = now + lifetime;

        if let Some(rt) = token_response.refresh_token() {
            new.refresh_token = Some(rt.clone());
        }

        new.last_active = now;
        new
    }

    /// Produces a new `SessionState` with the last-active timestamp set to now.
    #[must_use]
    pub fn with_activity(&self) -> Self {
        let mut new = self.clone();
        new.last_active = SystemTime::now();
        new
    }
}

/// Exposes session state from a session type so the middleware can enforce
/// lifetime policies (max lifetime, idle timeout, token-bound expiry) and
/// perform token refresh.
///
/// Implement this on the session type used with the login middleware.
/// Only two methods are required — [`state`](Self::state) for reads and
/// [`set_state`](Self::set_state) for replacement. All others have default
/// implementations.
///
/// State is never mutated through interior references. Event methods produce
/// a new [`SessionState`] value and set it back via `set_state`, matching
/// the load->transform->save model needed for distributed session stores.
pub trait Session {
    /// Returns a shared reference to the embedded [`SessionState`].
    fn state(&self) -> &SessionState;

    /// Replaces the embedded [`SessionState`] with a new value.
    fn set_state(&mut self, state: SessionState);

    /// Absolute expiry of the access token (`received_at + expires_in`, or
    /// `received_at + default_token_lifetime` when the AS omits `expires_in`).
    fn token_expiry(&self) -> SystemTime {
        self.state().token_expiry
    }

    /// The refresh token, if the authorization server issued one.
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.state().refresh_token.as_ref()
    }

    /// The ID token (identity assertion), if the session stores one.
    ///
    /// The default implementation returns `None` because the built-in
    /// [`SessionState`] does not store the raw `id_token` (it would add ~1 KB
    /// per request to the cookie hot path). Sessions that need the `id_token`
    /// for RP-initiated logout (`id_token_hint`) should override this method
    /// on their custom session type.
    fn id_token(&self) -> Option<&IdToken> {
        None
    }

    /// Subject identifier from the ID token, if present.
    ///
    /// Used for back-channel logout revocation lookup.
    fn sub(&self) -> Option<&str> {
        self.state().sub.as_deref()
    }

    /// Session ID from the ID token, if present.
    ///
    /// Used for front-channel and back-channel logout revocation lookup.
    fn sid(&self) -> Option<&str> {
        self.state().sid.as_deref()
    }

    /// When the session was created (initial login).
    fn created_at(&self) -> SystemTime {
        self.state().created_at
    }

    /// When the session was last active (last request that used this session).
    fn last_active(&self) -> SystemTime {
        self.state().last_active
    }

    /// Apply tokens from a refresh response.
    ///
    /// Produces a new [`SessionState`] via [`SessionState::refreshed`] and sets it.
    fn apply_refresh(&mut self, token_response: &TokenResponse, default_lifetime: Duration) {
        let new_state = self.state().refreshed(token_response, default_lifetime);
        self.set_state(new_state);
    }

    /// Record that the session was active.
    ///
    /// Produces a new [`SessionState`] via [`SessionState::with_activity`] and sets it.
    fn record_activity(&mut self) {
        let new_state = self.state().with_activity();
        self.set_state(new_state);
    }
}
