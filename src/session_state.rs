//! Session state and lifecycle introspection: [`SessionState`] holds the
//! token/timing fields, [`Session`] exposes them to the middleware. State is
//! immutable. Liveness is tracked separately (see [`crate::liveness`]).

use huskarl::{
    core::{
        platform::{Duration, SystemTime},
        serde_utils::time::{option_unix_secs, unix_secs},
    },
    grant::core::TokenResponse,
    token::{IdToken, RefreshToken},
};
use serde::{Deserialize, Serialize};

/// Common token and timing state shared by all session types.
///
/// Use [`SessionState::builder`] for tests and custom flows. The raw `id_token`
/// JWT is not stored here — see [`Session::id_token`].
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct SessionState {
    /// Absolute expiry of the access token (from `expires_in`, else the default lifetime).
    #[serde(with = "unix_secs")]
    pub token_expiry: SystemTime,
    /// Refresh token issued alongside the access token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    /// Subject identifier from the ID token, for logout revocation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Session ID from the ID token, for logout revocation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// When the session was created (initial login).
    #[serde(with = "unix_secs")]
    pub created_at: SystemTime,
    /// Absolute session deadline, **fixed at login**: `created_at` plus the
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap in force when
    /// the session was created; `None` under a delegated lifetime. See
    /// [`Bounded`](crate::SessionLifetime::Bounded) for how changing the cap
    /// affects existing sessions.
    #[serde(with = "option_unix_secs")]
    pub expire_at: Option<SystemTime>,
}

impl SessionState {
    /// Creates a `SessionState` from a completed login. `max_lifetime` is the
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap stamped onto
    /// the session store, freezing [`expire_at`](Self::expire_at) at login.
    pub(crate) fn from_completed(
        completed: &crate::CompletedLogin,
        default_lifetime: Duration,
        max_lifetime: Option<Duration>,
    ) -> Self {
        let now = SystemTime::now();
        let token_response = completed.token_response();
        let lifetime = token_response
            .raw_token_response()
            .expires_in
            .map_or(default_lifetime, Duration::from_secs);
        let token_expiry = now + lifetime;
        let sub = completed.subject().map(str::to_string);
        let sid = completed
            .id_token_claims()
            .and_then(|claims| claims.sid.clone());

        Self {
            token_expiry,
            refresh_token: token_response.refresh_token().cloned(),
            sub,
            sid,
            created_at: now,
            expire_at: max_lifetime.map(|max| now + max),
        }
    }

    /// Produces a new `SessionState` with tokens updated from a refresh response,
    /// keeping the existing refresh token unless the response rotates it.
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

        new
    }
}

/// Exposes session state so the middleware can enforce lifetime policies and refresh tokens.
///
/// Implement on the session type used with the middleware; only
/// [`state`](Self::state) and [`set_state`](Self::set_state) are required.
pub trait Session {
    /// Returns a shared reference to the embedded [`SessionState`].
    fn state(&self) -> &SessionState;

    /// Replaces the embedded [`SessionState`] with a new value.
    fn set_state(&mut self, state: SessionState);

    /// Absolute expiry of the access token.
    fn token_expiry(&self) -> SystemTime {
        self.state().token_expiry
    }

    /// The refresh token, if the authorization server issued one.
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.state().refresh_token.as_ref()
    }

    /// The ID token, if the session stores one.
    ///
    /// Defaults to `None`: [`SessionState`] does not store the raw `id_token`.
    /// Override on a custom session type to supply it (e.g. for `id_token_hint`).
    fn id_token(&self) -> Option<&IdToken> {
        None
    }

    /// Subject identifier from the ID token, if present.
    fn sub(&self) -> Option<&str> {
        self.state().sub.as_deref()
    }

    /// Session ID from the ID token, if present.
    fn sid(&self) -> Option<&str> {
        self.state().sid.as_deref()
    }

    /// When the session was created (initial login).
    fn created_at(&self) -> SystemTime {
        self.state().created_at
    }

    /// Absolute session deadline fixed at login, if the deployment bounded
    /// it — see [`SessionState::expire_at`]. External stores retain the
    /// record until at least this instant; the engine enforces it alongside
    /// the live config.
    fn expire_at(&self) -> Option<SystemTime> {
        self.state().expire_at
    }

    /// Apply tokens from a refresh response via [`SessionState::refreshed`].
    fn apply_refresh(&mut self, token_response: &TokenResponse, default_lifetime: Duration) {
        let new_state = self.state().refreshed(token_response, default_lifetime);
        self.set_state(new_state);
    }
}
