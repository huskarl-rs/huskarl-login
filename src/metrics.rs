//! Metrics emitted by this crate through the [`metrics`] facade. Install a
//! recorder (e.g. `metrics-exporter-prometheus`) to collect them; without one
//! they are no-ops. All are counters, incremented inline on the request path.
//!
//! | Counter | Labels |
//! |---------|--------|
//! | `huskarl.login.start` | `outcome`: `ok`, `error` |
//! | `huskarl.login.complete` | `outcome`: `ok`, `already_authenticated`, `as_denied`, `invalid_request`, `state_invalid`, `token_exchange_failed`, `session_create_failed`; `error`: the normalized AS error code for `as_denied` (RFC 6749 / OIDC Core codes, else `other`), `none` otherwise |
//! | `huskarl.session.refresh` | `outcome`: `ok`, `no_refresh_token`, `failed`, `failed_retained`, `failed_unavailable` |
//! | `huskarl.session.teardown` | `reason`: [`TeardownReason`] values (`max_lifetime`, `idle_timeout`, …) |
//! | `huskarl.session.superseded_delete` | `outcome`: `deleted`, `not_found`, `load_failed`, `delete_failed` |
//! | `huskarl.session.liveness_failure` | `op`: `read` (failed open), `touch`, `clear` |
//! | `huskarl.session_cookie.encrypt` | `cookie`: cookie name; `kid`: active key id, `none` if the key has no identity |
//! | `huskarl.session_cookie.decrypt` | `cookie`: cookie name; `kid`: matched key id, `unknown` (unmatched sidecar — attacker-suppliable values never become labels), `none` (no sidecar); `outcome`: `ok`, `bad_encoding`, `decrypt_failed`, `payload_invalid` |
//!
//! When `metrics_name` is set on the [`LoginEngine`] builder, every counter
//! additionally carries a `name` label with that value — it tells engine
//! instances apart when one process runs several (the same label
//! `huskarl.aead.*` uses for cipher instances).
//!
//! [`TeardownReason`]: crate::engine::TeardownReason
//! [`LoginEngine`]: crate::engine::LoginEngine

/// Increments counter `name` with `labels`, appending the instance `name`
/// label when `metrics_name` is set.
pub(crate) fn emit_counter(
    name: &'static str,
    mut labels: Vec<metrics::Label>,
    metrics_name: Option<&str>,
) {
    if let Some(v) = metrics_name {
        labels.push(metrics::Label::new("name", v.to_owned()));
    }
    metrics::counter!(name, labels).increment(1);
}

/// Outcome of a session cookie decryption attempt; the
/// `huskarl.session_cookie.decrypt` `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum DecryptResult {
    /// The cookie was successfully decrypted and deserialized.
    Ok,
    /// The cookie value was not valid base64url.
    BadEncoding,
    /// The AEAD seal could not be verified (wrong key, tampered payload, etc.).
    DecryptFailed,
    /// The plaintext was authenticated but could not be deserialized.
    PayloadInvalid,
}

impl DecryptResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of a login redirect attempt; the `huskarl.login.start` `outcome`
/// label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LoginStartResult {
    /// The redirect to the authorization server was produced successfully.
    Ok,
    /// Generating the redirect failed (e.g. authorization server unreachable).
    Error,
}

impl LoginStartResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of processing an OAuth callback; the `huskarl.login.complete`
/// `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LoginCompleteResult {
    /// Login completed successfully — a new session was created.
    Ok,
    /// The callback carried no usable login state but the browser already
    /// holds a valid session (e.g. a second tab completing after the first,
    /// or a re-navigated stale callback URL) — redirected home without
    /// re-authenticating.
    AlreadyAuthenticated,
    /// The authorization server returned an error response (e.g. user denied access).
    AsDenied,
    /// The callback request was malformed: missing or invalid `code` or `state`.
    InvalidRequest,
    /// The login-state cookie was absent, corrupted, or could not be authenticated.
    StateInvalid,
    /// The token exchange with the authorization server failed.
    TokenExchangeFailed,
    /// Session creation in the session store failed.
    SessionCreateFailed,
}

impl LoginCompleteResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Authorization error codes recognized by [`normalize_as_error`] (RFC 6749 / OIDC Core).
const KNOWN_AS_ERROR_CODES: &[&str] = &[
    // RFC 6749 §4.1.2.1
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    // OIDC Core §3.1.2.6
    "interaction_required",
    "login_required",
    "account_selection_required",
    "consent_required",
    "invalid_request_uri",
    "invalid_request_object",
    "request_not_supported",
    "request_uri_not_supported",
    "registration_not_supported",
];

/// Normalizes an attacker-suppliable AS `error` code: known codes pass
/// through, anything else maps to `"other"`.
pub(crate) fn normalize_as_error(error: &str) -> &'static str {
    KNOWN_AS_ERROR_CODES
        .iter()
        .find(|code| **code == error)
        .copied()
        .unwrap_or("other")
}

/// Outcome of a token refresh attempt; the `huskarl.session.refresh`
/// `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum RefreshResult {
    /// The session had no refresh token — it was cleared.
    NoRefreshToken,
    /// The refresh token was exchanged successfully for new tokens.
    Ok,
    /// The token refresh request failed conclusively — session was cleared.
    Failed,
    /// The refresh failed with a retryable error while the access token was
    /// still valid — the session was retained and keeps being served.
    FailedRetained,
    /// The refresh failed with a retryable error after the access token had
    /// expired — the session was retained for a later retry, but the request
    /// could not be served
    /// ([`LoadedSession::RefreshUnavailable`](crate::engine::LoadedSession::RefreshUnavailable)).
    FailedUnavailable,
}

impl RefreshResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of deleting the record a new login superseded; the
/// `huskarl.session.superseded_delete` `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum SupersededDeleteResult {
    /// The superseded record was deleted.
    Deleted,
    /// The pointer cookie was valid but no record exists for it.
    NotFound,
    /// Loading the superseded record failed; it may still be stored.
    LoadFailed,
    /// Deleting the superseded record failed; it is still stored.
    DeleteFailed,
}

impl SupersededDeleteResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// A [`LivenessStore`](crate::LivenessStore) operation that failed
/// (best-effort: the request proceeded); the
/// `huskarl.session.liveness_failure` `op` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LivenessFailure {
    /// `last_active` could not be read; the session was served as active
    /// (fail open).
    Read,
    /// Recording activity failed; the next advance is delayed.
    Touch,
    /// Removing an entry failed; the stale entry remains until its TTL.
    Clear,
}

impl LivenessFailure {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_as_error_passes_known_codes_through() {
        for code in KNOWN_AS_ERROR_CODES {
            assert_eq!(normalize_as_error(code), *code);
        }
    }

    #[test]
    fn normalize_as_error_maps_unknown_to_other() {
        for input in [
            "",
            "not_a_real_code",
            "ACCESS_DENIED", // case-sensitive: not the registered code
            "access_denied ",
            "access_denied\n",
            "a]b{c}", // label-syntax metacharacters
        ] {
            assert_eq!(normalize_as_error(input), "other", "input: {input:?}");
        }
    }

    #[test]
    fn normalize_as_error_rejects_oversized_input() {
        let long = "a".repeat(64 * 1024);
        assert_eq!(normalize_as_error(&long), "other");
    }
}
