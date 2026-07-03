//! Observer traits and result types for login and session-cookie metrics.
//!
//! The [`LoginEngineMetrics`] and [`SessionCookieMetrics`] observer traits wire
//! a metrics backend in; result enums carry the outcome as `&'static str` labels.

use huskarl::core::platform::MaybeSendSync;

use crate::engine::TeardownReason;

/// Outcome of a session cookie decryption attempt.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum DecryptResult {
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
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Observer for session cookie encrypt/decrypt events. Absent cookies are
/// silent.
pub trait SessionCookieMetrics: MaybeSendSync + 'static {
    /// Record a decryption attempt. `kid` is the identity from the kid sidecar cookie, or `None` if absent/undecodable.
    fn record_decrypt(&self, cookie_name: &str, kid: Option<&str>, result: &DecryptResult);

    /// Record a completed encryption. `kid` is the active sealer's key ID, or `None` if the key has no identity.
    fn record_encrypt(&self, cookie_name: &str, kid: Option<&str>);
}

// ── Login engine metrics ───────────────────────────────────────────────────────

/// Outcome of a login redirect attempt.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum LoginStartResult {
    /// The redirect to the authorization server was produced successfully.
    Ok,
    /// Generating the redirect failed (e.g. authorization server unreachable).
    Error,
}

impl LoginStartResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of processing an OAuth callback (token exchange and session creation).
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum LoginCompleteResult {
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
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
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

/// Normalizes an attacker-suppliable AS `error` code: known codes pass through, anything else maps to `"other"`.
#[must_use]
pub fn normalize_as_error(error: &str) -> &'static str {
    KNOWN_AS_ERROR_CODES
        .iter()
        .find(|code| **code == error)
        .copied()
        .unwrap_or("other")
}

/// Outcome of a token refresh attempt.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum RefreshResult {
    /// The session had no refresh token — it was cleared.
    NoRefreshToken,
    /// The refresh token was exchanged successfully for new tokens.
    Ok,
    /// The token refresh request failed conclusively — session was cleared.
    Failed,
    /// The refresh failed with a retryable error while the access token was
    /// still valid — the session was retained and will be re-attempted later.
    FailedRetained,
}

impl RefreshResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Observer for [`LoginEngine`](crate::engine::LoginEngine) login-flow events.
/// Methods are called inline on the request path, so they must not block.
pub trait LoginEngineMetrics: MaybeSendSync + 'static {
    /// Record a login redirect attempt.
    fn record_login_start(&self, result: &LoginStartResult);

    /// Record the outcome of an OAuth callback. `as_error` is the normalized AS `error` code for [`LoginCompleteResult::AsDenied`], else `None`.
    fn record_login_complete(&self, result: &LoginCompleteResult, as_error: Option<&str>);

    /// Record the outcome of a token refresh attempt.
    fn record_refresh(&self, result: &RefreshResult);

    /// Record why a presented session was dropped rather than served. No-op by default.
    fn record_teardown(&self, _reason: &TeardownReason) {}
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
