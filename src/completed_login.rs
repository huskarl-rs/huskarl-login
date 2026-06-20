//! The result of a successful login completion.
//!
//! [`CompletedLogin`] packages what the OAuth callback produced — the token
//! response and, for OIDC flows, the validated ID token claims — and is the
//! input to session creation ([`SessionDriver::create`](crate::SessionDriver)
//! and [`SessionEnricher`](crate::SessionEnricher)).

use huskarl::{grant::core::TokenResponse, token::id_token::IdTokenClaims};

/// The token response and validated identity claims from a completed login.
///
/// Produced by the OAuth callback and consumed by session creation. Carries the
/// token response and, when the authorization server returns an ID token (OIDC),
/// the validated identity claims extracted from it. Non-standard claims are
/// accessible via `claims.extra.get("…")`.
#[derive(bon::Builder)]
pub struct CompletedLogin {
    token_response: TokenResponse,
    id_token_claims: Option<IdTokenClaims>,
}

impl CompletedLogin {
    /// Returns the token response (access token, optional refresh token, and
    /// any ID token).
    #[must_use]
    pub fn token_response(&self) -> &TokenResponse {
        &self.token_response
    }

    /// Returns the validated ID token claims — present only for OIDC flows.
    #[must_use]
    pub fn id_token_claims(&self) -> Option<&IdTokenClaims> {
        self.id_token_claims.as_ref()
    }

    /// Consumes the `CompletedLogin`, returning the token response and
    /// optional ID token claims.
    #[must_use]
    pub fn into_parts(self) -> (TokenResponse, Option<IdTokenClaims>) {
        (self.token_response, self.id_token_claims)
    }
}
