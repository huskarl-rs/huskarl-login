//! [`CompletedLogin`]: the result of a successful login completion.

use huskarl::{grant::core::TokenResponse, token::id_token::IdTokenClaims};

/// The token response and validated identity claims from a completed login
/// (claims present only for OIDC flows).
#[derive(bon::Builder)]
pub struct CompletedLogin {
    token_response: TokenResponse,
    id_token_claims: Option<IdTokenClaims>,
}

impl CompletedLogin {
    /// Returns the token response.
    #[must_use]
    pub fn token_response(&self) -> &TokenResponse {
        &self.token_response
    }

    /// Returns the validated ID token claims — present only for OIDC flows.
    #[must_use]
    pub fn id_token_claims(&self) -> Option<&IdTokenClaims> {
        self.id_token_claims.as_ref()
    }

    /// Consumes the `CompletedLogin`, returning its parts.
    #[must_use]
    pub fn into_parts(self) -> (TokenResponse, Option<IdTokenClaims>) {
        (self.token_response, self.id_token_claims)
    }
}
