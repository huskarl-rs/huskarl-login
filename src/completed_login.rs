//! [`CompletedLogin`]: the result of a successful login completion.

use huskarl::{grant::core::TokenResponse, token::id_token::IdTokenClaims};

/// The token response and validated identity claims from a completed login
/// (claims present only for OIDC flows).
#[derive(bon::Builder)]
pub struct CompletedLogin {
    token_response: TokenResponse,
    /// The subject (`sub`) registered claim from the validated ID token —
    /// present only for OIDC flows. It lives on the JWT wrapper rather than in
    /// [`IdTokenClaims`], so it is carried separately here.
    subject: Option<String>,
    id_token_claims: Option<IdTokenClaims>,
}

impl CompletedLogin {
    /// Returns the token response.
    #[must_use]
    pub fn token_response(&self) -> &TokenResponse {
        &self.token_response
    }

    /// Returns the subject (`sub`) from the validated ID token — present only
    /// for OIDC flows.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Returns the validated ID token claims — present only for OIDC flows.
    #[must_use]
    pub fn id_token_claims(&self) -> Option<&IdTokenClaims> {
        self.id_token_claims.as_ref()
    }

    /// Consumes the `CompletedLogin`, returning its parts.
    #[must_use]
    pub fn into_parts(self) -> (TokenResponse, Option<String>, Option<IdTokenClaims>) {
        (self.token_response, self.subject, self.id_token_claims)
    }
}
