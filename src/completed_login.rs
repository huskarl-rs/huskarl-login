//! Tokens and identity data produced by a successful login callback.

use crate::client::{grant::core::TokenResponse, token::id_token::IdTokenClaims};

/// Input available when building an application session after login.
///
/// It contains the OAuth token response and, for `OpenID` Connect flows, the
/// validated subject and ID-token claims. A [`SessionEnricher`](crate::SessionEnricher)
/// combines this value with framework-managed state; this value is not itself
/// the persisted session.
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
