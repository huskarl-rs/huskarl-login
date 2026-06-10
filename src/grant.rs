//! Authorization Code Grant abstraction.
//!
//! [`LoginGrant`] decouples the login middleware from the concrete grant type.
//! A blanket implementation is provided for
//! [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant),
//! which automatically handles PAR, JAR, `DPoP`, and PKCE based on the grant's
//! own configuration.

use huskarl::{
    core::{
        BoxedError,
        client_auth::ClientAuthentication,
        dpop::AuthorizationServerDPoP,
        http::HttpClient,
        platform::{MaybeSend, MaybeSendSync},
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrant, CompleteInput, Jar, PendingState, StartInput, StartOutput,
        },
        core::{OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
    token::{RefreshToken, id_token::IdTokenClaims},
};
use serde::{Deserialize, Serialize};

/// The result of a successful login completion.
///
/// Contains the token response and, when the authorization server returns an
/// ID token (OIDC), the validated identity claims extracted from it. The
/// claims use the default `HashMap<String, serde_json::Value>` extra type so
/// non-standard claims are accessible via `claims.extra.get("…")`.
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

    /// Returns the validated ID token claims, if present.
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

/// Abstracts the Authorization Code Grant start/complete lifecycle.
///
/// Implementations handle PAR, JAR, `DPoP`, PKCE, and state/nonce generation
/// automatically. A blanket implementation is provided for
/// [`AuthorizationCodeGrant`].
pub trait LoginGrant: MaybeSendSync {
    /// Begin an Authorization Code flow: build the authorization URL and the
    /// per-flow `PendingState` (state, nonce, PKCE verifier) that must be
    /// stashed for the callback.
    fn start(
        &self,
        http_client: &impl HttpClient,
        scopes: Vec<String>,
    ) -> impl Future<Output = Result<StartOutput, BoxedError>> + MaybeSend;

    /// Exchange an authorization `code` for tokens, validating `state` (and
    /// `iss` when present) against the stashed `PendingState`.
    fn complete(
        &self,
        http_client: &impl HttpClient,
        pending_state: &PendingState,
        code: String,
        state: String,
        iss: Option<String>,
    ) -> impl Future<Output = Result<CompletedLogin, BoxedError>> + MaybeSend;

    /// Exchange a `refresh_token` for a fresh token response.
    fn refresh(
        &self,
        http_client: &impl HttpClient,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = Result<TokenResponse, BoxedError>> + MaybeSend;
}

impl<Auth, D, J, Extra> LoginGrant for AuthorizationCodeGrant<Auth, D, J, Extra>
where
    Auth: ClientAuthentication + Clone + MaybeSendSync + 'static,
    D: AuthorizationServerDPoP + MaybeSendSync + 'static,
    J: Jar + MaybeSendSync + 'static,
    Extra: Clone + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static,
{
    async fn start(
        &self,
        http_client: &impl HttpClient,
        scopes: Vec<String>,
    ) -> Result<StartOutput, BoxedError> {
        // The inherent start() takes StartInput; LoginGrant::start takes Vec<String>.
        // Different signatures mean self.start(...) unambiguously calls the inherent method.
        self.start(http_client, StartInput::scopes(scopes))
            .await
            .map_err(BoxedError::from_err)
    }

    async fn complete(
        &self,
        http_client: &impl HttpClient,
        pending_state: &PendingState,
        code: String,
        state: String,
        iss: Option<String>,
    ) -> Result<CompletedLogin, BoxedError> {
        // The inherent complete() takes CompleteInput; LoginGrant::complete takes individual
        // parameters — again, no ambiguity when calling self.complete(...).
        let input = CompleteInput::builder()
            .code(code)
            .state(state)
            .maybe_iss(iss)
            .build();
        let (token_response, validated_id_token) = self
            .complete_oidc(http_client, pending_state, input)
            .await
            .map_err(BoxedError::from_err)?;

        // The grant validates claims with its concrete `Extra` type; re-shape
        // through `Value` into the default `HashMap<String, Value>` Extra so
        // `CompletedLogin` is non-generic and any extra fields stay reachable
        // via `claims.extra.get(...)`.
        let id_token_claims = validated_id_token
            .map(|jwt| {
                serde_json::to_value(&jwt.claims)
                    .and_then(serde_json::from_value::<IdTokenClaims>)
                    .map_err(|e| BoxedError::from_err(ClaimsReshapeError(e)))
            })
            .transpose()?;

        Ok(CompletedLogin::builder()
            .token_response(token_response)
            .maybe_id_token_claims(id_token_claims)
            .build())
    }

    async fn refresh(
        &self,
        http_client: &impl HttpClient,
        refresh_token: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        self.to_refresh_grant()
            .exchange(
                http_client,
                RefreshGrantParameters::refresh_token(refresh_token.clone()),
            )
            .await
            .map_err(BoxedError::from_err)
    }
}

#[derive(Debug)]
struct ClaimsReshapeError(serde_json::Error);

impl std::fmt::Display for ClaimsReshapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to reshape id token claims: {}", self.0)
    }
}

impl std::error::Error for ClaimsReshapeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl huskarl::core::Error for ClaimsReshapeError {
    fn is_retryable(&self) -> bool {
        false
    }
}
