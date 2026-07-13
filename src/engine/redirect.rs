//! `redirect_to_as` — start the OAuth flow by redirecting to the AS.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderValue, Uri};
use huskarl::{
    core::{crypto::cipher::AeadSealer as _, platform::SystemTime},
    grant::authorization_code::StartInput,
};

use super::{EngineError, LoginEngine, LoginResponse, LoginStateCookie};
use crate::{
    SessionDriver, SessionError, SessionErrorKind,
    cookie::{cookie_attrs, encode_payload, login_state_cookie_name},
    url::{base_url_as_string, original_url},
};

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    pub(super) async fn redirect_to_as(
        &self,
        request_uri: &Uri,
    ) -> Result<LoginResponse, EngineError> {
        let orig_url = original_url(&self.config, request_uri)
            .unwrap_or_else(|| base_url_as_string(&self.config));

        let start = self
            .grant
            .start(StartInput::scope(self.config.scope.clone()))
            .await?;
        let state = start.pending_state.state.clone();

        let cookie_header = self
            .build_login_state_cookie(&state, orig_url, start.pending_state)
            .await?;

        let location = HeaderValue::from_str(&start.authorization_url.to_string())
            .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))?;
        Ok(LoginResponse::Redirect {
            status: http::StatusCode::FOUND,
            location,
            set_cookies: vec![cookie_header],
        })
    }

    /// Seals the login-state payload under AEAD
    /// ([`login_state_aad`](super::login_state_aad) as associated data) and
    /// returns the `Set-Cookie` value.
    async fn build_login_state_cookie(
        &self,
        state: &str,
        original_url: String,
        pending_state: huskarl::grant::authorization_code::PendingState,
    ) -> Result<HeaderValue, EngineError> {
        let payload = encode_payload(&LoginStateCookie {
            original_url,
            pending_state,
            created_at: SystemTime::now(),
        })
        .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))?;
        let bundle = self
            .cipher
            .seal(&payload, &super::login_state_aad(state))
            .await
            .map_err(|e| SessionError::new(SessionErrorKind::Crypto, e))?;
        let cookie_name = login_state_cookie_name(
            state,
            self.config.secure,
            self.config.browser_callback_path.as_str(),
            self.config.login_cookie_prefix.as_str(),
        );
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = cookie_attrs(
            self.config.secure,
            self.config.browser_callback_path.as_str(),
        );
        let max_age = self.config.login_state_ttl.as_secs();
        HeaderValue::from_str(&format!(
            "{cookie_name}={cookie_value}; {attrs}; Max-Age={max_age}"
        ))
        .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))
    }
}
