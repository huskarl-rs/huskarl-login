//! `redirect_to_as` — start (or restart) the OAuth flow by redirecting the
//! user to the authorization server.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use huskarl::{core::crypto::cipher::AeadSealer as _, grant::authorization_code::StartInput};

use super::{EngineError, LoginEngine, LoginResponse, LoginStateCookie, error_chain};
use crate::{
    SessionDriver,
    cookie::{cookie_attrs, encode_payload, login_state_cookie_name},
    url::{base_url_as_string, original_url},
};

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    pub(super) async fn redirect_to_as(
        &self,
        request_headers: &HeaderMap,
        request_uri: &Uri,
        expired_session: Option<&SD::SessionType>,
    ) -> Result<LoginResponse, EngineError> {
        let orig_url = original_url(&self.config, request_uri)
            .unwrap_or_else(|| base_url_as_string(&self.config));

        let start = self
            .grant
            .start(StartInput::scopes(self.config.scopes.clone()))
            .await?;
        let state = start.pending_state.state.clone();

        let cookie_header = self
            .build_login_state_cookie(&state, orig_url, start.pending_state)
            .await?;

        let mut resp_headers = vec![
            (
                header::LOCATION,
                HeaderValue::from_str(&start.authorization_url.to_string())?,
            ),
            (header::SET_COOKIE, cookie_header),
        ];
        if let Some(s) = expired_session {
            self.append_expired_session_cookies(s, request_headers, &mut resp_headers)
                .await;
        }

        Ok(LoginResponse {
            status: StatusCode::FOUND,
            headers: resp_headers,
            body: Bytes::new(),
        })
    }

    /// Serializes the login-state payload, seals it under AEAD (with `state`
    /// as associated data), and returns the `Set-Cookie` header value.
    async fn build_login_state_cookie(
        &self,
        state: &str,
        original_url: String,
        pending_state: huskarl::grant::authorization_code::PendingState,
    ) -> Result<HeaderValue, EngineError> {
        let payload = encode_payload(&LoginStateCookie {
            original_url,
            pending_state,
        })?;
        let bundle = self.cipher.seal(&payload, state.as_bytes()).await?;
        let cookie_name = login_state_cookie_name(
            state,
            self.config.secure,
            &self.config.browser_callback_path,
            &self.config.login_cookie_prefix,
        );
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = cookie_attrs(self.config.secure, &self.config.browser_callback_path);
        let max_age = self.config.login_state_ttl.as_secs();
        Ok(HeaderValue::from_str(&format!(
            "{cookie_name}={cookie_value}; {attrs}; Max-Age={max_age}"
        ))?)
    }

    /// Best-effort delete of an expiring session: appends its cookie clears
    /// to `resp_headers`, logging and continuing on error.
    async fn append_expired_session_cookies(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
        resp_headers: &mut Vec<(http::HeaderName, HeaderValue)>,
    ) {
        match self.session_store.delete(session, request_headers).await {
            Ok(cookies) => {
                for c in cookies {
                    resp_headers.push((header::SET_COOKIE, c));
                }
            }
            Err(e) => {
                log::error!("failed to delete expired session: {}", error_chain(&*e));
            }
        }
    }

    pub(super) async fn build_error_response_with_delete(
        &self,
        status: StatusCode,
        message: &str,
        request_headers: &HeaderMap,
        expired_session: Option<&SD::SessionType>,
    ) -> LoginResponse {
        let mut resp = self.build_error_response(status, message);
        if let Some(s) = expired_session {
            self.append_expired_session_cookies(s, request_headers, &mut resp.headers)
                .await;
        }
        resp
    }
}
