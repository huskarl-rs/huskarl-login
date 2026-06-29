//! `handle_callback` — exchange the authorization code for tokens and create
//! the session.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use huskarl::{
    core::{crypto::cipher::AeadUnsealer as _, platform::SystemTime},
    grant::authorization_code::CompleteInput,
};
use serde::Deserialize;

use super::{LoginEngine, LoginResponse, LoginStateCookie, error_chain};
use crate::{
    CompletedLogin, SessionDriver,
    cookie::{
        cookie_attrs, decode_payload, get_cookie, is_valid_oauth_state, login_state_cookie_name,
    },
    metrics::{LoginCompleteResult, normalize_as_error},
    url::base_url_as_string,
};

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    pub(super) async fn handle_callback(&self, uri: &Uri, headers: &HeaderMap) -> LoginResponse {
        let (code, state, iss) = match parse_callback_params(uri.query().unwrap_or("")) {
            CallbackParse::Valid { code, state, iss } => (code, state, iss),
            CallbackParse::AuthServerError { error, description } => {
                return self.handle_as_error(&error, description.as_deref());
            }
            CallbackParse::Missing => {
                self.record_login_complete(&LoginCompleteResult::InvalidRequest, None);
                return self.build_error_response(StatusCode::BAD_REQUEST, "missing code or state");
            }
        };

        // Locate and validate the login-state cookie.
        let cookie_name = login_state_cookie_name(
            &state,
            self.config.secure,
            self.config.browser_callback_path.as_str(),
            self.config.login_cookie_prefix.as_str(),
        );
        let Some(cookie_encoded) = get_cookie(headers, &cookie_name).map(str::to_owned) else {
            // No cookie to clear — either none was set, or the browser sent a
            // cookie under a different `state` name (which we can't address).
            self.record_login_complete(&LoginCompleteResult::InvalidRequest, None);
            return self.build_error_response(StatusCode::BAD_REQUEST, "invalid or missing state");
        };

        // From here on, the login-state cookie is present and known by name —
        // every failure path clears it so a stale flow doesn't replay.
        let login_state = match self.decode_login_state(&cookie_encoded, &state).await {
            Ok(s) => s,
            Err((status, msg)) => {
                self.record_login_complete(&LoginCompleteResult::StateInvalid, None);
                return self.callback_error(status, msg, &cookie_name);
            }
        };

        let complete_input = CompleteInput::builder()
            .code(code)
            .state(state)
            .maybe_iss(iss)
            .build();
        let completed_login = match self
            .grant
            .complete_oidc(&login_state.pending_state, complete_input)
            .await
        {
            Ok((token_response, validated_id_token)) => CompletedLogin::builder()
                .token_response(token_response)
                .maybe_id_token_claims(validated_id_token.map(|jwt| jwt.claims))
                .build(),
            Err(e) => {
                log::error!("token exchange failed: {}", error_chain(&e));
                self.record_login_complete(&LoginCompleteResult::TokenExchangeFailed, None);
                return self.callback_error(
                    StatusCode::BAD_GATEWAY,
                    "token exchange failed",
                    &cookie_name,
                );
            }
        };

        let (_new_session, session_cookies) = match self
            .session_store
            .create(completed_login, self.config.default_token_lifetime, headers)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                log::error!("failed to create session: {}", error_chain(&e));
                self.record_login_complete(&LoginCompleteResult::SessionCreateFailed, None);
                return self.callback_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to create session",
                    &cookie_name,
                );
            }
        };

        self.record_login_complete(&LoginCompleteResult::Ok, None);
        self.build_callback_redirect(&login_state.original_url, &cookie_name, session_cookies)
    }

    /// Handles an RFC 6749 §4.1.2.1 error response from the authorization server:
    /// records the metric (error code normalized to a closed set) and renders a
    /// 403. The raw `description` reaches the error page, which must escape it.
    fn handle_as_error(&self, error: &str, description: Option<&str>) -> LoginResponse {
        let message = match description {
            Some(desc) => format!("authorization denied: {desc}"),
            None => format!("authorization denied ({error})"),
        };
        self.record_login_complete(
            &LoginCompleteResult::AsDenied,
            Some(normalize_as_error(error)),
        );
        self.build_error_response(StatusCode::FORBIDDEN, &message)
    }

    /// Assembles the 302 back to `original_url`, with the login-state cookie
    /// clear and the session cookies minted on `create`. Falls back to
    /// `base_url` if `original_url` is not a valid header value.
    fn build_callback_redirect(
        &self,
        original_url: &str,
        cookie_name: &str,
        session_cookies: Vec<HeaderValue>,
    ) -> LoginResponse {
        let location = HeaderValue::from_str(original_url)
            .or_else(|_| HeaderValue::from_str(&base_url_as_string(&self.config)))
            .unwrap_or_else(|_| HeaderValue::from_static("/"));
        let mut set_cookies = Vec::with_capacity(session_cookies.len() + 1);
        if let Some(v) = self.clear_login_state_cookie(cookie_name) {
            set_cookies.push(v);
        }
        set_cookies.extend(session_cookies);
        LoginResponse::Redirect {
            location,
            set_cookies,
        }
    }

    /// Decodes the base64-encoded, AEAD-sealed login-state cookie. On failure
    /// returns the status and message to respond with (the caller clears the
    /// cookie). Enforces
    /// [`login_state_ttl`](crate::LoginConfig::login_state_ttl) server-side.
    async fn decode_login_state(
        &self,
        cookie_encoded: &str,
        state: &str,
    ) -> Result<LoginStateCookie, (StatusCode, &'static str)> {
        let bundle = URL_SAFE_NO_PAD
            .decode(cookie_encoded)
            .map_err(|_| (StatusCode::BAD_REQUEST, "malformed state cookie"))?;
        let plaintext = self
            .cipher
            .unseal(None, &bundle, state.as_bytes())
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "state cookie decryption failed"))?;
        let login_state = decode_payload::<LoginStateCookie>(&plaintext)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt login state"))?;
        if super::elapsed_since(login_state.created_at, SystemTime::now())
            > self.config.login_state_ttl
        {
            return Err((StatusCode::BAD_REQUEST, "login state expired"));
        }
        Ok(login_state)
    }

    /// Builds the `Set-Cookie` value that clears a login-state cookie by name.
    /// `None` if the name produces an invalid header value.
    pub(super) fn clear_login_state_cookie(&self, cookie_name: &str) -> Option<HeaderValue> {
        let attrs = cookie_attrs(
            self.config.secure,
            self.config.browser_callback_path.as_str(),
        );
        HeaderValue::from_str(&format!("{cookie_name}=; {attrs}; Max-Age=0")).ok()
    }

    /// Builds a callback error response and appends a `Set-Cookie` clearing the
    /// login-state cookie.
    fn callback_error(
        &self,
        status: StatusCode,
        message: &str,
        cookie_name: &str,
    ) -> LoginResponse {
        let mut resp = self.build_error_response(status, message);
        if let Some(v) = self.clear_login_state_cookie(cookie_name) {
            resp.push_rendered_header(header::SET_COOKIE, v);
        }
        resp
    }
}

/// Outcome of parsing the callback query string.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum CallbackParse {
    /// Valid OAuth response: code + state present (and optional `iss`).
    Valid {
        code: String,
        state: String,
        iss: Option<String>,
    },
    /// Authorization server returned an error response per RFC 6749 §4.1.2.1.
    AuthServerError {
        error: String,
        description: Option<String>,
    },
    /// Neither error nor a usable code/state pair was provided.
    Missing,
}

/// Parses the callback query string into a [`CallbackParse`] outcome. Treats
/// a malformed query string the same as missing parameters.
fn parse_callback_params(query: &str) -> CallbackParse {
    #[derive(Deserialize, Default)]
    struct Raw {
        code: Option<String>,
        state: Option<String>,
        iss: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }
    let params: Raw = serde_html_form::from_str(query).unwrap_or_default();

    if let Some(error) = params.error {
        return CallbackParse::AuthServerError {
            error,
            description: params.error_description,
        };
    }
    match (params.code, params.state) {
        (Some(code), Some(state)) if is_valid_oauth_state(&state) => CallbackParse::Valid {
            code,
            state,
            iss: params.iss,
        },
        _ => CallbackParse::Missing,
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn valid_code_and_state() {
        assert_eq!(
            parse_callback_params("code=abc&state=xyz"),
            CallbackParse::Valid {
                code: "abc".to_owned(),
                state: "xyz".to_owned(),
                iss: None,
            }
        );
    }

    #[test]
    fn valid_with_iss() {
        assert_eq!(
            parse_callback_params("code=abc&state=xyz&iss=https%3A%2F%2Fas.example.com"),
            CallbackParse::Valid {
                code: "abc".to_owned(),
                state: "xyz".to_owned(),
                iss: Some("https://as.example.com".to_owned()),
            }
        );
    }

    #[test]
    fn auth_server_error_with_description() {
        assert_eq!(
            parse_callback_params("error=access_denied&error_description=user+rejected"),
            CallbackParse::AuthServerError {
                error: "access_denied".to_owned(),
                description: Some("user rejected".to_owned()),
            }
        );
    }

    #[test]
    fn auth_server_error_without_description() {
        assert_eq!(
            parse_callback_params("error=server_error"),
            CallbackParse::AuthServerError {
                error: "server_error".to_owned(),
                description: None,
            }
        );
    }

    #[test]
    fn missing_state_returns_missing() {
        assert!(matches!(
            parse_callback_params("code=abc"),
            CallbackParse::Missing
        ));
    }

    #[test]
    fn missing_code_returns_missing() {
        assert!(matches!(
            parse_callback_params("state=xyz"),
            CallbackParse::Missing
        ));
    }

    #[test]
    fn empty_query_returns_missing() {
        assert!(matches!(parse_callback_params(""), CallbackParse::Missing));
    }

    #[test]
    fn error_takes_priority_over_code_and_state() {
        // Even if code/state are present, an `error` parameter means the AS
        // rejected the flow.
        assert!(matches!(
            parse_callback_params("error=denied&code=abc&state=xyz"),
            CallbackParse::AuthServerError { .. }
        ));
    }

    #[test]
    fn state_with_unsafe_chars_treated_as_missing() {
        assert!(matches!(
            parse_callback_params("code=abc&state=xyz%3Bfoo"),
            CallbackParse::Missing
        ));
    }

    #[test]
    fn empty_state_treated_as_missing() {
        assert!(matches!(
            parse_callback_params("code=abc&state="),
            CallbackParse::Missing
        ));
    }

    #[test]
    fn overlong_state_treated_as_missing() {
        let long = "a".repeat(257);
        let q = format!("code=abc&state={long}");
        assert!(matches!(parse_callback_params(&q), CallbackParse::Missing));
    }
}
