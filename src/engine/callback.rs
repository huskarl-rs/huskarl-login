//! `handle_callback` — exchange the authorization code for tokens and create
//! the session.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header};
use huskarl::core::{crypto::cipher::AeadUnsealer, http::HttpClient};
use serde::Deserialize;

use super::{LoginEngine, LoginResponse, LoginStateCookie, error_chain};
use crate::{
    LoginGrant, SessionDriver,
    cookie::{
        cookie_attrs, decode_payload, get_cookie, is_valid_oauth_state, login_state_cookie_name,
    },
};

impl<G, SD, H> LoginEngine<G, SD, H>
where
    G: LoginGrant,
    SD: SessionDriver,
    H: HttpClient + Send + Sync,
{
    pub(super) async fn handle_callback(&self, uri: &Uri, headers: &HeaderMap) -> LoginResponse {
        let (code, state, iss) = match parse_callback_params(uri.query().unwrap_or("")) {
            CallbackParse::Valid { code, state, iss } => (code, state, iss),
            CallbackParse::AuthServerError { error, description } => {
                let message = match description {
                    Some(desc) => format!("authorization denied: {desc}"),
                    None => format!("authorization denied ({error})"),
                };
                return self
                    .build_error_response_with_delete(
                        StatusCode::FORBIDDEN,
                        &message,
                        headers,
                        None,
                    )
                    .await;
            }
            CallbackParse::Missing => {
                return self
                    .build_error_response_with_delete(
                        StatusCode::BAD_REQUEST,
                        "missing code or state",
                        headers,
                        None,
                    )
                    .await;
            }
        };

        // Locate and validate the login-state cookie.
        let cookie_name = login_state_cookie_name(
            &state,
            self.config.secure,
            &self.config.browser_callback_path,
            &self.config.login_cookie_prefix,
        );
        let Some(cookie_encoded) = get_cookie(headers, &cookie_name).map(str::to_owned) else {
            // No cookie to clear — either none was set, or the browser sent a
            // cookie under a different `state` name (which we can't address).
            return self
                .build_error_response_with_delete(
                    StatusCode::BAD_REQUEST,
                    "invalid or missing state",
                    headers,
                    None,
                )
                .await;
        };

        // From here on, the login-state cookie is present and known by name —
        // every failure path clears it so a stale flow doesn't replay.
        let login_state = match self.decode_login_state(&cookie_encoded, &state).await {
            Ok(s) => s,
            Err((status, msg)) => {
                return self
                    .callback_error(status, msg, headers, &cookie_name)
                    .await;
            }
        };

        let completed_login = match self
            .grant
            .complete(
                &self.http_client,
                &login_state.pending_state,
                code,
                state,
                iss,
            )
            .await
        {
            Ok(cl) => cl,
            Err(e) => {
                log::error!("token exchange failed: {}", error_chain(&e));
                return self
                    .callback_error(
                        StatusCode::BAD_GATEWAY,
                        "token exchange failed",
                        headers,
                        &cookie_name,
                    )
                    .await;
            }
        };

        let (_new_session, session_cookies) = match self
            .session_store
            .create(completed_login, self.config.default_token_lifetime, headers)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                log::error!("failed to create session: {}", error_chain(&*e));
                return self
                    .callback_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to create session",
                        headers,
                        &cookie_name,
                    )
                    .await;
            }
        };

        self.build_callback_redirect(&login_state.original_url, &cookie_name, session_cookies)
    }

    /// Assembles the 302 response that sends the user back to their original
    /// URL: `Location`, the login-state cookie clear, and the session cookies
    /// the driver minted on `create`.
    fn build_callback_redirect(
        &self,
        original_url: &str,
        cookie_name: &str,
        session_cookies: Vec<HeaderValue>,
    ) -> LoginResponse {
        let mut resp_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if let Ok(v) = HeaderValue::from_str(original_url) {
            resp_headers.push((header::LOCATION, v));
        }
        // The 302 carries session-bearing Set-Cookie headers; tell upstream
        // caches not to retain it (RFC 6749 §5.1).
        resp_headers.push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
        if let Some(v) = self.clear_login_state_cookie(cookie_name) {
            resp_headers.push((header::SET_COOKIE, v));
        }
        for c in session_cookies {
            resp_headers.push((header::SET_COOKIE, c));
        }
        LoginResponse {
            status: StatusCode::FOUND,
            headers: resp_headers,
            body: Bytes::new(),
        }
    }

    /// Decodes the (base64-encoded, AEAD-sealed) login-state cookie and
    /// returns the deserialized payload. On failure, returns the status code
    /// and message the callback should respond with — the caller is
    /// responsible for clearing the cookie.
    async fn decode_login_state(
        &self,
        cookie_encoded: &str,
        state: &str,
    ) -> Result<LoginStateCookie, (StatusCode, &'static str)> {
        let bundle = URL_SAFE_NO_PAD
            .decode(cookie_encoded)
            .map_err(|_| (StatusCode::BAD_REQUEST, "malformed state cookie"))?;
        let plaintext = self
            .unsealer
            .unseal(None, &bundle, state.as_bytes())
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "state cookie decryption failed"))?;
        decode_payload::<LoginStateCookie>(&plaintext)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "corrupt login state"))
    }

    /// Builds the `Set-Cookie` value that clears a login-state cookie by name.
    /// Returns `None` only if the name produces an invalid header value, which
    /// shouldn't happen for cookies we generated.
    fn clear_login_state_cookie(&self, cookie_name: &str) -> Option<HeaderValue> {
        let attrs = cookie_attrs(self.config.secure, &self.config.browser_callback_path);
        HeaderValue::from_str(&format!("{cookie_name}=; {attrs}; Max-Age=0")).ok()
    }

    /// Builds an error response for a failed callback and appends a
    /// `Set-Cookie` that clears the located login-state cookie, so a stale
    /// flow cannot be replayed.
    async fn callback_error(
        &self,
        status: StatusCode,
        message: &str,
        request_headers: &HeaderMap,
        cookie_name: &str,
    ) -> LoginResponse {
        let mut resp = self
            .build_error_response_with_delete(status, message, request_headers, None)
            .await;
        if let Some(v) = self.clear_login_state_cookie(cookie_name) {
            resp.headers.push((header::SET_COOKIE, v));
        }
        resp
    }
}

/// Outcome of parsing the callback query string.
///
/// Pure data — the engine maps each variant to the appropriate HTTP response,
/// keeping query parsing decoupled from response building.
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
