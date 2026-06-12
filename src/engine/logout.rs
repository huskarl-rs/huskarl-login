//! `handle_logout` — clear the local session and redirect to either the OIDC
//! end-session endpoint or the configured post-logout target.

use http::{HeaderMap, HeaderValue, StatusCode};

use super::{LoginEngine, LoginResponse, error_chain, is_cross_site_request};
use crate::{
    LogoutConfig, Session, SessionDriver,
    url::{build_end_session_url, default_post_logout_redirect},
};

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    pub(super) async fn handle_logout(
        &self,
        logout: &LogoutConfig,
        headers: &HeaderMap,
    ) -> LoginResponse {
        // Logout is state-changing and session cookies are SameSite=Lax (sent
        // on cross-site top-level navigations), so reject forged cross-site
        // requests before touching the session.
        if is_cross_site_request(headers) {
            return self
                .build_error_response(StatusCode::FORBIDDEN, "cross-site logout request rejected");
        }

        // A missing or unreadable session is not an error during logout.
        let loaded_session = self.load_session_for_logout(headers).await;
        let redirect_target = self.logout_redirect_target(logout, loaded_session.as_ref());

        let location = match HeaderValue::from_str(&redirect_target) {
            Ok(v) => v,
            Err(e) => {
                log::error!("invalid logout redirect target: {e}");
                return self.build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build logout redirect",
                );
            }
        };

        let mut set_cookies = Vec::new();
        if let Some(ref s) = loaded_session {
            self.append_session_delete_cookies(s, headers, &mut set_cookies)
                .await;
        }

        LoginResponse::Redirect {
            location,
            set_cookies,
        }
    }

    /// Loads the session for logout, swallowing load errors as `None` (logout
    /// should still redirect even if session storage is unavailable).
    async fn load_session_for_logout(&self, headers: &HeaderMap) -> Option<SD::SessionType> {
        match self.session_store.load(headers).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("failed to load session during logout: {}", error_chain(&e));
                None
            }
        }
    }

    /// Returns the URL to redirect the user to after the local session is
    /// cleared: the `IdP`'s `end_session_endpoint` (with `id_token_hint` and
    /// `post_logout_redirect_uri` when available), falling back to the plain
    /// post-logout target if the URL can't be built.
    fn logout_redirect_target(
        &self,
        logout: &LogoutConfig,
        loaded_session: Option<&SD::SessionType>,
    ) -> String {
        let post_logout = match &logout.post_logout_redirect_uri {
            Some(uri) => uri.to_string(),
            None => default_post_logout_redirect(&self.config),
        };
        let Some(endpoint) = &logout.end_session_endpoint else {
            return post_logout;
        };
        let id_token_hint = loaded_session
            .and_then(|s| s.id_token())
            .map(huskarl::token::IdToken::token);
        build_end_session_url(endpoint, id_token_hint, Some(post_logout.as_str())).unwrap_or_else(|e| {
            log::error!("failed to build end_session URL: {e}");
            post_logout.clone()
        })
    }

    /// Deletes the session via the driver and appends the returned cookie
    /// clears to `set_cookies`. Logs and continues on delete errors.
    async fn append_session_delete_cookies(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
        set_cookies: &mut Vec<HeaderValue>,
    ) {
        match self.session_store.delete(session, request_headers).await {
            Ok(cookies) => set_cookies.extend(cookies),
            Err(e) => {
                log::error!("failed to delete session on logout: {}", error_chain(&*e));
            }
        }
    }
}
