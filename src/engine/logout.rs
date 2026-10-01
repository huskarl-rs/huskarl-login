//! `handle_logout` — clear the local session and redirect to either the OIDC
//! end-session endpoint or the configured post-logout target.

use http::{HeaderMap, HeaderValue, StatusCode, header};

use super::{DiagnosticOperation, LoginEngine, LoginResponse, is_cross_site_request};
use crate::{
    DriverLoad, LogoutConfig, Session, SessionDriver,
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
        // Logout changes authentication state and may propagate to the OP.
        // SameSite is not sufficient: a sibling origin is "same-site" and can
        // submit the browser's host-only cookie. Require the POST's Origin to
        // match the exact public origin; Fetch Metadata remains a fast
        // defense-in-depth rejection.
        if is_cross_site_request(headers) || !self.has_same_origin(headers) {
            return self.build_error_response(StatusCode::FORBIDDEN, "logout origin rejected");
        }

        // A missing or unreadable session is not an error during logout.
        let loaded_session = self.load_session_for_logout(headers).await;
        let redirect_target = self.logout_redirect_target(logout, loaded_session.as_ref());

        let location = match HeaderValue::from_str(&redirect_target) {
            Ok(v) => v,
            Err(e) => {
                self.diagnose(DiagnosticOperation::LogoutRedirect, &e);
                return self.build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to build logout redirect",
                );
            }
        };

        // Browser-local logout must not depend on the backing store: clear the
        // session cookies even when loading or revoking server-side state
        // fails. Logout still attempts backend-wide revocation below; copied
        // store pointers remain usable until that succeeds or their record TTL
        // expires.
        let set_cookies = self.session_store.clear_session_cookies(headers);
        if let Some(ref s) = loaded_session {
            self.revoke_session_best_effort(s).await;
        }

        // 303, not 302: logout is a POST, and See Other pins the follow-up
        // request to GET (302 leaves the method to the client's discretion —
        // browsers switch to GET, other clients may re-POST).
        LoginResponse::Redirect {
            status: StatusCode::SEE_OTHER,
            location,
            set_cookies,
        }
    }

    fn has_same_origin(&self, headers: &HeaderMap) -> bool {
        let Some(origin) = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<http::Uri>().ok())
        else {
            return false;
        };
        if origin.query().is_some() || !matches!(origin.path(), "" | "/") {
            return false;
        }
        same_origin(&origin, &self.base_url)
    }

    /// Loads the session for logout, swallowing load errors as `None`.
    async fn load_session_for_logout(&self, headers: &HeaderMap) -> Option<SD::SessionType> {
        match self.session_store.load(headers).await {
            Ok(DriverLoad::Valid(session)) => Some(session),
            Ok(DriverLoad::Absent | DriverLoad::Invalid(_)) => None,
            Err(e) => {
                self.diagnose(DiagnosticOperation::LogoutLoad, &e);
                None
            }
        }
    }

    /// Returns the post-logout redirect URL: the `IdP`'s `end_session_endpoint`
    /// (with `id_token_hint`/`post_logout_redirect_uri` when available), falling
    /// back to the plain post-logout target.
    fn logout_redirect_target(
        &self,
        logout: &LogoutConfig,
        loaded_session: Option<&SD::SessionType>,
    ) -> String {
        let post_logout = match &logout.post_logout_redirect_uri {
            Some(uri) => uri.clone(),
            None => default_post_logout_redirect(&self.base_url),
        };
        let Some(endpoint) = &logout.end_session_endpoint else {
            return post_logout;
        };
        let id_token_hint = loaded_session
            .and_then(|s| s.id_token())
            .map(crate::client::token::IdToken::token);
        // Always send client_id: the built-in sessions don't store the
        // id_token, so without it the OP can't identify the RP and will drop
        // post_logout_redirect_uri (OIDC RP-Initiated Logout 1.0 §2).
        let client_id = Some(self.grant.client_id());
        build_end_session_url(
            endpoint.as_uri(),
            id_token_hint,
            client_id,
            Some(post_logout.as_str()),
        )
        .unwrap_or_else(|e| {
            self.diagnose(DiagnosticOperation::LogoutUrl, &e);
            post_logout.clone()
        })
    }

    /// Attempts server-side revocation; browser-local cookie clearing is
    /// performed independently by [`SessionDriver::clear_session_cookies`].
    async fn revoke_session_best_effort(&self, session: &SD::SessionType) {
        match self.session_store.revoke(session).await {
            Ok(()) => {}
            Err(e) => {
                self.diagnose(DiagnosticOperation::LogoutRevoke, &e);
            }
        }
    }
}

fn same_origin(left: &http::Uri, right: &http::Uri) -> bool {
    match (origin_parts(left), origin_parts(right)) {
        (Some((ls, lh, lp)), Some((rs, rh, rp))) => {
            ls.eq_ignore_ascii_case(rs) && lh.eq_ignore_ascii_case(rh) && lp == rp
        }
        _ => false,
    }
}

fn origin_parts(uri: &http::Uri) -> Option<(&str, &str, u16)> {
    let scheme = uri.scheme_str()?;
    let host = uri.host()?;
    let port = uri.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    Some((scheme, host, port))
}
