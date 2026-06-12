//! `redirect_to_as` — start (or restart) the OAuth flow by redirecting the
//! user to the authorization server.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, Uri, header};
use huskarl::{
    core::{
        crypto::cipher::{AeadSealer as _, AeadUnsealer as _},
        platform::SystemTime,
    },
    grant::authorization_code::StartInput,
};

use super::{EngineError, LoginEngine, LoginResponse, LoginStateCookie};
use crate::{
    SessionDriver,
    cookie::{
        cookie_attrs, decode_payload, encode_payload, login_state_cookie_name,
        login_state_cookie_name_prefix,
    },
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

        let location = HeaderValue::from_str(&start.authorization_url.to_string())?;
        let mut set_cookies = vec![cookie_header];
        set_cookies.extend(self.evict_excess_login_flows(request_headers).await);

        Ok(LoginResponse::Redirect {
            location,
            set_cookies,
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
            created_at: SystemTime::now(),
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

    /// Cookie-jar housekeeping for in-flight login flows: when the request
    /// already carries enough login-state cookies that, together with the one
    /// this redirect is about to set, the browser would exceed
    /// [`max_pending_logins`](crate::LoginConfig::max_pending_logins), emits
    /// `Max-Age=0` clears for the excess. Unreadable cookies (garbage,
    /// tampered, sealed under a retired key, or a pre-`created_at` format)
    /// are evicted first; readable flows are ranked by their sealed
    /// `created_at`, oldest out.
    ///
    /// Counting is done on cookie *names* alone, so the common case — fewer
    /// cookies than the cap — performs no decryption. Only an over-cap
    /// request pays one unseal per candidate, and login starts are rare.
    /// Eviction is best-effort housekeeping: an evicted tab's callback fails
    /// with an invalid-state error and that tab just logs in again.
    async fn evict_excess_login_flows(&self, request_headers: &HeaderMap) -> Vec<HeaderValue> {
        // The new flow's cookie occupies one slot under the cap.
        let keep = self.config.max_pending_logins.max(1) - 1;
        let name_prefix = login_state_cookie_name_prefix(
            self.config.secure,
            &self.config.browser_callback_path,
            &self.config.login_cookie_prefix,
        );
        let candidates = collect_login_state_cookies(request_headers, &name_prefix);
        if candidates.len() <= keep {
            return vec![];
        }

        let mut evict: Vec<String> = Vec::new();
        let mut alive: Vec<(SystemTime, String)> = Vec::new();
        for (name, state, value) in candidates {
            match self.read_login_state_created_at(&value, &state).await {
                Some(created_at) => alive.push((created_at, name)),
                None => evict.push(name),
            }
        }
        alive.sort_by_key(|(created_at, _)| *created_at);
        let excess = alive.len().saturating_sub(keep);
        evict.extend(alive.drain(..excess).map(|(_, name)| name));
        evict
            .iter()
            .filter_map(|name| self.clear_login_state_cookie(name))
            .collect()
    }

    /// Unseals a login-state cookie (the `state` from its name is the AAD)
    /// just far enough to read its `created_at`. Returns `None` for anything
    /// that doesn't decode — the caller treats that as first in line for
    /// eviction.
    async fn read_login_state_created_at(&self, encoded: &str, state: &str) -> Option<SystemTime> {
        let bundle = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let plaintext = self
            .cipher
            .unseal(None, &bundle, state.as_bytes())
            .await
            .ok()?;
        let cookie: LoginStateCookie = decode_payload(&plaintext).ok()?;
        Some(cookie.created_at)
    }

}

/// Collects `(name, state, value)` for every request cookie whose name starts
/// with the login-state prefix, deduplicated by name. The `state` is whatever
/// follows the prefix — it is *not* validated here, because a name that
/// matches the prefix but carries a malformed state can't be one of our live
/// flows and will simply fail to unseal, putting it first in line for
/// eviction.
fn collect_login_state_cookies(
    headers: &HeaderMap,
    name_prefix: &str,
) -> Vec<(String, String, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            let name = name.trim();
            let Some(state) = name.strip_prefix(name_prefix) else {
                continue;
            };
            if seen.insert(name.to_owned()) {
                out.push((name.to_owned(), state.to_owned(), value.trim().to_owned()));
            }
        }
    }
    out
}
