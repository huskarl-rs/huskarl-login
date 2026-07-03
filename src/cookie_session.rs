//! Cookie-based session storage. [`CookieSessionStore`] encrypts the session
//! into AEAD-sealed browser cookies, chunked (`.0`, `.1`, …) to stay within
//! browser size limits.

use std::{borrow::Cow, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::core::{
    crypto::cipher::{AeadCipher, AeadSealer as _, CipherMatch},
    platform::MaybeSendSync,
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    completed_login::CompletedLogin,
    config::RoutePath,
    cookie::{
        CookieName, CookieSealer, DEFAULT_COOKIE_MAX_AGE, decode_payload, encode_payload,
        get_kid_cookie, kid_cookie_name, unseal_with_kid_fallback,
    },
    enrich::{NoEnrichment, SessionEnricher},
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionDriver, SessionError, SessionErrorKind},
    session_state::{Session, SessionState},
};

const CHUNK_SIZE: usize = 3800;

/// Default chunk budget for a saved session (see the builder's `max_chunks`).
/// Two chunks ≈ 7.6 KB of cookie data (~5.6 KB of plaintext session), sized
/// against common 8–16 KB request-header limits (nginx and Apache default to
/// 8 KB, Node to 16 KB in total).
const DEFAULT_MAX_CHUNKS: usize = 2;

/// [`CookieSessionStore`] refused to save a session whose sealed payload
/// exceeds the configured chunk budget.
#[derive(Debug, Clone, Snafu)]
#[snafu(display(
    "serialized session needs {chunks} cookie chunks ({encoded_len} bytes encoded), over the \
     configured max_chunks of {max_chunks}; oversized cookies can exceed request-header limits \
     and lock the client out — shrink the session payload or use a store-backed session"
))]
struct SessionTooLarge {
    /// Base64-encoded size of the sealed session.
    encoded_len: usize,
    /// Chunks the payload would need.
    chunks: usize,
    /// The configured budget it exceeded.
    max_chunks: usize,
}

/// A [`Session`] that round-trips through serde, sealable into the session
/// cookie. Blanket-implemented; build custom payloads via a [`SessionEnricher`].
pub trait CookiePayload:
    Session + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static
{
}

impl<T: Session + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static> CookiePayload
    for T
{
}

/// The default [`CookieSessionStore`] payload: a transparent newtype over
/// [`SessionState`], carrying no claims beyond its `sub`/`sid`.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct CookieSession(SessionState);

impl Session for CookieSession {
    fn state(&self) -> &SessionState {
        &self.0
    }
    fn set_state(&mut self, state: SessionState) {
        self.0 = state;
    }
}

/// Lets [`NoEnrichment`] build the default session directly from the seed.
impl From<SessionState> for CookieSession {
    fn from(state: SessionState) -> Self {
        CookieSession(state)
    }
}

/// A built-in session store that encrypts session data into chunked cookies.
///
/// The type parameter `C` is the [`CookiePayload`] stored in the cookie,
/// defaulting to [`CookieSession`]. Decryption failure is treated as "no
/// session". The `Secure` attribute and `__Host-`/`__Secure-` prefix are
/// stamped on by the engine via
/// [`SessionDriver::apply_cookie_secure`](crate::SessionDriver::apply_cookie_secure),
/// not configured here.
///
/// Cookie sessions are stateless: [`delete`](SessionDriver::delete) only
/// clears the cooperating browser's cookie (no server-side revocation, no idle
/// timeout); a stolen copy stays valid until
/// [`max_lifetime`](crate::LoginConfig::max_lifetime) elapses. For revocation,
/// use [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
pub struct CookieSessionStore<C = CookieSession> {
    /// Shared cookie-sealing machinery — see [`CookieSealer`].
    sealer: CookieSealer,
    enricher: Box<dyn SessionEnricher<SessionState, C>>,
    /// Chunk budget enforced on save — see the builder's `max_chunks`.
    max_chunks: usize,
}

#[bon::bon]
impl<C> CookieSessionStore<C> {
    /// Creates a new cookie session store. Finish the builder with `build()`
    /// (uses [`NoEnrichment`]; requires `C: From<SessionState>`) or
    /// `build_with_enricher(…)` to attach an async [`SessionEnricher`].
    #[builder(state_mod(name = "cookie_store_builder"), finish_fn(vis = "", name = build_internal))]
    pub fn new(
        #[builder(finish_fn)] enricher: Box<dyn SessionEnricher<SessionState, C>>,
        #[builder(with = |cipher: impl AeadCipher + 'static| Arc::new(cipher) as Arc<dyn AeadCipher>)]
        cipher: Arc<dyn AeadCipher>,
        /// Base name for the session cookie.
        cookie_name: CookieName,
        /// Cookie `Path` scope.
        cookie_path: RoutePath,
        /// Cookie `Max-Age`; defaults to 400 days. Pass `LoginConfig`'s
        /// `max_lifetime` so the browser discards the cookie when the session
        /// can no longer be valid.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Most chunk cookies a saved session may occupy; a save needing more
        /// fails instead of writing. Each chunk holds 3800 bytes of base64
        /// (~2.8 KB of plaintext), so the default of 2 allows ~5.6 KB of
        /// serialized session — sized against common 8–16 KB request-header
        /// limits, past which servers reject requests *before* any code that
        /// could clear the cookies runs, locking the client out for the
        /// cookies' lifetime. Raise this only if every proxy in front of the
        /// app accepts larger request headers; if sessions routinely need
        /// more than one chunk, prefer
        /// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
        /// Values below 1 are treated as 1.
        #[builder(default = DEFAULT_MAX_CHUNKS)]
        max_chunks: usize,
        /// Optional metrics observer for encrypt/decrypt events.
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        Self {
            sealer: CookieSealer::new(cipher, cookie_name, cookie_path, max_age, metrics),
            enricher,
            max_chunks: max_chunks.max(1),
        }
    }
}

impl<C, S: cookie_store_builder::IsComplete> CookieSessionStoreBuilder<C, S> {
    /// Finishes the builder with the default [`NoEnrichment`] enricher, which
    /// converts the [`SessionState`] seed into the payload via `From`.
    #[must_use]
    pub fn build(self) -> CookieSessionStore<C>
    where
        C: From<SessionState>,
    {
        self.build_internal(Box::new(NoEnrichment))
    }

    /// Finishes the builder with a custom [`SessionEnricher`], for payloads
    /// that need ID token claims or I/O to construct.
    #[must_use]
    pub fn build_with_enricher(
        self,
        enricher: impl SessionEnricher<SessionState, C> + 'static,
    ) -> CookieSessionStore<C> {
        self.build_internal(Box::new(enricher))
    }

    /// Finishes the builder with a synchronous claim-mapper that builds the
    /// payload from the [`SessionState`] seed and the [`CompletedLogin`]
    /// without I/O. For `await`-ing enrichment use
    /// [`build_with_enricher`](Self::build_with_enricher).
    #[must_use]
    pub fn build_with_claims<F>(self, f: F) -> CookieSessionStore<C>
    where
        F: Fn(SessionState, &CompletedLogin) -> Result<C, SessionError> + MaybeSendSync + 'static,
    {
        self.build_internal(Box::new(crate::enrich::ClaimsFn(f)))
    }
}

impl<C> CookieSessionStore<C> {
    /// Returns the active cipher's key ID, if the key has an identity.
    #[must_use]
    pub fn key_id(&self) -> Option<Cow<'_, str>> {
        self.sealer.key_id()
    }
}

// -- Internal methods --

impl<C: CookiePayload> CookieSessionStore<C> {
    pub(crate) async fn load_session(&self, headers: &http::HeaderMap) -> Option<C> {
        let chunks = self.collect_session_chunks(headers);
        let raw_encoded = reassemble_chunks(&chunks)?;

        // A session-cookie-shaped value is present — record the outcome.
        let kid = get_kid_cookie(headers, &self.sealer.cookie_name);

        let Ok(bundle) = URL_SAFE_NO_PAD.decode(&raw_encoded) else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::BadEncoding);
            return None;
        };
        let cipher_match = kid
            .as_deref()
            .map(|k| CipherMatch::builder().kid(k).build());
        let aad = self.sealer.aad("session");
        let Some(plaintext) =
            unseal_with_kid_fallback(&self.sealer.cipher, cipher_match.as_ref(), &bundle, &aad)
                .await
        else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::DecryptFailed);
            return None;
        };
        if let Ok(session) = decode_payload(&plaintext) {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::Ok);
            Some(session)
        } else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::PayloadInvalid);
            None
        }
    }

    /// Scans request `Cookie` headers for `{cookie_name}.N` pairs, returning a
    /// map of chunk index to value. Unrelated cookies are ignored.
    fn collect_session_chunks(
        &self,
        headers: &http::HeaderMap,
    ) -> std::collections::HashMap<usize, String> {
        let mut chunks = std::collections::HashMap::new();
        for value in headers.get_all(http::header::COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            for pair in s.split(';') {
                if let Some((index, val)) = self.parse_chunk_pair(pair) {
                    chunks.insert(index, val);
                }
            }
        }
        chunks
    }

    /// Parses a `name=value` cookie pair into `(index, value)` if `name`
    /// matches `{cookie_name}.N`.
    fn parse_chunk_pair(&self, pair: &str) -> Option<(usize, String)> {
        let (k, v) = pair.trim().split_once('=')?;
        Some((self.parse_chunk_index(k)?, v.trim().to_owned()))
    }

    /// Parses the chunk index `N` from a `{cookie_name}.N` cookie name.
    fn parse_chunk_index(&self, name: &str) -> Option<usize> {
        let suffix = name.trim().strip_prefix(&self.sealer.cookie_name)?;
        suffix.strip_prefix('.')?.parse::<usize>().ok()
    }

    /// Invokes `f` once with each `{cookie_name}.N` index the browser sent.
    fn for_each_request_chunk_index(&self, headers: &http::HeaderMap, mut f: impl FnMut(usize)) {
        for value in headers.get_all(http::header::COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            for pair in s.split(';') {
                let Some((name, _)) = pair.trim().split_once('=') else {
                    continue;
                };
                if let Some(idx) = self.parse_chunk_index(name) {
                    f(idx);
                }
            }
        }
    }

    pub(crate) async fn save_session(
        &self,
        session: &C,
        request_headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let payload =
            encode_payload(session).map_err(|e| SessionError::new(SessionErrorKind::Store, e))?;
        let aad = self.sealer.aad("session");
        let bundle = self
            .sealer
            .cipher
            .seal(&payload, &aad)
            .await
            .map_err(|e| SessionError::new(SessionErrorKind::Crypto, e))?;
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let chunks = split_into_chunks(&cookie_value);
        let num_chunks = chunks.len();
        // Refuse oversized sessions instead of writing them: past common
        // request-header limits the server rejects every request before the
        // clearing path could run, bricking the client for the cookies'
        // Max-Age. Failing the save surfaces the problem at login instead.
        if num_chunks > self.max_chunks {
            return Err(SessionError::new(
                SessionErrorKind::Store,
                SessionTooLarge {
                    encoded_len: cookie_value.len(),
                    chunks: num_chunks,
                    max_chunks: self.max_chunks,
                },
            ));
        }
        // Read the active key's identity from the same cipher that just sealed
        // the bundle. The cipher is fixed at construction so this is stable;
        // if huskarl-login ever switches to a multi-key sealer that picks
        // per-call, this should move to a select-then-use pattern via
        // `AeadCipherSelector`.
        let kid = self.sealer.key_id();
        self.sealer.record_encrypt(kid.as_deref());

        let attrs = self.sealer.cookie_attrs();
        let mut headers = Vec::with_capacity(num_chunks + 2);
        for (i, chunk) in chunks.iter().enumerate() {
            headers.push(self.build_chunk_header(i, chunk, &attrs)?);
        }
        self.append_clears_for_leftover_chunks(&mut headers, num_chunks, request_headers);
        headers.push(self.sealer.build_kid_header(kid.as_deref())?);
        Ok(headers)
    }

    /// Builds the `Set-Cookie` header for chunk `i`.
    fn build_chunk_header(
        &self,
        i: usize,
        chunk: &str,
        attrs: &str,
    ) -> Result<HeaderValue, SessionError> {
        HeaderValue::from_str(&format!("{}.{i}={chunk}; {attrs}", self.sealer.cookie_name))
            .map_err(|e| SessionError::new(SessionErrorKind::Store, e))
    }

    /// Appends `Max-Age=0` clears for every chunk slot the browser sent that
    /// this save will not overwrite (indices `>= num_chunks`).
    fn append_clears_for_leftover_chunks(
        &self,
        headers: &mut Vec<HeaderValue>,
        num_chunks: usize,
        request_headers: &http::HeaderMap,
    ) {
        let clear_attrs = format!("{}; Max-Age=0", self.sealer.base_cookie_attrs());
        let cookie_name = &self.sealer.cookie_name;
        self.for_each_request_chunk_index(request_headers, |idx| {
            if idx >= num_chunks
                && let Ok(v) =
                    HeaderValue::from_str(&format!("{cookie_name}.{idx}=; {clear_attrs}"))
            {
                headers.push(v);
            }
        });
    }

    pub(crate) fn delete_headers(&self, request_headers: &http::HeaderMap) -> Vec<HeaderValue> {
        let clear_attrs = format!("{}; Max-Age=0", self.sealer.base_cookie_attrs());
        let cookie_name = &self.sealer.cookie_name;
        let mut headers = Vec::new();
        // Clear the kid sidecar unconditionally — cheap and avoids leaving a
        // stale hint that would just degrade the next request to trial-decrypt
        // against a session that no longer exists.
        let kid_name = kid_cookie_name(cookie_name);
        if let Ok(v) = HeaderValue::from_str(&format!("{kid_name}=; {clear_attrs}")) {
            headers.push(v);
        }
        // Clear every chunk slot the browser currently has — we don't have
        // a fixed cap to sweep, but we don't need one: the request tells us
        // exactly which slots exist.
        self.for_each_request_chunk_index(request_headers, |idx| {
            if let Ok(v) = HeaderValue::from_str(&format!("{cookie_name}.{idx}=; {clear_attrs}")) {
                headers.push(v);
            }
        });
        headers
    }
}

impl<C: CookiePayload> crate::session::sealed::Sealed for CookieSessionStore<C> {}

impl<C: CookiePayload> SessionDriver for CookieSessionStore<C> {
    type SessionType = C;
    type LoadError = std::convert::Infallible;

    fn apply_cookie_secure(&mut self, secure: bool) {
        self.sealer.apply_secure(secure);
    }

    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher> {
        self.sealer.aead.clone()
    }

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> Result<(C, Vec<HeaderValue>), SessionError> {
        let state = SessionState::from_completed(&completed, default_lifetime);
        let session = self.enricher.build_session(state, &completed).await?;
        let cookies = self.save_session(&session, headers).await?;
        Ok((session, cookies))
    }

    async fn load(&self, headers: &http::HeaderMap) -> Result<Option<C>, std::convert::Infallible> {
        Ok(self.load_session(headers).await)
    }

    async fn save(
        &self,
        session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session, headers).await
    }

    // Cookie sessions have no server-side liveness — they use the default
    // `check_liveness` (`Untracked`) and `commit_touch` (no-op) from
    // `SessionDriver`, so idle timeout is not enforced and activity is not
    // recorded. Absolute `max_lifetime` (from `created_at`) still applies.

    // Clearing chunk cookies is pure header construction with no I/O; the
    // `async` is only here to satisfy the `SessionDriver` trait signature.
    #[allow(clippy::unused_async_trait_impl)]
    async fn delete(
        &self,
        _session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        Ok(self.delete_headers(headers))
    }
}

/// Splits the encoded session string into [`CHUNK_SIZE`]-byte slices. Input is
/// ASCII base64, so byte-range slicing is always on a `char` boundary.
fn split_into_chunks(cookie_value: &str) -> Vec<&str> {
    let len = cookie_value.len();
    (0..len)
        .step_by(CHUNK_SIZE)
        .map(|start| &cookie_value[start..(start + CHUNK_SIZE).min(len)])
        .collect()
}

/// Reassembles the chunked payload by concatenating `{name}.0`, `{name}.1`, …
/// until a gap is found. Returns `None` if chunk 0 is absent; truncation or
/// gaps just yield a payload the AEAD layer rejects as "no session".
fn reassemble_chunks(chunks: &std::collections::HashMap<usize, String>) -> Option<String> {
    let first = chunks.get(&0)?;
    let mut raw_encoded = String::with_capacity(chunks.len() * CHUNK_SIZE);
    raw_encoded.push_str(first);
    let mut i = 1;
    while let Some(chunk) = chunks.get(&i) {
        raw_encoded.push_str(chunk);
        i += 1;
    }
    Some(raw_encoded)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use http::HeaderMap;
    use huskarl::core::{crypto::cipher::AeadV1Cipher, platform::MaybeSendBoxFuture};
    use huskarl_crypto_native::aead::AesGcmKey;

    use super::*;
    use crate::{
        config::InvalidRoutePath,
        cookie::{InvalidCookieName, encode_kid},
        session_state::SessionState,
        test_support::{aes_key_with_kid, test_cipher, test_cipher_with_kid},
    };

    // ── Cipher / fixtures ─────────────────────────────────────────────────

    fn test_state() -> SessionState {
        let now = SystemTime::now();
        SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(now)
            .build()
    }

    async fn test_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    #[test]
    fn cookie_path_rejects_unsafe_path() {
        // The cookie_path lands in a Set-Cookie `Path` attribute, so a `;`
        // (or control char) must be rejected when the `RoutePath` is built —
        // the builder only accepts an already-validated `RoutePath`.
        let result = "/bad;inject".parse::<RoutePath>();
        assert!(matches!(result, Err(InvalidRoutePath { .. })));
    }

    #[test]
    fn cookie_name_rejects_unsafe_name() {
        // The cookie name is interpolated into `Set-Cookie` as `{name}=...`, so
        // a `;` (or any non-token char) must be rejected when the `CookieName`
        // is built — the builder only accepts an already-validated `CookieName`.
        let result = "bad;name".parse::<CookieName>();
        assert!(matches!(result, Err(InvalidCookieName { .. })));
    }

    /// Builds a request `Cookie:` header from the `Set-Cookie` values a save
    /// produced, stripping attributes.
    fn request_cookies_from_set_cookies(set_cookies: &[HeaderValue]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let mut pairs = Vec::new();
        for v in set_cookies {
            let s = v.to_str().unwrap();
            // Skip Max-Age=0 clears (empty value).
            let pair = s.split(';').next().unwrap();
            let (_name, value) = pair.split_once('=').unwrap();
            if !value.is_empty() {
                pairs.push(pair.to_owned());
            }
        }
        if !pairs.is_empty() {
            headers.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        headers
    }

    /// A request `Cookie:` header carrying chunk slots `.0` through `.{n-1}`.
    fn request_with_chunk_slots(n: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if n > 0 {
            let pairs: Vec<String> = (0..n)
                .map(|i| format!("__Host-huskarl_session.{i}=x"))
                .collect();
            headers.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        headers
    }

    // ── Cookie attribute tests ────────────────────────────────────────────

    #[tokio::test]
    async fn save_emits_chunk_zero_with_raw_base64_value() {
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();

        let chunk0 = cookies[0].to_str().unwrap();
        assert!(
            chunk0.starts_with("__Host-huskarl_session.0="),
            "got: {chunk0}"
        );
        let value = chunk0.split('=').nth(1).unwrap().split(';').next().unwrap();
        // URL-safe base64 has no ':' — chunk 0 is now raw payload, no prefix.
        assert!(
            !value.contains(':'),
            "chunk 0 must not carry a delimiter prefix: {value}"
        );
        assert!(!value.is_empty(), "chunk 0 must carry payload data");
    }

    #[tokio::test]
    async fn secure_subpath_store_emits_secure_prefixed_cookies() {
        // A sub-path scope can't carry `__Host-` (browsers require `Path=/`),
        // but `__Secure-` is valid there — the store derives it so sub-path
        // deployments aren't left with an unprefixed session cookie.
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/app".parse().unwrap())
            .build();
        let cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let chunk0 = cookies[0].to_str().unwrap();
        assert!(
            chunk0.starts_with("__Secure-huskarl_session.0="),
            "got: {chunk0}"
        );
        assert!(chunk0.contains("Path=/app"));
    }

    #[tokio::test]
    async fn save_sets_security_attributes() {
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let chunk0 = cookies[0].to_str().unwrap();
        assert!(chunk0.contains("HttpOnly"));
        assert!(chunk0.contains("SameSite=Lax"));
        assert!(chunk0.contains("Secure"));
        assert!(chunk0.contains("Path=/"));
    }

    #[tokio::test]
    async fn save_emits_no_chunk_clears_when_request_has_none() {
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let chunk_clears = cookies
            .iter()
            .filter(|c| {
                let s = c.to_str().unwrap();
                // Exclude the kid sidecar: it lives under `__Host-huskarl_session.kid`
                // and is always emitted (as a set or clear) on save, but it's
                // not a chunk.
                s.contains("__Host-huskarl_session.")
                    && !s.starts_with("__Host-huskarl_session.kid=")
                    && s.contains("Max-Age=0")
            })
            .count();
        assert_eq!(
            chunk_clears, 0,
            "no chunk slots to clear without prior chunks"
        );
    }

    #[tokio::test]
    async fn save_emits_kid_set_when_cipher_has_identity() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("arn:aws:kms:us-east-1:111:key/abc").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let expected_value = URL_SAFE_NO_PAD.encode("arn:aws:kms:us-east-1:111:key/abc".as_bytes());
        let kid_set = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with(&format!("__Host-huskarl_session.kid={expected_value};"))
        });
        assert!(kid_set, "expected kid sidecar set to base64url(identity)");
    }

    #[tokio::test]
    async fn save_then_load_roundtrips_with_kid_sidecar() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("test-kid").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let session = CookieSession(test_state());
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies_from_set_cookies(&set_cookies);
        // Sanity: the kid sidecar made it into the simulated request.
        assert_eq!(
            get_kid_cookie(&req_headers, "__Host-huskarl_session").as_deref(),
            Some("test-kid")
        );
        let loaded = store.load_session(&req_headers).await;
        assert!(
            loaded.is_some(),
            "session should load with kid sidecar present"
        );
    }

    #[tokio::test]
    async fn load_falls_back_when_kid_sidecar_is_garbage() {
        // Sidecar present but garbled (not base64url): the helper returns None,
        // and load proceeds with trial-decrypt — which still succeeds because
        // the AEAD bundle authenticates regardless of the hint.
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("test-kid").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let session = CookieSession(test_state());
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let mut req_headers = request_cookies_from_set_cookies(&set_cookies);
        // Overwrite the cookie header with chunks + a deliberately bad kid.
        let existing = req_headers
            .get(http::header::COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        // Strip any kid pair from the existing cookie string, then append a bad one.
        let stripped: Vec<&str> = existing
            .split(';')
            .map(str::trim)
            .filter(|p| !p.starts_with("__Host-huskarl_session.kid="))
            .collect();
        let combined = format!("{}; __Host-huskarl_session.kid=!!!", stripped.join("; "));
        req_headers.insert(http::header::COOKIE, combined.parse().unwrap());
        assert!(store.load_session(&req_headers).await.is_some());
    }

    // ── kid sidecar as hint, not filter ───────────────────────────────────

    use huskarl::core::crypto::cipher::{AeadDecryptor, MultiKeyCipher, MultiKeyDecryptor};

    /// A rotation-shaped cipher: seals under "v2", unseals under {"v1", "v2"}.
    /// Its decryptor treats an exact-kid match as definitive, so a wrong
    /// sidecar hint actually bites (unlike the single-key test ciphers).
    async fn multi_key_cipher() -> MultiKeyCipher<AesGcmKey> {
        let decryptor = MultiKeyDecryptor::new(vec![
            Arc::new(aes_key_with_kid("v1", 1).await) as Arc<dyn AeadDecryptor>,
            Arc::new(aes_key_with_kid("v2", 2).await) as Arc<dyn AeadDecryptor>,
        ]);
        MultiKeyCipher::new(aes_key_with_kid("v2", 2).await, decryptor)
    }

    async fn multi_key_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .cipher(multi_key_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    /// Replaces the kid sidecar pair in the request's `Cookie` header with
    /// `value`, leaving the session chunks untouched.
    fn override_kid_cookie(req_headers: &mut HeaderMap, value: &str) {
        let existing = req_headers
            .get(http::header::COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let mut pairs: Vec<String> = existing
            .split(';')
            .map(str::trim)
            .filter(|p| !p.starts_with("__Host-huskarl_session.kid="))
            .map(str::to_owned)
            .collect();
        pairs.push(format!("__Host-huskarl_session.kid={value}"));
        req_headers.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
    }

    #[tokio::test]
    async fn load_falls_back_when_kid_sidecar_names_wrong_configured_key() {
        // The sidecar decodes cleanly but names "v1" while the payload was
        // sealed under "v2". The multi-key decryptor treats an exact-kid match
        // as definitive, so honoring the hint alone would fail the decrypt.
        // The load path must degrade to trial-decrypt (hint, not filter) and
        // still load the session.
        let store = multi_key_store().await;
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let mut req = request_cookies_from_set_cookies(&set_cookies);
        // Sanity: the save stamped the real sealing key's identity.
        assert_eq!(
            get_kid_cookie(&req, "__Host-huskarl_session").as_deref(),
            Some("v2")
        );
        override_kid_cookie(&mut req, &encode_kid("v1"));
        assert!(
            store.load_session(&req).await.is_some(),
            "wrong-but-configured kid hint must fall back to trial-decrypt"
        );
    }

    #[tokio::test]
    async fn load_falls_back_when_kid_sidecar_names_unknown_key() {
        // The sidecar names an identity no configured key has. Multi-key
        // selection finds nothing ("no matching key") — the load path must
        // retry across all keys instead of treating that as a dead session.
        let store = multi_key_store().await;
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let mut req = request_cookies_from_set_cookies(&set_cookies);
        override_kid_cookie(&mut req, &encode_kid("v9"));
        assert!(
            store.load_session(&req).await.is_some(),
            "unknown kid hint must fall back to trial-decrypt"
        );
    }

    #[tokio::test]
    async fn load_fallback_does_not_authenticate_foreign_bundles() {
        // Negative control: the fallback widens the key search, not the
        // authenticity gate. A bundle sealed under a key outside the
        // configured set must still fail, whatever the sidecar claims.
        let store = multi_key_store().await;
        let foreign = AeadV1Cipher::new(aes_key_with_kid("v9", 9).await);
        let payload = crate::cookie::encode_payload(&CookieSession(test_state())).unwrap();
        let bundle = foreign
            .seal(&payload, &store.sealer.aad("session"))
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!(
                "__Host-huskarl_session.0={}; __Host-huskarl_session.kid={}",
                URL_SAFE_NO_PAD.encode(&bundle),
                encode_kid("v1"),
            )
            .parse()
            .unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    #[tokio::test]
    async fn session_value_is_bound_to_its_cookie_name() {
        // F1: the session AAD binds the cookie name, so a value sealed for one
        // cookie context cannot be unsealed by another that shares the AEAD key
        // but uses a different cookie name.
        let cipher: Arc<dyn AeadCipher> = Arc::new(test_cipher().await);
        let sealer_a = CookieSealer::new(
            cipher.clone(),
            "app_a".parse().unwrap(),
            "/".parse().unwrap(),
            DEFAULT_COOKIE_MAX_AGE,
            None,
        );
        let sealer_b = CookieSealer::new(
            cipher.clone(),
            "app_b".parse().unwrap(),
            "/".parse().unwrap(),
            DEFAULT_COOKIE_MAX_AGE,
            None,
        );

        let bundle = sealer_a
            .cipher
            .seal(b"a session payload", &sealer_a.aad("session"))
            .await
            .unwrap();

        // Same key, different cookie name → the AAD differs, so it must not unseal.
        assert!(
            unseal_with_kid_fallback(&sealer_b.cipher, None, &bundle, &sealer_b.aad("session"))
                .await
                .is_none(),
            "a session sealed for app_a must not unseal under app_b's cookie name"
        );
        // Sanity: it unseals under its own cookie name.
        assert!(
            unseal_with_kid_fallback(&sealer_a.cipher, None, &bundle, &sealer_a.aad("session"))
                .await
                .is_some(),
        );
    }

    #[tokio::test]
    async fn save_emits_kid_clear_when_cipher_has_no_identity() {
        // The test cipher reports `key_id() == None`, so every save emits a
        // Max-Age=0 clear for the kid sidecar — defensively cleaning up any
        // sidecar set under a previous identity-bearing key.
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let kid_clear = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("__Host-huskarl_session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(
            kid_clear,
            "expected kid sidecar clear with no-identity cipher"
        );
    }

    #[tokio::test]
    async fn save_clears_only_request_chunks_above_new_count() {
        // Browser sent chunks .0 through .4 from a prior larger session.
        // New save fits in a single chunk → must emit clears for slots .1-.4,
        // and NOT clear slot .0 (it's about to be overwritten with new data).
        let store = test_store().await;
        let session = CookieSession(test_state());
        let req = request_with_chunk_slots(5);
        let cookies = store.save_session(&session, &req).await.unwrap();

        for stale in 1..5 {
            let cleared = cookies.iter().any(|c| {
                let s = c.to_str().unwrap();
                s.starts_with(&format!("__Host-huskarl_session.{stale}=;"))
                    && s.contains("Max-Age=0")
            });
            assert!(cleared, "expected clear for stale slot .{stale}");
        }
        // Slot .0 is being overwritten with data, not cleared.
        let zero_clear = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("__Host-huskarl_session.0=;") && s.contains("Max-Age=0")
        });
        assert!(
            !zero_clear,
            "slot .0 must not be cleared — it's overwritten with new data",
        );
    }

    // ── Save / load roundtrip ─────────────────────────────────────────────

    /// Sanity-check that the CBOR payload is smaller than the JSON equivalent.
    #[test]
    fn cbor_payload_is_smaller_than_json() {
        let state = test_state();
        let session = CookieSession(state);

        let json = serde_json::to_vec(&session).unwrap();
        let mut cbor = Vec::new();
        ciborium::into_writer(&session, &mut cbor).unwrap();

        assert!(
            cbor.len() < json.len(),
            "CBOR ({}) should be smaller than JSON ({})",
            cbor.len(),
            json.len()
        );
        // Allow some slack but flag if savings drop below ~15%.
        assert!(
            cbor.len() * 100 / json.len() <= 85,
            "expected CBOR <=85% of JSON size, got {}% ({} / {})",
            cbor.len() * 100 / json.len(),
            cbor.len(),
            json.len()
        );
    }

    #[tokio::test]
    async fn save_then_load_roundtrips_state() {
        let store = test_store().await;
        let original_state = test_state();
        let session = CookieSession(original_state.clone());

        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies_from_set_cookies(&set_cookies);
        let loaded = store
            .load_session(&req_headers)
            .await
            .expect("session loads");

        // SessionState serializes timestamps as unix seconds, so compare at
        // second precision.
        let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(
            secs(loaded.state().token_expiry),
            secs(original_state.token_expiry)
        );
        assert_eq!(
            secs(loaded.state().created_at),
            secs(original_state.created_at)
        );
    }

    // ── SessionEnricher / CookiePayload ───────────────────────────────────

    /// An enrichment-built session type: `email` is required, so there is no
    /// `From<SessionState>` and it must be built by an enricher.
    #[derive(Serialize, Deserialize)]
    struct EnrichedSession {
        state: SessionState,
        email: String,
    }

    impl Session for EnrichedSession {
        fn state(&self) -> &SessionState {
            &self.state
        }
        fn set_state(&mut self, s: SessionState) {
            self.state = s;
        }
    }

    /// Stands in for an enricher that awaits its own clients while building
    /// the session.
    struct TestEnricher;

    impl SessionEnricher<SessionState, EnrichedSession> for TestEnricher {
        fn build_session<'a>(
            &'a self,
            state: SessionState,
            _completed: &'a CompletedLogin,
        ) -> MaybeSendBoxFuture<'a, Result<EnrichedSession, SessionError>> {
            Box::pin(async move {
                Ok(EnrichedSession {
                    state,
                    email: "user@example.com".to_owned(),
                })
            })
        }
    }

    fn assert_session_driver<T: SessionDriver>(_: &T) {}

    #[tokio::test]
    async fn enriched_store_roundtrips_enrichment_only_payload() {
        // EnrichedSession has no From<SessionState>, so plain `build()` would
        // not compile — the enricher must be supplied at the finisher.
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_enricher(TestEnricher);
        assert_session_driver(&store);

        let session = EnrichedSession {
            state: test_state(),
            email: "user@example.com".to_owned(),
        };
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req = request_cookies_from_set_cookies(&set_cookies);
        let loaded = store.load_session(&req).await.expect("session loads");
        assert_eq!(loaded.email, "user@example.com");
    }

    #[tokio::test]
    async fn default_store_still_satisfies_session_driver() {
        // Regression guard: the default `build()` finisher (NoEnrichment)
        // must keep producing a store the engine can drive.
        let store = test_store().await;
        assert_session_driver(&store);
    }

    #[tokio::test]
    async fn session_aead_cipher_returns_the_configured_cipher() {
        // The accessor a convenience layer uses to default the login-state
        // cipher: it must hand back the store's actual configured cipher
        // (matched here by reported key id), not a re-wrapped or empty one.
        use huskarl::core::crypto::cipher::AeadEncryptor as _;
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let cipher = SessionDriver::session_aead_cipher(&store);
        assert_eq!(cipher.key_id().as_deref(), Some("v5"));
    }

    /// A completed login carrying an `email` profile claim.
    fn completed_with_email(email: &str) -> CompletedLogin {
        let token_response = huskarl::grant::core::RawTokenResponse::builder()
            // A fixture token value, not a key — `SecretString::new` is the
            // value wrapper, distinct from the `Secret` key-source layer.
            .access_token(huskarl::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .build()
            .into_token_response(None, SystemTime::now())
            .unwrap();
        let mut claims = huskarl::token::id_token::IdTokenClaims::default();
        claims.profile.email = Some(email.to_owned());
        CompletedLogin::builder()
            .token_response(token_response)
            .id_token_claims(claims)
            .build()
    }

    #[tokio::test]
    async fn build_with_claims_maps_id_token_claims_into_session() {
        // The synchronous finisher: no async enricher, just a closure that
        // reads the completed login. EnrichedSession has no From<SessionState>,
        // so this is the only no-I/O way to populate `email`.
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_claims(|state, completed| {
                Ok(EnrichedSession {
                    state,
                    email: completed
                        .id_token_claims()
                        .and_then(|c| c.profile.email.clone())
                        .ok_or_else(|| {
                            SessionError::new(SessionErrorKind::Store, "missing email claim")
                        })?,
                })
            });
        assert_session_driver(&store);

        let (session, cookies) = store
            .create(
                completed_with_email("user@example.com"),
                Duration::from_hours(1),
                &HeaderMap::new(),
            )
            .await
            .expect("create succeeds");
        assert_eq!(session.email, "user@example.com");

        // The mapped session round-trips through the cookie the same as any
        // other payload.
        let req = request_cookies_from_set_cookies(&cookies);
        let loaded = store.load_session(&req).await.expect("session loads");
        assert_eq!(loaded.email, "user@example.com");
    }

    #[tokio::test]
    async fn build_with_claims_error_fails_session_creation() {
        // A claim-mapper that returns Err aborts session creation, propagating
        // the error just like a failed async enricher.
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_claims(|_state, _completed| {
                Err(SessionError::new(
                    SessionErrorKind::Store,
                    "enrichment boom",
                ))
            });
        // The session types here aren't `Debug`, so assert on the `Err` arm
        // directly rather than via `expect_err`.
        let result = store
            .create(
                completed_with_email("user@example.com"),
                Duration::from_hours(1),
                &HeaderMap::new(),
            )
            .await;
        assert!(
            matches!(&result, Err(e)
                if e.kind() == SessionErrorKind::Store
                    && std::error::Error::source(e)
                        .is_some_and(|s| s.to_string().contains("enrichment boom"))),
            "enricher error must propagate",
        );
    }

    // ── max_chunks budget ─────────────────────────────────────────────────

    fn oversized_session() -> EnrichedSession {
        // ~9 KB of payload → ~12 KB of base64 → 4 chunks.
        EnrichedSession {
            state: test_state(),
            email: "x".repeat(9000),
        }
    }

    #[tokio::test]
    async fn save_rejects_session_over_default_chunk_budget() {
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_enricher(TestEnricher);
        let result = store
            .save_session(&oversized_session(), &HeaderMap::new())
            .await;
        // 4 chunks exceeds the default budget of 2: the save must fail loudly
        // instead of emitting cookies that can trip request-header limits and
        // lock the client out.
        assert!(
            matches!(&result, Err(e) if e.kind() == SessionErrorKind::Store
                && std::error::Error::source(e)
                    .is_some_and(|s| s.to_string().contains("max_chunks"))),
            "oversized session must fail the save with the budget in the message"
        );
    }

    #[tokio::test]
    async fn save_allows_larger_sessions_when_budget_is_raised() {
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .max_chunks(4)
            .build_with_enricher(TestEnricher);
        let session = oversized_session();
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .expect("raised budget accepts 4 chunks");
        let chunk_sets = cookies
            .iter()
            .filter(|c| {
                let s = c.to_str().unwrap();
                s.starts_with("__Host-huskarl_session.")
                    && !s.starts_with("__Host-huskarl_session.kid")
            })
            .count();
        assert_eq!(chunk_sets, 4);
        // The large payload still round-trips.
        let req = request_cookies_from_set_cookies(&cookies);
        let loaded = store.load_session(&req).await.expect("session loads");
        assert_eq!(loaded.email.len(), 9000);
    }

    #[tokio::test]
    async fn max_chunks_zero_is_treated_as_one() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .max_chunks(0)
            .build();
        // A small session (one chunk) still saves under the clamped budget.
        let cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .expect("single-chunk session saves under clamped budget");
        assert!(
            cookies
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("__Host-huskarl_session.0="))
        );
    }

    #[tokio::test]
    async fn load_returns_none_when_no_cookies() {
        let store = test_store().await;
        assert!(store.load_session(&HeaderMap::new()).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_for_unrelated_cookies() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "other=value; another=42".parse().unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_when_continuation_chunk_missing() {
        // Gap between chunks 0 and 2: reassembly stops at chunk 1's gap,
        // producing only chunk 0's data, which then fails AEAD authentication.
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=AAAA; __Host-huskarl_session.2=BBBB"
                .parse()
                .unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_when_decryption_fails() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        // Valid base64 but won't decrypt under the test cipher.
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    // ── delete ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_emits_clears_for_every_chunk_slot_the_request_sent() {
        let store = test_store().await;
        let req = request_with_chunk_slots(5);
        let clears = store.delete_headers(&req);
        // Kid sidecar + 5 chunk slots (.0 through .4).
        assert_eq!(clears.len(), 6);
        for c in &clears {
            assert!(c.to_str().unwrap().contains("Max-Age=0"));
        }
        for i in 0..5 {
            let found = clears.iter().any(|c| {
                let s = c.to_str().unwrap();
                s.starts_with(&format!("__Host-huskarl_session.{i}=;"))
            });
            assert!(found, "expected clear for slot .{i}");
        }
        let kid_cleared = clears.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("__Host-huskarl_session.kid=;")
        });
        assert!(kid_cleared, "expected kid sidecar clear");
    }

    #[tokio::test]
    async fn delete_emits_only_kid_clear_when_request_has_no_chunks() {
        let store = test_store().await;
        let clears = store.delete_headers(&HeaderMap::new());
        assert_eq!(clears.len(), 1);
        let kid = clears.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("__Host-huskarl_session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(kid, "expected kid sidecar clear");
    }

    // ── parse_chunk_pair ──────────────────────────────────────────────────

    #[tokio::test]
    async fn parse_chunk_pair_matches_indexed_cookie() {
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("__Host-huskarl_session.3=abc"),
            Some((3, "abc".to_owned()))
        );
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_unrelated_cookie() {
        let store = test_store().await;
        assert_eq!(store.parse_chunk_pair("other=value"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_base_name_without_index() {
        let store = test_store().await;
        // "__Host-huskarl_session=foo" — missing `.N` suffix.
        assert_eq!(store.parse_chunk_pair("__Host-huskarl_session=foo"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_non_numeric_suffix() {
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("__Host-huskarl_session.abc=foo"),
            None
        );
    }

    #[tokio::test]
    async fn parse_chunk_pair_accepts_any_index_within_usize() {
        // No artificial cap: the natural bound is "fits in the request" because
        // the chunk map and the reassembler walk top out at what the browser
        // could send. Indices are usize, so an attacker-crafted huge index
        // still parses; the reassembler stops at the first gap regardless.
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("__Host-huskarl_session.42=foo"),
            Some((42, "foo".to_owned()))
        );
        assert_eq!(
            store.parse_chunk_pair("__Host-huskarl_session.1000000=foo"),
            Some((1_000_000, "foo".to_owned()))
        );
    }

    // ── reassemble_chunks ─────────────────────────────────────────────────

    #[test]
    fn reassemble_returns_none_when_chunk_zero_missing() {
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(1, "c1".to_owned());
        assert!(reassemble_chunks(&chunks).is_none());
    }

    #[test]
    fn reassemble_concatenates_contiguous_chunks() {
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(0, "c0".to_owned());
        chunks.insert(1, "c1".to_owned());
        chunks.insert(2, "c2".to_owned());
        assert_eq!(reassemble_chunks(&chunks).as_deref(), Some("c0c1c2"));
    }

    #[test]
    fn reassemble_stops_at_first_gap() {
        // Chunks 0, 1 present; 2 missing; 3 present. The reader stops at 2,
        // dropping the orphan chunk 3 (likely a stale leftover from an older
        // larger session). AEAD on the truncated payload will then fail.
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(0, "c0".to_owned());
        chunks.insert(1, "c1".to_owned());
        chunks.insert(3, "stale".to_owned());
        assert_eq!(reassemble_chunks(&chunks).as_deref(), Some("c0c1"));
    }

    #[test]
    fn reassemble_handles_many_chunks() {
        let mut chunks = std::collections::HashMap::new();
        for i in 0..64 {
            chunks.insert(i, format!("c{i}"));
        }
        let out = reassemble_chunks(&chunks).expect("contiguous chunks reassemble");
        assert!(out.starts_with("c0"));
        assert!(out.ends_with("c63"));
    }

    // ── SessionCookieMetrics ──────────────────────────────────────────────

    use std::sync::{Arc, Mutex};

    use crate::metrics::{DecryptResult, SessionCookieMetrics};

    #[derive(Default)]
    struct RecordingMetrics {
        encrypts: Mutex<Vec<Option<String>>>,
        decrypts: Mutex<Vec<(Option<String>, &'static str)>>,
    }

    impl SessionCookieMetrics for RecordingMetrics {
        fn record_decrypt(&self, _: &str, kid: Option<&str>, result: &DecryptResult) {
            self.decrypts
                .lock()
                .unwrap()
                .push((kid.map(str::to_owned), result.as_str()));
        }
        fn record_encrypt(&self, _: &str, kid: Option<&str>) {
            self.encrypts.lock().unwrap().push(kid.map(str::to_owned));
        }
    }

    impl RecordingMetrics {
        fn encrypts(&self) -> Vec<Option<String>> {
            self.encrypts.lock().unwrap().clone()
        }
        fn decrypts(&self) -> Vec<(Option<String>, &'static str)> {
            self.decrypts.lock().unwrap().clone()
        }
    }

    async fn store_with_metrics() -> (CookieSessionStore<CookieSession>, Arc<RecordingMetrics>) {
        let m = Arc::new(RecordingMetrics::default());
        let s = CookieSessionStore::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        (s, m)
    }

    #[tokio::test]
    async fn metrics_save_records_encrypt() {
        let (store, m) = store_with_metrics().await;
        store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![None]);
    }

    #[tokio::test]
    async fn metrics_save_records_kid_when_cipher_has_identity() {
        let m = Arc::new(RecordingMetrics::default());
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![Some("v5".to_owned())]);
    }

    #[tokio::test]
    async fn metrics_load_absent_session_is_silent() {
        let (store, m) = store_with_metrics().await;
        store.load_session(&HeaderMap::new()).await;
        assert!(m.decrypts().is_empty());
    }

    #[tokio::test]
    async fn metrics_load_bad_base64_records_bad_encoding() {
        let (store, m) = store_with_metrics().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=not!!valid!!base64"
                .parse()
                .unwrap(),
        );
        store.load_session(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "bad_encoding")]);
    }

    #[tokio::test]
    async fn metrics_load_tampered_ciphertext_records_decrypt_failed() {
        let (store, m) = store_with_metrics().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
        );
        store.load_session(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "decrypt_failed")]);
    }

    #[tokio::test]
    async fn metrics_load_success_records_ok() {
        let (store, m) = store_with_metrics().await;
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let req = request_cookies_from_set_cookies(&set_cookies);
        store.load_session(&req).await;
        // No kid sidecar (identity-less cipher), so kid=None.
        assert_eq!(m.decrypts(), vec![(None, "ok")]);
    }

    #[tokio::test]
    async fn metrics_load_records_kid_from_sidecar_cookie() {
        let m = Arc::new(RecordingMetrics::default());
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let req = request_cookies_from_set_cookies(&set_cookies);
        store.load_session(&req).await;
        assert_eq!(m.decrypts(), vec![(Some("v5".to_owned()), "ok")]);
    }

    #[tokio::test]
    async fn metrics_load_payload_invalid_when_plaintext_is_not_valid_session() {
        let (store, m) = store_with_metrics().await;
        // Seal garbage bytes under the session AAD — AEAD passes but CBOR
        // deserialization of CookieSession fails, exercising PayloadInvalid.
        let bundle = AeadV1Cipher::new(test_cipher().await)
            .seal(b"not cbor", &store.sealer.aad("session"))
            .await
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&bundle);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("__Host-huskarl_session.0={encoded}")
                .parse()
                .unwrap(),
        );
        store.load_session(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "payload_invalid")]);
    }

    #[tokio::test]
    async fn metrics_load_forged_kid_is_normalized_to_unknown() {
        // The sidecar is client-supplied: a session sealed under "v5" but
        // carrying an attacker-chosen kid must not let that value reach the
        // metrics label. The decrypt still succeeds (kid is a hint, not a
        // filter), but the label collapses to "unknown".
        let m = Arc::new(RecordingMetrics::default());
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let mut req = request_cookies_from_set_cookies(&set_cookies);
        override_kid_cookie(&mut req, &encode_kid("totally-bogus"));
        store.load_session(&req).await;
        assert_eq!(m.decrypts(), vec![(Some("unknown".to_owned()), "ok")]);
    }

    #[tokio::test]
    async fn metrics_load_without_kid_sidecar_records_none_kid() {
        let m = Arc::new(RecordingMetrics::default());
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let set_cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        // Strip the kid sidecar from the simulated request so the unsealer
        // falls back to trial-decrypt and the metric receives kid=None.
        let mut req = HeaderMap::new();
        let pairs: Vec<String> = request_cookies_from_set_cookies(&set_cookies)
            .get_all(http::header::COOKIE)
            .iter()
            .flat_map(|v| {
                v.to_str()
                    .unwrap()
                    .split(';')
                    .map(str::trim)
                    .map(str::to_owned)
            })
            .filter(|p| !p.starts_with("__Host-huskarl_session.kid="))
            .collect();
        if !pairs.is_empty() {
            req.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        store.load_session(&req).await;
        assert_eq!(m.decrypts(), vec![(None, "ok")]);
    }
}
