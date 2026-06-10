//! Cookie-based session storage.
//!
//! [`CookieSessionStore`] encrypts the entire session into chunked browser
//! cookies using AEAD, so no server-side session store is needed. Large
//! payloads are automatically split across multiple cookies (`.0`, `.1`, ...)
//! to stay within browser size limits.

use std::{borrow::Cow, marker::PhantomData, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::core::{
    crypto::cipher::{
        AeadEncryptor, AeadSealer, AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher, CipherMatch,
    },
    platform::MaybeSendSync,
};
use serde::{Deserialize, Serialize};

use crate::{
    cookie::{
        DEFAULT_COOKIE_MAX_AGE, cookie_attrs, decode_payload, encode_kid, encode_payload,
        get_kid_cookie, kid_cookie_name, unseal_with_kid_fallback,
    },
    enrich::{NoEnrichment, SessionEnricher},
    grant::CompletedLogin,
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionDriver, SessionError, to_session_err},
    session_state::{Session, SessionState},
};

const CHUNK_SIZE: usize = 3800;

/// Bound alias for any type that can be sealed into (and unsealed from) the
/// session cookie: a [`Session`] that round-trips through serde.
///
/// Blanket-implemented — never implement it directly. Define a custom payload
/// type to store only the fields your application needs in the browser cookie
/// rather than the full [`SessionState`], and build it with a
/// [`SessionEnricher`] (attached via [`CookieSessionStore::with_enricher`]) —
/// see [`SessionEnricher`] for claim-mapping and `UserInfo` examples.
///
/// # Storing the `id_token` for RP-initiated logout
///
/// If your `IdP` supports RP-initiated logout and you want clean logout UX
/// (no OP confirmation page), store the `id_token` in your custom type and
/// override [`Session::id_token`]:
///
/// ```ignore
/// impl Session for MySession {
///     fn id_token(&self) -> Option<&IdToken> { self.id_token.as_ref() }
///     // ...other methods
/// }
/// ```
///
/// # Updating custom fields on token refresh
///
/// If any of your custom fields come from a refresh response, override
/// [`Session::apply_refresh`] to update them alongside the [`SessionState`]:
///
/// ```ignore
/// fn apply_refresh(&mut self, token_response: &TokenResponse) {
///     let new_state = self.state().refreshed(token_response);
///     self.set_state(new_state);
///     // update your own fields from token_response here
/// }
/// ```
pub trait CookiePayload:
    Session + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static
{
}

impl<T: Session + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static> CookiePayload
    for T
{
}

/// A session that stores token state encrypted in browser cookies.
///
/// This is the default session type used with [`CookieSessionStore`]. It is a
/// transparent newtype over [`SessionState`], so existing encrypted cookies
/// deserialize correctly.
///
/// It carries no ID token claims beyond the `sub`/`sid` baked into
/// [`SessionState`]. For a payload with user info (or a smaller one), define
/// a custom type and build it with a [`SessionEnricher`].
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
/// Large payloads are automatically split across multiple cookies (`.0`, `.1`,
/// etc.) to stay within browser cookie size limits. Decryption failure is
/// treated as "no session" rather than an error.
///
/// The type parameter `C` controls what is stored in the cookie. The default
/// is [`CookieSession`], which stores the full [`SessionState`]. For a custom
/// payload, supply any [`CookiePayload`] type.
///
/// The type parameter `F` is the [`SessionEnricher`] that builds the session
/// payload after a completed login. The default, [`NoEnrichment`], converts
/// the [`SessionState`] seed via `From`; attach a custom enricher (e.g. one
/// that maps ID token claims or calls the OIDC `UserInfo` endpoint) with
/// [`with_enricher`](Self::with_enricher).
///
/// # Cookie format
///
/// - Cookie name: `{name}.0`, `{name}.1`, etc.
/// - Chunk value: raw base64 of the sealed payload, split across chunks
/// - Attributes: `HttpOnly; SameSite=Lax; Path={path}` plus optional `Secure`
///
/// On read, chunks are concatenated by walking `{name}.0`, `{name}.1`, … until
/// an index is missing. Truncation or stale leftover chunks just produce a
/// payload the AEAD layer can't authenticate, which surfaces as "no session"
/// and triggers a fresh login.
pub struct CookieSessionStore<C = CookieSession, F = NoEnrichment> {
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
    max_age: Duration,
    metrics: Option<Arc<dyn SessionCookieMetrics>>,
    enricher: F,
    _phantom: PhantomData<C>,
}

#[bon::bon]
impl<C> CookieSessionStore<C> {
    /// Creates a new cookie session store (with [`NoEnrichment`] — chain
    /// [`with_enricher`](Self::with_enricher) on the built store to attach an
    /// async [`SessionEnricher`]).
    #[builder]
    pub fn new(
        cipher: BoxedAeadCipher,
        #[builder(into)] cookie_name: String,
        secure: bool,
        #[builder(into)] cookie_path: String,
        /// Defaults to 400 days — finite but generous enough that the cookie
        /// never expires before the server-side session does. If `max_lifetime`
        /// is configured in `LoginConfig`, pass it here so the browser discards
        /// the cookie around the time the session can no longer be valid.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Optional metrics observer for encrypt/decrypt events.
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        Self {
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            cookie_name,
            secure,
            cookie_path,
            max_age,
            metrics,
            enricher: NoEnrichment,
            _phantom: PhantomData,
        }
    }
}

impl<C, F> CookieSessionStore<C, F> {
    /// Replaces the session enricher, e.g. with one that calls the OIDC
    /// `UserInfo` endpoint after login. See [`SessionEnricher`] for an example.
    pub fn with_enricher<F2: SessionEnricher<SessionState, C>>(
        self,
        enricher: F2,
    ) -> CookieSessionStore<C, F2> {
        CookieSessionStore {
            sealer: self.sealer,
            unsealer: self.unsealer,
            cookie_name: self.cookie_name,
            secure: self.secure,
            cookie_path: self.cookie_path,
            max_age: self.max_age,
            metrics: self.metrics,
            enricher,
            _phantom: PhantomData,
        }
    }

    /// Returns the active sealer's key ID, if the key has an identity.
    ///
    /// Delegates to [`AeadEncryptor::key_id`]. Once reload support is added to
    /// `AeadCipher`, this will reflect the key that will be used for the
    /// **next** seal operation — suitable for updating an active-key gauge from
    /// a reload callback.
    #[must_use]
    pub fn key_id(&self) -> Option<Cow<'_, str>> {
        self.sealer.key_id()
    }

    fn base_cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, &self.cookie_path)
    }

    fn cookie_attrs(&self) -> String {
        format!(
            "{}; Max-Age={}",
            self.base_cookie_attrs(),
            self.max_age.as_secs()
        )
    }
}

// -- Internal methods --

impl<C: CookiePayload, F> CookieSessionStore<C, F> {
    pub(crate) async fn load_session(&self, headers: &http::HeaderMap) -> Option<C> {
        let chunks = self.collect_session_chunks(headers);
        let raw_encoded = reassemble_chunks(&chunks)?;

        // A session-cookie-shaped value is present — record the outcome.
        let kid = get_kid_cookie(headers, &self.cookie_name);

        let Ok(bundle) = URL_SAFE_NO_PAD.decode(&raw_encoded) else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::BadEncoding);
            return None;
        };
        let cipher_match = kid
            .as_deref()
            .map(|k| CipherMatch::builder().kid(k).build());
        let Some(plaintext) =
            unseal_with_kid_fallback(&self.unsealer, cipher_match.as_ref(), &bundle, b"session")
                .await
        else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::DecryptFailed);
            return None;
        };
        if let Ok(session) = decode_payload(&plaintext) {
            self.record_decrypt(kid.as_deref(), &DecryptResult::Ok);
            Some(session)
        } else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::PayloadInvalid);
            None
        }
    }

    fn record_decrypt(&self, kid: Option<&str>, result: &DecryptResult) {
        if let Some(m) = &self.metrics {
            m.record_decrypt(&self.cookie_name, kid, result);
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

    /// Parses a single `name=value` cookie pair as a chunk if `name` matches
    /// `{cookie_name}.N` for some non-negative integer `N`. The full
    /// `(index, value)` form is what `load_session` needs to reassemble.
    fn parse_chunk_pair(&self, pair: &str) -> Option<(usize, String)> {
        let (k, v) = pair.trim().split_once('=')?;
        Some((self.parse_chunk_index(k)?, v.trim().to_owned()))
    }

    /// Parses just the chunk index from a cookie name. Used by the clear-path,
    /// which needs to know which `{name}.N` slots the browser currently has
    /// but doesn't care about their values.
    fn parse_chunk_index(&self, name: &str) -> Option<usize> {
        let suffix = name.trim().strip_prefix(&self.cookie_name)?;
        suffix.strip_prefix('.')?.parse::<usize>().ok()
    }

    /// Invokes `f` once with each `{cookie_name}.N` index the browser sent on
    /// this request. The callback shape avoids materializing a `Vec<usize>`
    /// when the only reason for enumerating is to emit one `Set-Cookie` per
    /// match — and we only ever enumerate on a save/touch/delete path that's
    /// already emitting cookies, so this is the one walk per write.
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
        let payload = encode_payload(session)?;
        let bundle = self
            .sealer
            .seal(&payload, b"session")
            .await
            .map_err(to_session_err)?;
        // Read the active key's identity from the same sealer that just sealed
        // the bundle. For `AeadV1Sealer<BoxedAeadCipher>` the cipher is fixed
        // at construction so this is stable; if huskarl-login ever switches to
        // a multi-key sealer that picks per-call, this should move to a
        // select-then-use pattern via `AeadCipherSelector`.
        let kid = self.sealer.key_id();
        if let Some(m) = &self.metrics {
            m.record_encrypt(&self.cookie_name, kid.as_deref());
        }
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let chunks = split_into_chunks(&cookie_value);
        let num_chunks = chunks.len();

        let attrs = self.cookie_attrs();
        let mut headers = Vec::with_capacity(num_chunks + 2);
        for (i, chunk) in chunks.iter().enumerate() {
            headers.push(self.build_chunk_header(i, chunk, &attrs)?);
        }
        self.append_clears_for_leftover_chunks(&mut headers, num_chunks, request_headers);
        headers.push(self.build_kid_header(kid.as_deref())?);
        Ok(headers)
    }

    /// Builds the `Set-Cookie` header for chunk `i`. All chunks carry the raw
    /// base64 payload — chunk count is implied by the presence of `{name}.0`,
    /// `{name}.1`, … in the request and inferred by the reader.
    fn build_chunk_header(
        &self,
        i: usize,
        chunk: &str,
        attrs: &str,
    ) -> Result<HeaderValue, SessionError> {
        HeaderValue::from_str(&format!("{}.{i}={chunk}; {attrs}", self.cookie_name))
            .map_err(to_session_err)
    }

    /// Builds the `Set-Cookie` header for the kid sidecar. When `kid` is
    /// `Some`, the value is the base64url-encoded identity; when `None`, a
    /// `Max-Age=0` clear is emitted so that a sidecar set under a previous
    /// (identity-bearing) key doesn't linger after operators switch to a key
    /// source with no natural identity.
    fn build_kid_header(&self, kid: Option<&str>) -> Result<HeaderValue, SessionError> {
        let name = kid_cookie_name(&self.cookie_name);
        let value = match kid {
            Some(k) => format!("{name}={}; {}", encode_kid(k), self.cookie_attrs()),
            None => format!("{name}=; {}; Max-Age=0", self.base_cookie_attrs()),
        };
        HeaderValue::from_str(&value).map_err(to_session_err)
    }

    /// Appends `Max-Age=0` clears for every chunk slot the browser sent that
    /// the current save is not going to overwrite (indices `>= num_chunks`).
    /// Reads the request rather than walking a fixed range, so there is no
    /// chunk-count cap to grow over time and no orphaned slots after a shrink.
    fn append_clears_for_leftover_chunks(
        &self,
        headers: &mut Vec<HeaderValue>,
        num_chunks: usize,
        request_headers: &http::HeaderMap,
    ) {
        let clear_attrs = format!("{}; Max-Age=0", self.base_cookie_attrs());
        let cookie_name = &self.cookie_name;
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
        let clear_attrs = format!("{}; Max-Age=0", self.base_cookie_attrs());
        let cookie_name = &self.cookie_name;
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

impl<C: CookiePayload, F: SessionEnricher<SessionState, C>> crate::session::sealed::Sealed
    for CookieSessionStore<C, F>
{
}

impl<C: CookiePayload, F: SessionEnricher<SessionState, C>> SessionDriver
    for CookieSessionStore<C, F>
{
    type SessionType = C;
    type LoadError = std::convert::Infallible;

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> Result<(C, Vec<HeaderValue>), SessionError> {
        let state = SessionState::from_completed(&completed, default_lifetime);
        let session = self
            .enricher
            .build_session(state, &completed)
            .await
            .map_err(to_session_err)?;
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

    /// Re-emits the chunked session cookies so that the updated `last_active`
    /// timestamp reaches the browser. Cookie sessions have no server-side TTL,
    /// so a touch is implemented as a full re-save.
    ///
    /// This means every `Touch` pays the cost of an AEAD seal + emitting the
    /// session-cookie chunks on the response. Pair with a non-zero
    /// [`touch_min_interval`](crate::LoginConfig::touch_min_interval) (e.g. a
    /// fraction of [`idle_timeout`](crate::LoginConfig::idle_timeout)) so this
    /// only fires periodically instead of on every authenticated request.
    async fn touch(
        &self,
        session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session, headers).await
    }

    async fn delete(
        &self,
        _session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        Ok(self.delete_headers(headers))
    }
}

/// Splits the encoded session string into [`CHUNK_SIZE`]-byte slices. The
/// input is URL-safe base64 (ASCII), so byte chunks are valid UTF-8.
fn split_into_chunks(cookie_value: &str) -> Vec<&str> {
    cookie_value
        .as_bytes()
        .chunks(CHUNK_SIZE)
        .map(|c| std::str::from_utf8(c).expect("base64 output is ASCII"))
        .collect()
}

/// Reassembles the chunked session payload by concatenating `{name}.0`,
/// `{name}.1`, … until a gap is found. Returns `None` if chunk 0 is absent.
/// Truncation, gaps, and stale leftover chunks all produce a payload the AEAD
/// layer can't authenticate — caller treats that as "no session" and the user
/// re-logs in.
///
/// The loop is bounded by the size of the request (the chunk map only contains
/// what the browser actually sent), which is in turn bounded by the HTTP layer's
/// request-size limit.
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
    use std::{
        convert::Infallible,
        time::{Duration, SystemTime},
    };

    use http::HeaderMap;
    use huskarl::core::secrets::{Secret, SecretBytes, SecretOutput};
    use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

    use super::*;
    use crate::session_state::SessionState;

    // ── Cipher / fixtures ─────────────────────────────────────────────────

    #[derive(Clone)]
    struct TestSecret(SecretBytes);
    impl Secret for TestSecret {
        type Output = SecretBytes;
        type Error = Infallible;
        async fn get_secret_value(&self) -> Result<SecretOutput<SecretBytes>, Infallible> {
            Ok(SecretOutput {
                value: self.0.clone(),
                identity: None,
            })
        }
    }

    async fn test_cipher() -> BoxedAeadCipher {
        let key = AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![0u8; 32])),
            |_| None,
        )
        .await
        .unwrap();
        BoxedAeadCipher::new(key)
    }

    fn test_state() -> SessionState {
        let now = SystemTime::now();
        SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(now)
            .last_active(now)
            .build()
    }

    async fn test_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
            .build()
    }

    /// A cipher whose `key_id()` reports a fixed identity, used to exercise
    /// the kid-sidecar set path on save and the `CipherMatch` path on load.
    async fn test_cipher_with_kid(kid: &str) -> BoxedAeadCipher {
        let kid_owned = kid.to_owned();
        let key = AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![0u8; 32])),
            move |_| Some(kid_owned.clone()),
        )
        .await
        .unwrap();
        BoxedAeadCipher::new(key)
    }

    /// Builds a `Cookie:` header from the `Set-Cookie` values a save produced,
    /// stripping cookie attributes so it looks like an actual request cookie
    /// header sent by the browser.
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
    /// Used to exercise the clear-leftover-chunks path on save without going
    /// through a real round-trip.
    fn request_with_chunk_slots(n: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if n > 0 {
            let pairs: Vec<String> = (0..n).map(|i| format!("huskarl_session.{i}=x")).collect();
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
        assert!(chunk0.starts_with("huskarl_session.0="), "got: {chunk0}");
        let value = chunk0.split('=').nth(1).unwrap().split(';').next().unwrap();
        // URL-safe base64 has no ':' — chunk 0 is now raw payload, no prefix.
        assert!(
            !value.contains(':'),
            "chunk 0 must not carry a delimiter prefix: {value}"
        );
        assert!(!value.is_empty(), "chunk 0 must carry payload data");
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
                // Exclude the kid sidecar: it lives under `huskarl_session.kid`
                // and is always emitted (as a set or clear) on save, but it's
                // not a chunk.
                s.contains("huskarl_session.")
                    && !s.starts_with("huskarl_session.kid=")
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
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
            .build();
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let expected_value = URL_SAFE_NO_PAD.encode("arn:aws:kms:us-east-1:111:key/abc".as_bytes());
        let kid_set = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with(&format!("huskarl_session.kid={expected_value};"))
        });
        assert!(kid_set, "expected kid sidecar set to base64url(identity)");
    }

    #[tokio::test]
    async fn save_then_load_roundtrips_with_kid_sidecar() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("test-kid").await)
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
            .build();
        let session = CookieSession(test_state());
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies_from_set_cookies(&set_cookies);
        // Sanity: the kid sidecar made it into the simulated request.
        assert_eq!(
            get_kid_cookie(&req_headers, "huskarl_session").as_deref(),
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
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
            .filter(|p| !p.starts_with("huskarl_session.kid="))
            .collect();
        let combined = format!("{}; huskarl_session.kid=!!!", stripped.join("; "));
        req_headers.insert(http::header::COOKIE, combined.parse().unwrap());
        assert!(store.load_session(&req_headers).await.is_some());
    }

    // ── kid sidecar as hint, not filter ───────────────────────────────────

    use huskarl::core::crypto::cipher::{BoxedAeadDecryptor, MultiKeyCipher, MultiKeyDecryptor};

    /// An AES-256 key with a stable identity, deterministic in `byte` so the
    /// "same" key can be constructed twice (e.g. once for a decryptor set and
    /// once as the encryptor).
    async fn aes_key_with_kid(kid: &str, byte: u8) -> huskarl_crypto_native::aead::AesGcmKey {
        let kid_owned = kid.to_owned();
        AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![byte; 32])),
            move |_| Some(kid_owned.clone()),
        )
        .await
        .unwrap()
    }

    /// A rotation-shaped cipher: seals under "v2", unseals under {"v1", "v2"}.
    /// Unlike the single-key test ciphers (which ignore the `CipherMatch`
    /// hint entirely), the multi-key decryptor takes an exact-kid match as
    /// definitive and reports "no matching key" for unknown kids — the shape
    /// that makes a wrong sidecar hint actually bite.
    async fn multi_key_cipher() -> BoxedAeadCipher {
        let decryptor = MultiKeyDecryptor::new(vec![
            BoxedAeadDecryptor::new(aes_key_with_kid("v1", 1).await),
            BoxedAeadDecryptor::new(aes_key_with_kid("v2", 2).await),
        ]);
        BoxedAeadCipher::new(MultiKeyCipher::new(
            aes_key_with_kid("v2", 2).await,
            decryptor,
        ))
    }

    async fn multi_key_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .cipher(multi_key_cipher().await)
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
            .filter(|p| !p.starts_with("huskarl_session.kid="))
            .map(str::to_owned)
            .collect();
        pairs.push(format!("huskarl_session.kid={value}"));
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
            get_kid_cookie(&req, "huskarl_session").as_deref(),
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
        let foreign = AeadV1Sealer::new(BoxedAeadCipher::new(aes_key_with_kid("v9", 9).await));
        let payload = crate::cookie::encode_payload(&CookieSession(test_state())).unwrap();
        let bundle = foreign.seal(&payload, b"session").await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!(
                "huskarl_session.0={}; huskarl_session.kid={}",
                URL_SAFE_NO_PAD.encode(&bundle),
                encode_kid("v1"),
            )
            .parse()
            .unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
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
            s.starts_with("huskarl_session.kid=;") && s.contains("Max-Age=0")
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
                s.starts_with(&format!("huskarl_session.{stale}=;")) && s.contains("Max-Age=0")
            });
            assert!(cleared, "expected clear for stale slot .{stale}");
        }
        // Slot .0 is being overwritten with data, not cleared.
        let zero_clear = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("huskarl_session.0=;") && s.contains("Max-Age=0")
        });
        assert!(
            !zero_clear,
            "slot .0 must not be cleared — it's overwritten with new data",
        );
    }

    // ── Save / load roundtrip ─────────────────────────────────────────────

    /// Sanity-check that the CBOR payload is meaningfully smaller than the
    /// equivalent JSON payload. Cookies are sent on every authenticated
    /// request, so this directly affects bandwidth.
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
        assert_eq!(
            secs(loaded.state().last_active),
            secs(original_state.last_active)
        );
    }

    // ── SessionEnricher / CookiePayload ───────────────────────────────────

    /// An enrichment-built session type: `email` is *required*, so the type
    /// can't be built from the seed alone (no `From<SessionState>`). It
    /// implements only `Session` + serde (`CookiePayload` is
    /// blanket-implemented) and is constructed by an enricher.
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

    /// Stands in for an enricher that owns its own clients (e.g. a
    /// `UserInfoClient`) and awaits them while building the session.
    struct TestEnricher;

    impl SessionEnricher<SessionState, EnrichedSession> for TestEnricher {
        type Error = Infallible;

        async fn build_session(
            &self,
            state: SessionState,
            _completed: &CompletedLogin,
        ) -> Result<EnrichedSession, Infallible> {
            Ok(EnrichedSession {
                state,
                email: "user@example.com".to_owned(),
            })
        }
    }

    fn assert_session_driver<T: SessionDriver>(_: &T) {}

    #[tokio::test]
    async fn enriched_store_roundtrips_enrichment_only_payload() {
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .cipher(test_cipher().await)
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
            .build()
            .with_enricher(TestEnricher);
        // The enriched store still satisfies SessionDriver, so the engine can
        // drive it. (Without the enricher it would not: EnrichedSession has no
        // From<SessionState>, so NoEnrichment can't build it.)
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
        // Regression guard: adding the enricher type parameter must not cost
        // the plain (NoEnrichment) store its SessionDriver impl.
        let store = test_store().await;
        assert_session_driver(&store);
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
            "huskarl_session.0=AAAA; huskarl_session.2=BBBB"
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
            "huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
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
                s.starts_with(&format!("huskarl_session.{i}=;"))
            });
            assert!(found, "expected clear for slot .{i}");
        }
        let kid_cleared = clears.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("huskarl_session.kid=;")
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
            s.starts_with("huskarl_session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(kid, "expected kid sidecar clear");
    }

    // ── parse_chunk_pair ──────────────────────────────────────────────────

    #[tokio::test]
    async fn parse_chunk_pair_matches_indexed_cookie() {
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.3=abc"),
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
        // "huskarl_session=foo" — missing `.N` suffix.
        assert_eq!(store.parse_chunk_pair("huskarl_session=foo"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_non_numeric_suffix() {
        let store = test_store().await;
        assert_eq!(store.parse_chunk_pair("huskarl_session.abc=foo"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_accepts_any_index_within_usize() {
        // No artificial cap: the natural bound is "fits in the request" because
        // the chunk map and the reassembler walk top out at what the browser
        // could send. Indices are usize, so an attacker-crafted huge index
        // still parses; the reassembler stops at the first gap regardless.
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.42=foo"),
            Some((42, "foo".to_owned()))
        );
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.1000000=foo"),
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
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
            "huskarl_session.0=not!!valid!!base64".parse().unwrap(),
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
            "huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
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
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
        let bundle = AeadV1Sealer::new(test_cipher().await)
            .seal(b"not cbor", b"session")
            .await
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&bundle);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("huskarl_session.0={encoded}").parse().unwrap(),
        );
        store.load_session(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "payload_invalid")]);
    }

    #[tokio::test]
    async fn metrics_load_without_kid_sidecar_records_none_kid() {
        let m = Arc::new(RecordingMetrics::default());
        let store = CookieSessionStore::<CookieSession>::builder()
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("huskarl_session")
            .secure(true)
            .cookie_path("/")
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
            .filter(|p| !p.starts_with("huskarl_session.kid="))
            .collect();
        if !pairs.is_empty() {
            req.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        store.load_session(&req).await;
        assert_eq!(m.decrypts(), vec![(None, "ok")]);
    }
}
