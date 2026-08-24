//! Browser-held session storage.
//!
//! [`CookieSessionStore`] encrypts the complete application session into
//! AEAD-sealed cookies, split into numbered chunks (`.0`, `.1`, …) when
//! needed. Use [`StoreBackedSessionStore`](crate::StoreBackedSessionStore)
//! instead when sessions are large or require server-side revocation, idle
//! tracking, or atomic concurrent updates.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    completed_login::CompletedLogin,
    config::RoutePath,
    cookie::{CookieName, CookieSealer, DEFAULT_COOKIE_MAX_AGE, decode_payload, encode_payload},
    core::{
        crypto::seal::AeadSealerUnsealer,
        platform::{MaybeSendSync, SystemTime},
        prelude::*,
    },
    enrich::{NoEnrichment, SessionEnricher},
    metrics::DecryptResult,
    session::{
        DriverLoad, InvalidSessionReason, SessionDriver, SessionError, SessionErrorKind,
        SessionPolicy,
    },
    session_state::{Session, SessionState, bounded_time_add},
};

const CHUNK_SIZE: usize = 3800;

/// Default chunk budget for a saved session (see the builder's `max_chunks`).
/// Two chunks ≈ 7.6 KB of cookie data (~5.6 KB of plaintext session), sized
/// against common 8–16 KB request-header limits (nginx and Apache default to
/// 8 KB, Node to 16 KB in total).
const DEFAULT_MAX_CHUNKS: usize = 2;

/// Maximum request-supplied chunk slots cleared in one response beyond the
/// configured budget. This bounds request-to-response header amplification
/// while still removing legacy slots incrementally after `max_chunks` shrinks.
const MAX_OBSERVED_LEGACY_CHUNK_CLEARS: usize = 16;

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
///
/// `Clone` because
/// [`PendingPersist::commit`](crate::engine::PendingPersist::commit) persists
/// from a clone.
pub trait CookiePayload:
    Session + Clone + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static
{
}

impl<T: Session + Clone + Serialize + for<'de> Deserialize<'de> + MaybeSendSync + 'static>
    CookiePayload for T
{
}

/// The default [`CookieSessionStore`] payload: a transparent newtype over
/// [`SessionState`], carrying no claims beyond its `sub`/`sid`.
#[derive(Clone, Serialize, Deserialize)]
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

/// Stores the complete encrypted session in browser cookies.
///
/// The type parameter `C` is the [`CookiePayload`] stored in the cookie,
/// defaulting to [`CookieSession`]. Decryption failure is classified as an
/// invalid presented session so the engine clears its cookies. The `Secure`
/// attribute, the `__Host-`/`__Secure-` prefix, and the `Max-Age` clamp to the
/// session-lifetime cap are stamped on by the engine via
/// [`SessionDriver::apply_session_policy`],
/// not configured here.
///
/// Cookie sessions are stateless: [`SessionDriver::revoke`] is a no-op and
/// [`SessionDriver::clear_session_cookies`] only clears the cooperating
/// browser's cookie (no server-side revocation, no idle timeout); a stolen copy
/// stays valid until the
/// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap elapses. Prefer a
/// bounded lifetime with this store — see [the session
/// model](crate::_docs::explanation::session_model). For revocation, use
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
pub struct CookieSessionStore<C = CookieSession> {
    /// Shared cookie-sealing machinery — see [`CookieSealer`].
    sealer: CookieSealer,
    enricher: Box<dyn SessionEnricher<SessionState, C>>,
    /// Chunk budget enforced on save — see the builder's `max_chunks`.
    max_chunks: usize,
    /// The [`SessionLifetime::Bounded`](crate::SessionLifetime) cap, stamped
    /// by the engine at construction; frozen into each new session's
    /// [`SessionState::expire_at`] at login. `None` until stamped (or when
    /// the lifetime is delegated).
    max_lifetime: Option<Duration>,
}

#[bon::bon]
impl<C> CookieSessionStore<C> {
    /// Creates a new cookie session store. Finish the builder with `build()`
    /// (uses [`NoEnrichment`]; requires `C: From<SessionState>`) or
    /// `build_with_enricher(…)` to attach an async [`SessionEnricher`].
    #[builder(state_mod(name = "cookie_store_builder"), finish_fn(vis = "", name = build_internal))]
    pub fn new(
        #[builder(finish_fn)] enricher: Box<dyn SessionEnricher<SessionState, C>>,
        #[builder(with = |sealer: impl AeadSealerUnsealer + 'static| Arc::new(sealer) as Arc<dyn AeadSealerUnsealer>)]
        sealer: Arc<dyn AeadSealerUnsealer>,
        /// Base name for the session cookie.
        cookie_name: CookieName,
        /// Cookie `Path` scope. Defaults to `/` — which also enables the
        /// strongest `__Host-` cookie prefix; set a narrower path only
        /// deliberately. It must cover the configured logout route, but need
        /// not cover the callback route.
        #[builder(default = RoutePath::root())]
        cookie_path: RoutePath,
        /// Cookie `Max-Age`; defaults to 400 days. The engine clamps it to the
        /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap at
        /// construction, so the browser discards the cookie when the session
        /// can no longer be valid; set it explicitly only to go *shorter*.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Most chunk cookies a saved session may occupy; a save needing more
        /// fails instead of writing. Each chunk holds 3800 bytes of base64
        /// (~2.8 KB of plaintext), so the default of 2 allows ~5.6 KB of
        /// serialized session — sized against common 8–16 KB request-header
        /// limits, past which servers reject requests *before* any code that
        /// could clear the cookies runs, locking the client out for the
        /// cookies' lifetime. Raise this only if every proxy in front of the
        /// app accepts larger request headers; every save also emits one
        /// `Max-Age=0` clear for each unused configured slot, so a larger
        /// budget increases response-header size even for small sessions. If
        /// sessions routinely need more than one chunk, prefer
        /// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
        /// Values below 1 are treated as 1.
        #[builder(default = DEFAULT_MAX_CHUNKS)]
        max_chunks: usize,
    ) -> Self {
        Self {
            sealer: CookieSealer::new(sealer, cookie_name, cookie_path, max_age),
            enricher,
            max_chunks: max_chunks.max(1),
            max_lifetime: None,
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

// -- Internal methods --

impl<C: CookiePayload> CookieSessionStore<C> {
    pub(crate) async fn load_session(&self, headers: &http::HeaderMap) -> DriverLoad<C> {
        let chunks = self.collect_session_chunks(headers);
        if chunks.is_empty() {
            return DriverLoad::Absent;
        }
        let Some(raw_encoded) = reassemble_chunks(&chunks) else {
            return DriverLoad::Invalid(InvalidSessionReason::IncompleteChunks);
        };

        let plaintext = match self
            .sealer
            .unseal_cookie_value(headers, &raw_encoded, "session")
            .await
        {
            Ok(plaintext) => plaintext,
            Err(reason) => return DriverLoad::Invalid(reason),
        };
        if let Ok(session) = decode_payload(&plaintext) {
            self.sealer.record_decrypt(&DecryptResult::Ok);
            DriverLoad::Valid(session)
        } else {
            self.sealer.record_decrypt(&DecryptResult::PayloadInvalid);
            DriverLoad::Invalid(InvalidSessionReason::InvalidPayload)
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
        let payload = encode_payload(session)
            .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))?;
        let aad = self.sealer.aad("session");
        let sealed = self
            .sealer
            .cipher
            .seal(&payload, &aad)
            .await
            .map_err(|e| SessionError::new(SessionErrorKind::Crypto, e))?;
        let cookie_value = URL_SAFE_NO_PAD.encode(&sealed.bundle);
        let chunks = split_into_chunks(&cookie_value);
        let num_chunks = chunks.len();
        // Refuse oversized sessions instead of writing them: past common
        // request-header limits the server rejects every request before the
        // clearing path could run, bricking the client for the cookies'
        // Max-Age. Failing the save surfaces the problem at login instead.
        if num_chunks > self.max_chunks {
            return Err(SessionError::new(
                SessionErrorKind::Encoding,
                SessionTooLarge {
                    encoded_len: cookie_value.len(),
                    chunks: num_chunks,
                    max_chunks: self.max_chunks,
                },
            ));
        }
        // The kid comes back from the seal itself: under a multi-key cipher
        // each seal names exactly the key that sealed this bundle, so the
        // sidecar always matches the ciphertext it accompanies.
        let kid = sealed.kid;
        self.sealer.record_encrypt(kid.as_deref());

        let now = SystemTime::now();
        let configured_deadline = self
            .max_lifetime
            .map(|cap| bounded_time_add(session.created_at(), cap));
        let deadline = match (session.expire_at(), configured_deadline) {
            (Some(frozen), Some(configured)) => Some(frozen.min(configured)),
            (frozen, configured) => frozen.or(configured),
        };
        let attrs = if let Some(deadline) = deadline {
            let remaining = deadline
                .duration_since(now)
                .map_err(|_| SessionError::from(SessionErrorKind::Gone))?;
            if remaining == Duration::ZERO {
                return Err(SessionErrorKind::Gone.into());
            }
            self.sealer.cookie_attrs_with_max_age(remaining)
        } else {
            self.sealer.cookie_attrs()
        };
        let mut headers = Vec::with_capacity(num_chunks + 2);
        for (i, chunk) in chunks.iter().enumerate() {
            headers.push(self.build_chunk_header(i, chunk, &attrs)?);
        }
        self.append_chunk_clears(&mut headers, num_chunks, request_headers);
        headers.push(
            self.sealer
                .build_kid_header_with_attrs(kid.as_deref(), &attrs)?,
        );
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
            .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))
    }

    /// Appends clears for configured chunk slots and a bounded batch of
    /// observed legacy slots at or above `first_index`. Clearing the full
    /// configured tail makes saves deterministic even when responses arrive
    /// out of order; bounding request-controlled extras prevents header
    /// amplification. Remaining legacy slots are cleared on later requests.
    fn append_chunk_clears(
        &self,
        headers: &mut Vec<HeaderValue>,
        first_index: usize,
        request_headers: &http::HeaderMap,
    ) {
        let mut indices = (first_index..self.max_chunks).collect::<std::collections::BTreeSet<_>>();
        let mut legacy_indices = std::collections::BTreeSet::new();
        self.for_each_request_chunk_index(request_headers, |idx| {
            if idx >= first_index && idx >= self.max_chunks {
                legacy_indices.insert(idx);
            }
        });
        indices.extend(
            legacy_indices
                .into_iter()
                .take(MAX_OBSERVED_LEGACY_CHUNK_CLEARS),
        );
        for idx in indices {
            let name = format!("{}.{idx}", self.sealer.cookie_name);
            if let Ok(header) = self.sealer.build_clear_header(&name) {
                headers.push(header);
            }
        }
    }

    pub(crate) fn clear_session_cookie_headers(
        &self,
        request_headers: &http::HeaderMap,
    ) -> Vec<HeaderValue> {
        let mut headers = Vec::new();
        // Clear the kid sidecar unconditionally — cheap and avoids leaving a
        // stale hint that would just degrade the next request to trial-decrypt
        // against a session that no longer exists.
        if let Ok(header) = self.sealer.build_kid_header(None) {
            headers.push(header);
        }
        // Clear every configured slot even when the request route could not see
        // the cookie, plus a bounded batch of legacy slots observed after a
        // max_chunks change.
        self.append_chunk_clears(&mut headers, 0, request_headers);
        headers
    }
}

impl<C: CookiePayload> crate::session::sealed::Sealed for CookieSessionStore<C> {}

impl<C: CookiePayload> SessionDriver for CookieSessionStore<C> {
    type SessionType = C;
    type LoadError = std::convert::Infallible;

    fn apply_session_policy(&mut self, policy: &SessionPolicy) -> Result<(), crate::ConfigError> {
        // Callback visibility is optional for stateless sessions: the callback
        // can set a cookie scoped elsewhere, and there is no old server record
        // to revoke. It only loses the friendly already-authenticated fallback.
        policy.validate_logout_cookie_path(self.sealer.cookie_path())?;
        self.sealer.apply_session_policy(policy);
        // Retained to freeze `SessionState::expire_at` into new sessions.
        self.max_lifetime = policy.max_lifetime();
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        self.sealer.cipher.clone()
    }

    fn clear_session_cookies(&self, headers: &http::HeaderMap) -> Vec<HeaderValue> {
        self.clear_session_cookie_headers(headers)
    }

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> Result<(C, Vec<HeaderValue>), SessionError> {
        let state = SessionState::from_completed(&completed, default_lifetime, self.max_lifetime);
        let session = self.enricher.build_session(state, &completed).await?;
        let cookies = self.save_session(&session, headers).await?;
        Ok((session, cookies))
    }

    async fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<DriverLoad<C>, std::convert::Infallible> {
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
    // recorded. The absolute lifetime bound (from `created_at`) still applies.

    // Cookie sessions have no authoritative server-side state to revoke.
    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke(&self, _session: &C) -> Result<(), SessionError> {
        Ok(())
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
    (i == chunks.len()).then_some(raw_encoded)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use http::HeaderMap;
    use huskarl_crypto_native::aead::AesGcmKey;

    use super::*;
    use crate::{
        ConfigError,
        config::InvalidRoutePath,
        cookie::{InvalidCookieName, encode_kid, get_kid_cookie, unseal_with_kid_fallback},
        core::{crypto::seal::AeadV1Sealer, platform::MaybeSendBoxFuture},
        session_state::SessionState,
        test_support::{
            aes_key_with_kid, request_cookies, test_cipher, test_sealer, test_sealer_with_kid,
            test_session_policy,
        },
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
            .sealer(test_sealer().await)
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

    /// Minimal browser jar for response-order tests: `Set-Cookie` replaces a
    /// name and an empty `Max-Age=0` value removes it. All fixtures use one
    /// origin and path; path visibility is covered separately by policy tests.
    fn apply_to_jar(
        jar: &mut std::collections::BTreeMap<String, String>,
        set_cookies: &[HeaderValue],
    ) {
        for value in set_cookies {
            let raw = value.to_str().unwrap();
            let pair = raw.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            if value.is_empty() && raw.contains("Max-Age=0") {
                jar.remove(name);
            } else {
                jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    fn request_from_jar(jar: &std::collections::BTreeMap<String, String>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if !jar.is_empty() {
            let value = jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.insert(http::header::COOKIE, value.parse().unwrap());
        }
        headers
    }

    #[tokio::test]
    async fn session_policy_allows_callback_outside_path_but_rejects_logout() {
        let mut store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/app".parse().unwrap())
            .build();
        store
            .apply_session_policy(&SessionPolicy::new(
                true,
                None,
                None,
                "/callback".parse().unwrap(),
                None,
            ))
            .unwrap();

        let logout_error = store
            .apply_session_policy(&SessionPolicy::new(
                true,
                None,
                None,
                "/app/callback".parse().unwrap(),
                Some("/logout".parse().unwrap()),
            ))
            .unwrap_err();
        assert!(matches!(
            logout_error,
            ConfigError::InvalidSessionCookiePath {
                route: "logout",
                ..
            }
        ));
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
            .sealer(test_sealer().await)
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
    async fn session_policy_clamps_max_age_to_bounded_lifetime() {
        // The engine stamps the Bounded cap at construction; the default
        // 400-day Max-Age must come down to it so no cookie outlives the
        // session.
        let mut store = test_store().await;
        SessionDriver::apply_session_policy(
            &mut store,
            &test_session_policy(Some(Duration::from_hours(8))),
        )
        .unwrap();
        let cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let chunk0 = cookies[0].to_str().unwrap();
        assert!(
            chunk0.contains(&format!("Max-Age={}", 8 * 3600)),
            "got: {chunk0}"
        );
    }

    #[tokio::test]
    async fn save_uses_remaining_absolute_lifetime_not_the_original_cap() {
        let now = SystemTime::now();
        let created_at = now - Duration::from_hours(2);
        let state = SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(created_at)
            .expire_at(created_at + Duration::from_hours(8))
            .build();
        let mut store = test_store().await;
        store
            .apply_session_policy(&test_session_policy(Some(Duration::from_hours(8))))
            .unwrap();

        let cookies = store
            .save_session(&CookieSession(state), &HeaderMap::new())
            .await
            .unwrap();
        let chunk = cookies[0].to_str().unwrap();
        let max_age = chunk
            .split(';')
            .find_map(|attr| attr.trim().strip_prefix("Max-Age="))
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(
            (6 * 3600 - 1..=6 * 3600).contains(&max_age),
            "remaining Max-Age was {max_age}"
        );
    }

    #[tokio::test]
    async fn session_policy_keeps_shorter_configured_max_age() {
        // The clamp only ever lowers: an explicitly shorter max_age wins.
        let mut store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .max_age(Duration::from_hours(1))
            .build();
        SessionDriver::apply_session_policy(
            &mut store,
            &test_session_policy(Some(Duration::from_hours(8))),
        )
        .unwrap();
        let cookies = store
            .save_session(&CookieSession(test_state()), &HeaderMap::new())
            .await
            .unwrap();
        let chunk0 = cookies[0].to_str().unwrap();
        assert!(chunk0.contains("Max-Age=3600"), "got: {chunk0}");
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
    async fn save_clears_every_unused_configured_slot() {
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
            chunk_clears, 1,
            "the unused configured slot must be cleared even when unseen"
        );
    }

    #[tokio::test]
    async fn save_emits_kid_set_when_cipher_has_identity() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer_with_kid("arn:aws:kms:us-east-1:111:key/abc").await)
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
            .sealer(test_sealer_with_kid("test-kid").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let session = CookieSession(test_state());
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies(&set_cookies);
        // Sanity: the kid sidecar made it into the simulated request.
        assert_eq!(
            get_kid_cookie(&req_headers, "__Host-huskarl_session").as_deref(),
            Some("test-kid")
        );
        let loaded = store.load_session(&req_headers).await;
        assert!(
            matches!(loaded, DriverLoad::Valid(_)),
            "session should load with kid sidecar present"
        );
    }

    #[tokio::test]
    async fn load_falls_back_when_kid_sidecar_is_garbage() {
        // Sidecar present but garbled (not base64url): the helper returns None,
        // and load proceeds with trial-decrypt — which still succeeds because
        // the AEAD bundle authenticates regardless of the hint.
        let store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer_with_kid("test-kid").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let session = CookieSession(test_state());
        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let mut req_headers = request_cookies(&set_cookies);
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
        assert!(matches!(
            store.load_session(&req_headers).await,
            DriverLoad::Valid(_)
        ));
    }

    // ── kid sidecar as hint, not filter ───────────────────────────────────

    use crate::core::crypto::cipher::{AeadDecryptor, MultiKeyCipher, MultiKeyDecryptor};

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
            .sealer(AeadV1Sealer::new(multi_key_cipher().await))
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
        let mut req = request_cookies(&set_cookies);
        // Sanity: the save stamped the real sealing key's identity.
        assert_eq!(
            get_kid_cookie(&req, "__Host-huskarl_session").as_deref(),
            Some("v2")
        );
        override_kid_cookie(&mut req, &encode_kid("v1"));
        assert!(
            matches!(store.load_session(&req).await, DriverLoad::Valid(_)),
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
        let mut req = request_cookies(&set_cookies);
        override_kid_cookie(&mut req, &encode_kid("v9"));
        assert!(
            matches!(store.load_session(&req).await, DriverLoad::Valid(_)),
            "unknown kid hint must fall back to trial-decrypt"
        );
    }

    #[tokio::test]
    async fn load_fallback_does_not_authenticate_foreign_bundles() {
        // Negative control: the fallback widens the key search, not the
        // authenticity gate. A bundle sealed under a key outside the
        // configured set must still fail, whatever the sidecar claims.
        let store = multi_key_store().await;
        let foreign = AeadV1Sealer::new(aes_key_with_kid("v9", 9).await);
        let payload = crate::cookie::encode_payload(&CookieSession(test_state())).unwrap();
        let sealed = foreign
            .seal(&payload, &store.sealer.aad("session"))
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!(
                "__Host-huskarl_session.0={}; __Host-huskarl_session.kid={}",
                URL_SAFE_NO_PAD.encode(&sealed.bundle),
                encode_kid("v1"),
            )
            .parse()
            .unwrap(),
        );
        assert!(matches!(
            store.load_session(&headers).await,
            DriverLoad::Invalid(InvalidSessionReason::DecryptionFailed)
        ));
    }

    #[tokio::test]
    async fn session_value_is_bound_to_its_cookie_name() {
        // F1: the session AAD binds the cookie name, so a value sealed for one
        // cookie context cannot be unsealed by another that shares the AEAD key
        // but uses a different cookie name.
        let sealer: Arc<dyn AeadSealerUnsealer> = Arc::new(AeadV1Sealer::new(test_cipher().await));
        let sealer_a = CookieSealer::new(
            sealer.clone(),
            "app_a".parse().unwrap(),
            "/".parse().unwrap(),
            DEFAULT_COOKIE_MAX_AGE,
        );
        let sealer_b = CookieSealer::new(
            sealer.clone(),
            "app_b".parse().unwrap(),
            "/".parse().unwrap(),
            DEFAULT_COOKIE_MAX_AGE,
        );

        let output = sealer_a
            .cipher
            .seal(b"a session payload", &sealer_a.aad("session"))
            .await
            .unwrap();

        // Same key, different cookie name → the AAD differs, so it must not unseal.
        assert!(
            unseal_with_kid_fallback(
                &sealer_b.cipher,
                None,
                &output.bundle,
                &sealer_b.aad("session")
            )
            .await
            .is_none(),
            "a session sealed for app_a must not unseal under app_b's cookie name"
        );
        // Sanity: it unseals under its own cookie name.
        assert!(
            unseal_with_kid_fallback(
                &sealer_a.cipher,
                None,
                &output.bundle,
                &sealer_a.aad("session")
            )
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
        let req_headers = request_cookies(&set_cookies);
        let loaded = store
            .load_session(&req_headers)
            .await
            .into_valid()
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

    #[tokio::test]
    async fn save_then_load_roundtrips_frozen_expire_at() {
        let store = test_store().await;
        let mut state = test_state();
        let deadline = state.created_at + Duration::from_hours(8);
        state.expire_at = Some(deadline);

        let set_cookies = store
            .save_session(&CookieSession(state), &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies(&set_cookies);
        let loaded = store
            .load_session(&req_headers)
            .await
            .into_valid()
            .expect("session loads");

        let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(loaded.state().expire_at.map(secs), Some(secs(deadline)));
    }

    // ── SessionEnricher / CookiePayload ───────────────────────────────────

    /// An enrichment-built session type: `email` is required, so there is no
    /// `From<SessionState>` and it must be built by an enricher.
    #[derive(Clone, Serialize, Deserialize)]
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

    #[tokio::test]
    async fn concurrent_short_and_long_saves_never_leave_mixed_chunks() {
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .sealer(test_sealer().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .max_chunks(2)
            .build_with_enricher(TestEnricher);
        let short = EnrichedSession {
            state: test_state(),
            email: "short@example.com".to_owned(),
        };
        let long = EnrichedSession {
            state: test_state(),
            email: "x".repeat(3500),
        };
        // Both responses are based on the same one-chunk/empty request, like
        // two concurrent handlers. The short response must nevertheless clear
        // slot .1 so response ordering cannot splice two ciphertexts together.
        let short_headers = store.save_session(&short, &HeaderMap::new()).await.unwrap();
        let long_headers = store.save_session(&long, &HeaderMap::new()).await.unwrap();
        let chunk_sets = |headers: &[HeaderValue]| {
            headers
                .iter()
                .filter(|header| {
                    let value = header.to_str().unwrap();
                    value.starts_with("__Host-huskarl_session.")
                        && !value.starts_with("__Host-huskarl_session.kid=")
                        && !value.contains("Max-Age=0")
                })
                .count()
        };
        assert_eq!(chunk_sets(&short_headers), 1);
        assert_eq!(chunk_sets(&long_headers), 2);

        let mut jar = std::collections::BTreeMap::new();
        apply_to_jar(&mut jar, &long_headers);
        apply_to_jar(&mut jar, &short_headers);
        let loaded = store
            .load_session(&request_from_jar(&jar))
            .await
            .into_valid()
            .expect("long then short leaves the complete short session");
        assert_eq!(loaded.email, short.email);

        let mut jar = std::collections::BTreeMap::new();
        apply_to_jar(&mut jar, &short_headers);
        apply_to_jar(&mut jar, &long_headers);
        let loaded = store
            .load_session(&request_from_jar(&jar))
            .await
            .into_valid()
            .expect("short then long leaves the complete long session");
        assert_eq!(loaded.email, long.email);
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
            .sealer(test_sealer().await)
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
        let req = request_cookies(&set_cookies);
        let loaded = store
            .load_session(&req)
            .await
            .into_valid()
            .expect("session loads");
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
    async fn session_sealer_returns_the_configured_sealer() {
        // The accessor a convenience layer uses to default the login-state
        // sealer: it must hand back the store's configured sealer (identified
        // here by the kid it stamps on a seal), not a re-wrapped or empty one.
        let store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let sealed = SessionDriver::session_sealer(&store)
            .seal(b"probe", b"aad")
            .await
            .unwrap();
        assert_eq!(sealed.kid.as_deref(), Some("v5"));
    }

    /// A completed login carrying an `email` profile claim.
    fn completed_with_email(email: &str) -> CompletedLogin {
        let token_response = crate::client::grant::core::RawTokenResponse::builder()
            // A fixture token value, not a key — `SecretString::new` is the
            // value wrapper, distinct from the `Secret` key-source layer.
            .access_token(crate::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .build()
            .into_token_response(None, SystemTime::now())
            .unwrap();
        let mut claims = crate::client::token::id_token::IdTokenClaims::default();
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
            .sealer(test_sealer().await)
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
        let req = request_cookies(&cookies);
        let loaded = store
            .load_session(&req)
            .await
            .into_valid()
            .expect("session loads");
        assert_eq!(loaded.email, "user@example.com");
    }

    #[tokio::test]
    async fn build_with_claims_error_fails_session_creation() {
        // A claim-mapper that returns Err aborts session creation, propagating
        // the error just like a failed async enricher.
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .sealer(test_sealer().await)
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
            .sealer(test_sealer().await)
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
            matches!(&result, Err(e) if e.kind() == SessionErrorKind::Encoding
                && std::error::Error::source(e)
                    .is_some_and(|s| s.to_string().contains("max_chunks"))),
            "oversized session must fail the save with the budget in the message"
        );
    }

    #[tokio::test]
    async fn save_allows_larger_sessions_when_budget_is_raised() {
        let store = CookieSessionStore::<EnrichedSession>::builder()
            .sealer(test_sealer().await)
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
        let req = request_cookies(&cookies);
        let loaded = store
            .load_session(&req)
            .await
            .into_valid()
            .expect("session loads");
        assert_eq!(loaded.email.len(), 9000);
    }

    #[tokio::test]
    async fn max_chunks_zero_is_treated_as_one() {
        let store = CookieSessionStore::<CookieSession>::builder()
            .sealer(test_sealer().await)
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
    async fn load_is_absent_when_no_cookies() {
        let store = test_store().await;
        assert!(matches!(
            store.load_session(&HeaderMap::new()).await,
            DriverLoad::Absent
        ));
    }

    #[tokio::test]
    async fn load_is_absent_for_unrelated_cookies() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "other=value; another=42".parse().unwrap(),
        );
        assert!(matches!(
            store.load_session(&headers).await,
            DriverLoad::Absent
        ));
    }

    #[tokio::test]
    async fn load_is_invalid_when_continuation_chunk_missing() {
        // Gap between chunks 0 and 2 is session-shaped state that the browser
        // must clear, not an absent session.
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=AAAA; __Host-huskarl_session.2=BBBB"
                .parse()
                .unwrap(),
        );
        assert!(matches!(
            store.load_session(&headers).await,
            DriverLoad::Invalid(InvalidSessionReason::IncompleteChunks)
        ));
    }

    #[tokio::test]
    async fn load_is_invalid_when_decryption_fails() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        // Valid base64 but won't decrypt under the test cipher.
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
        );
        assert!(matches!(
            store.load_session(&headers).await,
            DriverLoad::Invalid(InvalidSessionReason::DecryptionFailed)
        ));
    }

    // ── browser clearing ──────────────────────────────────────────────────

    #[tokio::test]
    async fn clearing_emits_clears_for_every_chunk_slot_the_request_sent() {
        let store = test_store().await;
        let req = request_with_chunk_slots(5);
        let clears = store.clear_session_cookie_headers(&req);
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
    async fn clearing_sweeps_full_configured_budget_without_request_chunks() {
        let store = test_store().await;
        let clears = store.clear_session_cookie_headers(&HeaderMap::new());
        assert_eq!(clears.len(), 3);
        let kid = clears.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("__Host-huskarl_session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(kid, "expected kid sidecar clear");
        for i in 0..2 {
            assert!(clears.iter().any(|c| {
                c.to_str()
                    .unwrap()
                    .starts_with(&format!("__Host-huskarl_session.{i}=;"))
            }));
        }
    }

    #[tokio::test]
    async fn clearing_bounds_request_controlled_legacy_slots() {
        let store = test_store().await;
        let requested = MAX_OBSERVED_LEGACY_CHUNK_CLEARS + 20;
        let req = request_with_chunk_slots(requested);

        let clears = store.clear_session_cookie_headers(&req);

        // Kid sidecar + the two configured slots + one bounded batch of slots
        // beyond the configured budget.
        assert_eq!(
            clears.len(),
            1 + DEFAULT_MAX_CHUNKS + MAX_OBSERVED_LEGACY_CHUNK_CLEARS
        );
        assert!(clears.iter().any(|header| {
            header.to_str().unwrap().starts_with(&format!(
                "__Host-huskarl_session.{}=;",
                DEFAULT_MAX_CHUNKS + MAX_OBSERVED_LEGACY_CHUNK_CLEARS - 1
            ))
        }));
        assert!(!clears.iter().any(|header| {
            header.to_str().unwrap().starts_with(&format!(
                "__Host-huskarl_session.{}=;",
                DEFAULT_MAX_CHUNKS + MAX_OBSERVED_LEGACY_CHUNK_CLEARS
            ))
        }));
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
    fn reassemble_rejects_a_gap() {
        // A gap is presented session state, but not a coherent ciphertext.
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(0, "c0".to_owned());
        chunks.insert(1, "c1".to_owned());
        chunks.insert(3, "stale".to_owned());
        assert!(reassemble_chunks(&chunks).is_none());
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

    // ── Cookie metrics emission ──────────────────────────────────────────

    use crate::test_support::{counter_value, with_metrics};

    /// Counter labels for a session-cookie decrypt with the given outcome. The
    /// decrypt counter carries no kid label (see [`CookieSealer::record_decrypt`]).
    fn decrypt_labels(outcome: &str) -> [(&str, &str); 2] {
        [("cookie", "__Host-huskarl_session"), ("outcome", outcome)]
    }

    async fn plain_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .sealer(test_sealer().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    async fn kid_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::builder()
            .sealer(test_sealer_with_kid("v5").await)
            .cookie_name("huskarl_session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    #[test]
    fn metrics_save_records_encrypt() {
        let ((), counters) = with_metrics(async {
            plain_store()
                .await
                .save_session(&CookieSession(test_state()), &HeaderMap::new())
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.encrypt",
                &[("cookie", "__Host-huskarl_session"), ("kid", "none")],
            ),
            1
        );
    }

    #[test]
    fn metrics_save_records_kid_when_cipher_has_identity() {
        let ((), counters) = with_metrics(async {
            kid_store()
                .await
                .save_session(&CookieSession(test_state()), &HeaderMap::new())
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.encrypt",
                &[("cookie", "__Host-huskarl_session"), ("kid", "v5")],
            ),
            1
        );
    }

    #[test]
    fn metrics_load_absent_session_is_silent() {
        let ((), counters) = with_metrics(async {
            plain_store().await.load_session(&HeaderMap::new()).await;
        });
        assert!(
            !counters
                .iter()
                .any(|(name, _, _)| name == "huskarl.session_cookie.decrypt"),
            "absent cookies must not record a decrypt"
        );
    }

    #[test]
    fn metrics_load_bad_base64_records_bad_encoding() {
        let ((), counters) = with_metrics(async {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                "__Host-huskarl_session.0=not!!valid!!base64"
                    .parse()
                    .unwrap(),
            );
            plain_store().await.load_session(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("bad_encoding"),
            ),
            1
        );
    }

    #[test]
    fn metrics_load_tampered_ciphertext_records_decrypt_failed() {
        let ((), counters) = with_metrics(async {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                "__Host-huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
            );
            plain_store().await.load_session(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("decrypt_failed"),
            ),
            1
        );
    }

    #[test]
    fn metrics_load_success_records_ok() {
        let ((), counters) = with_metrics(async {
            let store = plain_store().await;
            let set_cookies = store
                .save_session(&CookieSession(test_state()), &HeaderMap::new())
                .await
                .unwrap();
            let req = request_cookies(&set_cookies);
            store.load_session(&req).await;
        });
        // No kid sidecar (identity-less cipher), so kid=none.
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("ok"),
            ),
            1
        );
    }

    #[test]
    fn metrics_load_payload_invalid_when_plaintext_is_not_valid_session() {
        let ((), counters) = with_metrics(async {
            let store = plain_store().await;
            // Seal garbage bytes under the session AAD — AEAD passes but CBOR
            // deserialization of CookieSession fails, exercising PayloadInvalid.
            let sealed = AeadV1Sealer::new(test_cipher().await)
                .seal(b"not cbor", &store.sealer.aad("session"))
                .await
                .unwrap();
            let encoded = URL_SAFE_NO_PAD.encode(&sealed.bundle);
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                format!("__Host-huskarl_session.0={encoded}")
                    .parse()
                    .unwrap(),
            );
            store.load_session(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("payload_invalid"),
            ),
            1
        );
    }
}
