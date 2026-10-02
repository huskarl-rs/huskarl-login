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
/// session-lifetime cap are applied by the engine through
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
///
/// # Example
///
/// Supply a sealer backed by your configured key. The default payload retains
/// token and timing state plus `sub`/`sid`; use
/// [an application session](crate::_docs::how_to::enrichment) to retain other claims.
///
/// ```
/// use huskarl_login::{
///     CookieSessionStore, InvalidCookieName, core::crypto::seal::AeadSealerUnsealer,
/// };
///
/// fn session_store(
///     sealer: impl AeadSealerUnsealer + 'static,
/// ) -> Result<CookieSessionStore, InvalidCookieName> {
///     Ok(CookieSessionStore::builder()
///         .sealer(sealer)
///         .cookie_name("session".parse()?)
///         .build())
/// }
/// ```
///
/// Pass the resulting store to [`LoginEngine::builder`](crate::engine::LoginEngine::builder).
/// See [Rotate cookie encryption keys](crate::_docs::how_to::cookie_keys) for
/// a sealer that can read cookies across key changes.
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
    #[builder(finish_fn(vis = "", name = build_internal))]
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
            sealer: CookieSealer::builder()
                .sealer(sealer)
                .cookie_name(cookie_name)
                .cookie_path(cookie_path)
                .max_age(max_age)
                .build(),
            enricher,
            max_chunks: max_chunks.max(1),
            max_lifetime: None,
        }
    }
}

impl<C, S: cookie_session_store_builder::IsComplete> CookieSessionStoreBuilder<C, S> {
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

    fn strip_session_credentials(&self, headers: &mut http::HeaderMap) {
        let kid_name = crate::cookie::kid_cookie_name(&self.sealer.cookie_name);
        crate::cookie::strip_cookies(headers, |name| {
            name == kid_name || self.parse_chunk_index(name).is_some()
        });
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

    async fn load(&self, headers: &http::HeaderMap) -> Result<DriverLoad<C>, SessionError> {
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
mod tests;
