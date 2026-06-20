#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Shared login core for huskarl framework integrations.
//!
//! This crate contains the framework-agnostic login logic shared by
//! `huskarl-axum` and `huskarl-pingora`: configuration, session drivers,
//! session enrichment, cookie helpers, URL helpers, and session store traits.
//! The OAuth flow itself is driven by a
//! [`huskarl::grant::authorization_code::AuthorizationCodeGrant`], passed
//! directly to the [`engine::LoginEngine`].
//!
//! # Session model
//!
//! Session creation follows one model regardless of where sessions live: the
//! framework prepares a *seed* ([`SessionState`], plus the session key for
//! store-backed sessions), a [`SessionEnricher`] builds the application's
//! session type from the seed and the [`CompletedLogin`] (mapping ID token
//! claims, calling the OIDC `UserInfo` endpoint, …), and the chosen backend
//! stores it:
//!
//! - [`CookieSessionStore`] seals the session into chunked, AEAD-encrypted
//!   browser cookies — no server-side storage.
//! - [`StoreBackedSessionStore`] keeps an encrypted pointer cookie and
//!   persists the session via an [`ExternalSessionStore`] (Redis, a
//!   database, …).
//!
//! The default enricher, [`NoEnrichment`], converts the seed straight into
//! the session type via `From`; pass a custom one to the store builders'
//! `build_with_enricher` finisher.
//!
//! The canonical [`SessionDriver`] interface returns `Vec<HeaderValue>` from
//! mutating methods (`save`, `touch`, `delete`). Framework crates that need a
//! different interface (e.g. Pingora's `&mut ResponseHeader`) adapt with a
//! small helper that appends the returned headers.
//!
//! # Platform support
//!
//! Trait bounds use `huskarl::core::platform`'s `MaybeSend` / `MaybeSendSync`
//! markers rather than bare `Send` / `Sync`: on native targets they are
//! equivalent to `Send + Sync`, while on `wasm32` (assumed single-threaded)
//! the requirement disappears. Time and sleeping likewise go through
//! `huskarl::core::platform`, so the crate compiles for
//! `wasm32-unknown-unknown` and WASI targets.

pub mod cookie;
pub mod engine;
pub mod liveness;
pub mod metrics;
pub mod session;
pub mod url;

mod completed_login;
mod config;
mod cookie_session;
mod enrich;
mod error_page;
mod session_state;
mod store_session;

#[cfg(test)]
mod test_support;

pub use completed_login::CompletedLogin;
pub use config::{
    ActivityPolicy, ConfigError, InvalidRoutePath, LoginConfig, LogoutConfig, RoutePath,
};
pub use cookie::{CookieName, InvalidCookieName};
pub use cookie_session::{
    CookiePayload, CookieSession, CookieSessionStore, CookieSessionStoreBuilder,
};
pub use engine::{DefaultPersistFailurePolicy, PersistFailurePolicy, TeardownReason};
pub use enrich::{NoEnrichment, SessionEnricher};
pub use error_page::{DefaultErrorPage, ErrorPage, ErrorPageResponse};
pub use huskarl::core::EndpointUrl;
pub use liveness::{LivenessConfig, LivenessStore, LivenessVerdict};
pub use metrics::{
    DecryptResult, LoginCompleteResult, LoginEngineMetrics, LoginStartResult, RefreshResult,
    SessionCookieMetrics, normalize_as_error,
};
pub use session::{SessionDriver, SessionError, SessionErrorKind};
pub use session_state::{Session, SessionState};
pub use store_session::{
    ExternalSessionStore, PersistedSession, PersistedSessionState, SaveOutcome, SessionNotFound,
    StoreBackedSessionStore, StoreBackedSessionStoreBuilder, VersionConflict,
};
