#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Tests legitimately unwrap/expect/panic; the denies above guard library code only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs_huskarl_login, feature(doc_cfg))]

//! Framework-neutral OAuth 2.0 and `OpenID` Connect login for Rust services.
//!
//! `huskarl-login` is the underlying engine used by
//! [`huskarl-axum`](https://docs.rs/huskarl-axum/latest/huskarl_axum/) and
//! [`huskarl-pingora`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/).
//! Start with your adapter's documentation to add login to an application or
//! proxy. Use this crate's docs to customize sessions and storage, understand
//! shared behavior, or integrate the engine with another framework.
//!
//! Integrators can start with [Build a login engine](_docs::tutorial::getting_started),
//! then [Build a framework adapter](_docs::how_to::adapter). The central type,
//! [`engine::LoginEngine`], starts and completes the Authorization Code flow,
//! validates and refreshes sessions, and handles logout. The adapter decides
//! which routes require authentication and delivers the engine's responses
//! and cookie updates.
//!
//! # Mental model
//!
//! A successful callback produces a [`CompletedLogin`]. A [`SessionEnricher`]
//! combines it with framework-managed state to build the application's
//! [`Session`]. A session driver then persists that value:
//!
//! ```text
//! authorization code ─▶ CompletedLogin ─┐
//!                                       ├─▶ SessionEnricher ─▶ Session ─▶ store
//!                      managed state ───┘
//! ```
//!
//! Choose [`CookieSessionStore`] to keep the encrypted session in the browser.
//! Choose [`StoreBackedSessionStore`] to keep only an encrypted lookup key in
//! the browser and store the session through an [`ExternalSessionStore`].
//! With fully stateless cookie sessions, logout clears the browser's cookies but
//! cannot selectively invalidate copied cookies that are still valid. Delayed
//! responses can also reinstall older session cookies. Use store-backed sessions
//! when you need server-enforced revocation and protection against stale updates.
//!
//! # Documentation
//!
//! | You want to | Start here |
//! | --- | --- |
//! | Understand sessions, refresh, and lifetime policy | [Explanations](_docs::explanation) |
//! | Add claims or application data to a session | [Build an application session](_docs::how_to::enrichment) |
//! | Use a database or other session backend | [Implement an external session store](_docs::how_to::external_store) |
//! | Configure or troubleshoot a deployment | [How-to guides](_docs::how_to) |
//! | Learn how to assemble the engine | [Engine tutorial](_docs::tutorial::getting_started) |
//! | Integrate another framework or proxy | [Adapter guide](_docs::how_to::adapter) and [`engine`] |
//! | Look up an API contract | [`LoginConfig`], [`Session`], [`SessionDriver`], [`ExternalSessionStore`] |
//!
//! # Features and imports
//!
//! - `metrics`: opt-in counters; the application must install a recorder. See
//!   [Observe login failures](_docs::how_to::observability) and the [`metrics`] catalog.
//! - `test-support`: deterministic store doubles for integration tests, exposed
//!   in `testing`. Enable it on a dev-dependency.
//!
//! [`prelude`] imports upstream extension traits for method calls; import this
//! crate's types and the traits you implement explicitly. The [`client`] and
//! [`core`] re-exports provide the matching OAuth and cryptography APIs.
//!
//! Trait bounds use [`core::platform`]'s `MaybeSend` and `MaybeSendSync`
//! markers, allowing the crate to compile for native, `wasm32`, and WASI
//! targets.

#[cfg(any(doc, doctest))]
pub mod _docs;

pub use huskarl as client;
pub use huskarl::core;

pub mod cookie;
pub mod engine;
pub mod liveness;
pub mod metrics;
pub mod prelude;
pub mod session;
#[cfg(any(test, feature = "test-support"))]
#[cfg_attr(docsrs_huskarl_login, doc(cfg(feature = "test-support")))]
pub mod testing;
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

pub use core::EndpointUrl;

pub use completed_login::CompletedLogin;
pub use config::{
    ActivityPolicy, ConfigError, InvalidRoutePath, LoginConfig, LogoutConfig, RoutePath,
    SessionLifetime,
};
pub use cookie::{CookieName, InvalidCookieName};
pub use cookie_session::{
    CookiePayload, CookieSession, CookieSessionStore, CookieSessionStoreBuilder,
};
pub use engine::{
    DefaultPersistFailurePolicy, PersistFailurePolicy, TeardownReason, TerminateSessionOutcome,
};
pub use enrich::{NoEnrichment, SessionEnricher};
pub use error_page::{DefaultErrorPage, ErrorPage, ErrorPageResponse};
pub use liveness::{DEFAULT_IDLE_TIMEOUT, LivenessConfig, LivenessStore, LivenessVerdict};
pub use session::{
    DriverLoad, InvalidSessionReason, SessionDriver, SessionError, SessionErrorKind, SessionPolicy,
};
pub use session_state::{Session, SessionState};
pub use store_session::{
    ExternalSessionStore, LoadOutcome, PersistedSession, PersistedSessionState, SaveOutcome,
    SessionNotFound, StoreBackedSessionStore, StoreBackedSessionStoreBuilder, VersionConflict,
};
