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
//! `huskarl-login` contains the framework-independent policy and state machine
//! shared by adapters such as `huskarl-axum` and `huskarl-pingora`. The central
//! type is [`engine::LoginEngine`]. It starts and completes the Authorization
//! Code flow, validates and refreshes sessions, and handles logout. A framework
//! adapter is responsible for calling the engine and delivering its response
//! and cookie outputs.
//!
//! # Mental model
//!
//! A successful callback produces a [`CompletedLogin`]. A [`SessionEnricher`]
//! combines it with framework-managed state to build the application's
//! [`Session`]. A session driver then persists that value:
//!
//! ```text
//! authorization code ─▶ CompletedLogin ─┐
//!                                      ├─▶ SessionEnricher ─▶ Session ─▶ store
//!                     managed state ───┘
//! ```
//!
//! Choose [`CookieSessionStore`] to keep the encrypted session in the browser.
//! Choose [`StoreBackedSessionStore`] to keep only an encrypted lookup key in
//! the browser and store the session through an [`ExternalSessionStore`].
//!
//! # Documentation
//!
//! - New to the crate? Follow the [getting-started
//!   tutorial](_docs::tutorial::getting_started).
//! - Integrating a framework or backend? Use the [how-to
//!   guides](_docs::how_to).
//! - Evaluating the design or security trade-offs? Read the
//!   [explanations](_docs::explanation).
//! - Looking up behavior and contracts? The public API items are the reference
//!   documentation; [`engine`], [`LoginConfig`], and [`prelude`] are useful
//!   entry points.
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
