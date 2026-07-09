#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Tests legitimately unwrap/expect/panic; the denies above guard library code only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![warn(clippy::pedantic)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Framework-agnostic login core shared by `huskarl-axum` and
//! `huskarl-pingora`: configuration, session drivers, session enrichment,
//! cookie and URL helpers, and session store traits.
//!
//! The OAuth flow is driven by a
//! [`huskarl::grant::authorization_code::AuthorizationCodeGrant`] passed to the
//! [`engine::LoginEngine`]. A [`SessionEnricher`] builds the application's
//! session type from a framework-prepared seed and the [`CompletedLogin`]; the
//! session is then stored by a [`CookieSessionStore`] (sealed into AEAD
//! browser cookies) or a [`StoreBackedSessionStore`] (persisted via an
//! [`ExternalSessionStore`] behind a pointer cookie).
//!
//! Trait bounds use `huskarl::core::platform`'s `MaybeSend` / `MaybeSendSync`
//! markers, so the crate also compiles for `wasm32` and WASI targets.
//!
//! # Guides and explanation
//!
//! The API items here are the reference docs. For task-oriented how-to guides
//! (implementing a framework adapter, enrichment, implementing an external
//! store, refresh-token rotation) and design explanation (the session model,
//! liveness, cookie security), see the [`_docs`] module.

#[cfg(any(doc, docsrs))]
pub mod _docs;

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
    SessionLifetime,
};
pub use cookie::{CookieName, InvalidCookieName};
pub use cookie_session::{
    CookiePayload, CookieSession, CookieSessionStore, CookieSessionStoreBuilder,
};
pub use engine::{DefaultPersistFailurePolicy, PersistFailurePolicy, TeardownReason};
pub use enrich::{NoEnrichment, SessionEnricher};
pub use error_page::{DefaultErrorPage, ErrorPage, ErrorPageResponse};
pub use huskarl::core::EndpointUrl;
pub use liveness::{DEFAULT_IDLE_TIMEOUT, LivenessConfig, LivenessStore, LivenessVerdict};
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
