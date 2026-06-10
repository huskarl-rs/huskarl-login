#![forbid(unsafe_code)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Shared login core for huskarl framework integrations.
//!
//! This crate contains the framework-agnostic login logic shared by
//! `huskarl-axum` and `huskarl-pingora`: configuration, session drivers,
//! cookie helpers, URL helpers, grant abstraction, and session store traits.
//!
//! The canonical [`SessionDriver`] interface returns `Vec<HeaderValue>` from
//! mutating methods (`save`, `touch`, `delete`). Framework crates that need a
//! different interface (e.g. Pingora's `&mut ResponseHeader`) adapt with a
//! small helper that appends the returned headers.

pub mod cookie;
pub mod engine;
pub mod metrics;
pub mod session;
pub mod url;

mod config;
mod cookie_session;
mod error_page;
mod grant;
mod session_state;
mod store_session;

pub use config::{ConfigError, LoginConfig};
pub use cookie_session::{CookieData, CookieSession, CookieSessionStore};
pub use engine::{DefaultPersistFailurePolicy, PersistFailurePolicy};
pub use error_page::{DefaultErrorPage, ErrorPage, ErrorPageResponse};
pub use grant::{CompletedLogin, LoginGrant};
pub use metrics::{
    ActivityOutcome, DecryptResult, LoginCompleteResult, LoginEngineMetrics, LoginStartResult,
    RefreshResult, SessionCookieMetrics, normalize_as_error,
};
pub use session::{SessionDriver, SessionError};
pub use session_state::{Session, SessionState};
pub use store_session::{
    ExternalSessionStore, PersistedSession, PersistedSessionState, StoreBackedSessionStore,
};
