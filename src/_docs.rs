//! Integrate, customize, and understand the login engine.
//!
//! Application and proxy setup starts in
//! [`huskarl-axum`](https://docs.rs/huskarl-axum/latest/huskarl_axum/) or
//! [`huskarl-pingora`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/).
//! The material here covers shared behavior and extension points, and provides
//! a direct starting point for integrators building on the engine.
//!
//! Choose the section that matches your task:
//!
//! - **[Tutorial](tutorial)** — build a minimal login engine while learning the
//!   main pieces.
//! - **[How-to guides](how_to)** — complete a specific integration or
//!   deployment task.
//! - **[Explanation](explanation)** — understand the design, trade-offs, and
//!   security model.
//! - **Reference** — use the crate's public modules and API items, starting
//!   with [`crate::engine`], [`crate::LoginConfig`], or the [`crate::prelude`].
//!
//! This module contains no runtime API and is compiled only while generating
//! documentation.

/// Learn how to assemble the engine used by framework adapters.
///
/// Start with [Build a login engine](tutorial::getting_started) to
/// connect OIDC discovery, cookie sealing, session storage, and the engine.
pub mod tutorial {
    #[doc = include_str!("../docs/tutorial/getting_started.md")]
    pub mod getting_started {}
}

/// Understand the design and its trade-offs.
///
/// - [The session model](explanation::session_model) defines the core terms,
///   persistence choices, and request states.
/// - [Session lifetime policy](explanation::session_lifetime) explains absolute
///   lifetime limits and how configuration changes affect existing sessions.
/// - [Token refresh](explanation::refresh) explains eager persistence,
///   transient failure, and concurrent refresh.
/// - [Server-side liveness](explanation::liveness) explains idle tracking and
///   its fail-open design.
/// - [Cookie security](explanation::cookie_security) explains names, AEAD
///   binding, chunking, flow-cookie hygiene, and key rotation.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/session_model.md")]
    pub mod session_model {}

    #[doc = include_str!("../docs/explanation/session_lifetime.md")]
    pub mod session_lifetime {}

    #[doc = include_str!("../docs/explanation/refresh.md")]
    pub mod refresh {}

    #[doc = include_str!("../docs/explanation/liveness.md")]
    pub mod liveness {}

    #[doc = include_str!("../docs/explanation/cookie_security.md")]
    pub mod cookie_security {}
}

/// Complete a specific integration or deployment task.
///
/// - [Choose and configure a deployment](how_to::deployment).
/// - [Build a framework adapter](how_to::adapter).
/// - [Build an application session](how_to::enrichment).
/// - [Implement an external session store](how_to::external_store).
/// - [Add idle-timeout tracking](how_to::liveness).
/// - [Configure public and ingress URLs](how_to::url_mapping).
/// - [Rotate cookie encryption keys](how_to::cookie_keys).
/// - [Observe login failures](how_to::observability).
/// - [Prevent session responses from being cached](how_to::caching).
/// - [Deploy refresh-token rotation safely](how_to::rotation).
/// - [Troubleshoot browser login](how_to::troubleshooting).
/// - [Adapt an existing integration](how_to::migration).
pub mod how_to {
    #[doc = include_str!("../docs/how_to/deployment.md")]
    pub mod deployment {}

    #[doc = include_str!("../docs/how_to/troubleshooting.md")]
    pub mod troubleshooting {}

    #[doc = include_str!("../docs/how_to/adapter.md")]
    pub mod adapter {}

    #[doc = include_str!("../docs/how_to/enrichment.md")]
    pub mod enrichment {}

    #[doc = include_str!("../docs/how_to/external_store.md")]
    pub mod external_store {}

    #[doc = include_str!("../docs/how_to/rotation.md")]
    pub mod rotation {}

    #[doc = include_str!("../docs/how_to/caching.md")]
    pub mod caching {}

    #[doc = include_str!("../docs/how_to/liveness.md")]
    pub mod liveness {}

    #[doc = include_str!("../docs/how_to/url_mapping.md")]
    pub mod url_mapping {}

    #[doc = include_str!("../docs/how_to/cookie_keys.md")]
    pub mod cookie_keys {}

    #[doc = include_str!("../docs/how_to/observability.md")]
    pub mod observability {}

    #[doc = include_str!("../docs/how_to/migration.md")]
    pub mod migration {}
}
