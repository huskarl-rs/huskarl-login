//! Learn and use `huskarl-login`.
//!
//! This crate organizes its documentation using
//! [Diátaxis](https://diataxis.fr). Choose the section that matches what you
//! are trying to do:
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

/// Learning-oriented material for first-time users.
///
/// Start with [Build your first login engine](tutorial::getting_started) to
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
/// - [Build a framework adapter](how_to::adapter).
/// - [Build an application session](how_to::enrichment).
/// - [Implement an external session store](how_to::external_store).
/// - [Prevent session responses from being cached](how_to::caching).
/// - [Deploy refresh-token rotation safely](how_to::rotation).
pub mod how_to {
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
}
