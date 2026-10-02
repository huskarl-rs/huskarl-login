//! Anonymous trait imports that make the crate's method syntax work.
//!
//! `use huskarl_login::prelude::*` brings the extension traits of the
//! re-exported [`client`](crate::client) and [`core`](crate::core) crates into
//! scope so method calls like `grant.exchange(…)` and
//! `secret.get_secret_value()` resolve — without a direct `huskarl` dependency.
//! Everything is imported anonymously (`as _`), so it adds **zero names** to
//! your namespace and never collides.
//!
//! Import this crate's types and traits explicitly. For example, use
//! `use huskarl_login::Session` to implement a session or call its lifecycle
//! methods, and `use huskarl_login::SessionDriver` when naming an engine's
//! generic bound. The prelude re-exports upstream extension traits only.

// `client::prelude` already re-exports `core::prelude::*`; the second re-export
// keeps the guarantee explicit and independent of that upstream detail.
pub use crate::{client::prelude::*, core::prelude::*};
