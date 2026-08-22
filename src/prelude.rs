//! Anonymous trait imports that make the crate's method syntax work.
//!
//! `use huskarl_login::prelude::*` brings the extension traits of the
//! re-exported [`client`](crate::client) and [`core`](crate::core) crates into
//! scope so method calls like `grant.exchange(…)` and
//! `secret.get_secret_value()` resolve — without a direct `huskarl` dependency.
//! Everything is imported anonymously (`as _`), so it adds **zero names** to
//! your namespace and never collides.
//!
//! It is trait-only *by design*: types are named and imported explicitly at
//! their use site, and traits you *implement* (rather than call) are excluded —
//! that includes this crate's own [`SessionDriver`](crate::SessionDriver),
//! [`Session`](crate::Session), [`SessionEnricher`](crate::SessionEnricher),
//! [`ExternalSessionStore`](crate::ExternalSessionStore), and
//! [`ErrorPage`](crate::ErrorPage), which are implemented, not called. So the
//! prelude re-exports the upstream [`huskarl::prelude`](crate::client::prelude)
//! and nothing login-specific.

// `client::prelude` already re-exports `core::prelude::*`; the second re-export
// keeps the guarantee explicit and independent of that upstream detail.
pub use crate::{client::prelude::*, core::prelude::*};
