//! Extended documentation: explanation and how-to guides.
//!
//! The API items in this crate are the **reference** documentation — they say
//! what each type and method is. These pages cover the other
//! [Diátaxis](https://diataxis.fr) quadrants:
//!
//! - **[Explanation](explanation)** — understanding-oriented background on how
//!   the crate works and why it is shaped the way it is.
//! - **[How-to guides](guide)** — task-oriented recipes for wiring the crate
//!   into an application.
//!
//! This module is documentation only; it contains no runnable API and is
//! compiled solely for `cargo doc` and `cargo test --doc`. The code blocks in
//! these pages are real doctests and are compiled with the rest of the crate.

/// Understanding-oriented background on how the crate works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/session_model.md")]
    pub mod session_model {}

    #[doc = include_str!("../docs/explanation/refresh.md")]
    pub mod refresh {}

    #[doc = include_str!("../docs/explanation/liveness.md")]
    pub mod liveness {}

    #[doc = include_str!("../docs/explanation/cookie_security.md")]
    pub mod cookie_security {}
}

/// Task-oriented recipes for wiring the crate into an application.
pub mod guide {
    #[doc = include_str!("../docs/guide/adapter.md")]
    pub mod adapter {}

    #[doc = include_str!("../docs/guide/enrichment.md")]
    pub mod enrichment {}

    #[doc = include_str!("../docs/guide/external_store.md")]
    pub mod external_store {}

    #[doc = include_str!("../docs/guide/rotation.md")]
    pub mod rotation {}

    #[doc = include_str!("../docs/guide/caching.md")]
    pub mod caching {}
}
