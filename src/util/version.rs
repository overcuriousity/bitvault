// DISCLAIMER
// (c) 2024-05-27 overcuriousity - derived from the original Microbin Project by Daniel Szabo
use std::borrow::Cow;

pub struct Version {
    pub title: Cow<'static, str>,
    pub long_title: Cow<'static, str>,
}

pub static GIT_COMMIT: &str = env!("GIT_COMMIT_SHORT");

// Derived from Cargo.toml at compile time so the reported version can never
// drift from the crate version again.
pub static CURRENT_VERSION: Version = Version {
    title: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
    long_title: Cow::Borrowed(concat!("Version ", env!("CARGO_PKG_VERSION"))),
};
