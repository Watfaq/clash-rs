pub type Error = eyre::Report;
pub type Result<T> = eyre::Result<T>;

pub use eyre::{Context as ErrContext, anyhow, bail};
