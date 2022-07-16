#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;

use crate::config::def::Config;
use crate::config::internal::InternalConfig;
use std::io;
use std::path::Path;
use thiserror::Error;
use tokio::sync::mpsc;

mod app;
mod common;
mod config;
mod proxy;
mod session;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error("proxy error: {0}")]
    ProxyError(String),
}

pub struct Options {
    pub home: String,
    pub config: String,
}

pub fn start(opts: Options) -> Result<(), Error> {
    let (reload_tx, mut reload_rx) = mpsc::channel(1);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    let mut config = Path::join(opts.home.into(), opts.config)
        .to_str()?
        .parse::<Config>()?
        .into::<InternalConfig>();
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
