#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;

use std::{
    io,
    sync::{Arc, RwLock},
};
use thiserror::Error;

mod app;
mod common;
mod config;
mod proxy;
mod session;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    InvalidConfig(#[from] anyhow::Error),
    #[error("profile error: {0}")]
    ProfileError(String),
}

pub fn start() -> Result<(), Error> {
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
