#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate anyhow;
extern crate core;

use crate::config::def::Config;
use std::borrow::Borrow;

use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::app::dispatcher::Dispatcher;
use crate::app::inbound::manager::InboundManager;
use crate::app::nat_manager::NatManager;
use crate::app::outbound::manager::OutboundManager;
use crate::app::router::Router;
use crate::app::{dns, ThreadSafeDNSResolver};
use crate::config::internal::proxy::OutboundProxy;
use crate::config::internal::InternalConfig;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use trust_dns_resolver::Resolver;

mod app;
mod common;
mod config;
mod proxy;
mod session;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
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

pub type Runner = futures::future::BoxFuture<'static, ()>;

pub struct Options {
    pub home: String,
    pub config: String,
}

pub fn start(opts: Options) -> Result<(), Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            start_async(opts);
        });
    Ok(())
}

pub async fn start_async(opts: Options) -> Result<(), Error> {
    let mut config: InternalConfig = Path::join(opts.home.as_str().as_ref(), &opts.config)
        .to_str()
        .ok_or(Error::InvalidConfig(format!(
            "invalid config file: home {} file: {}",
            opts.home, opts.config
        )))?
        .parse::<Config>()?
        .try_into()?;

    let mut tasks = Vec::<Runner>::new();
    let mut runners = Vec::new();

    let default_dns_resolver = Arc::new(RwLock::new(dns::Resolver::new(config.dns).await));
    let outbound_manager = Arc::new(RwLock::new(OutboundManager::new(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
        config
            .proxy_groups
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyGroup(g) => Some(g),
                _ => None,
            })
            .collect(),
        default_dns_resolver.clone(),
    )?));
    let router = Arc::new(RwLock::new(Router::new(
        config.rules,
        default_dns_resolver.clone(),
    )));
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager,
        router,
        default_dns_resolver,
    ));
    let nat_manager = Arc::new(NatManager::new(dispatcher.clone()));

    let inbound_manager = InboundManager::new(config.general.inbound, dispatcher, nat_manager)?;

    let mut inbound_runners = inbound_manager.get_runners()?;
    runners.append(&mut inbound_runners);

    tasks.push(Box::pin(async move {
        futures::future::join_all(runners).await;
    }));

    tasks.push(Box::pin(async move {
        let _ = tokio::signal::ctrl_c().await;
    }));

    futures::future::select_all(tasks).await;
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
