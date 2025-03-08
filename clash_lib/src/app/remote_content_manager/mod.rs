use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use chrono::{DateTime, Utc};

use futures::{StreamExt, stream::FuturesUnordered};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument, trace};
use watfaq_resolver::Resolver;
use watfaq_state::Context;

use crate::{
    common::{errors::new_io_error, timed_future::TimedFuture},
    proxy::AnyOutboundHandler,
};

use self::http_client::LocalConnector;

pub mod healthcheck;
mod http_client;
pub mod providers;

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    delay: u16,
    #[serde(rename = "meanDelay")]
    mean_delay: u16,
}

#[derive(Default)]
struct ProxyState {
    alive: AtomicBool,
    delay_history: VecDeque<DelayHistory>,
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    ctx: Arc<Context>,
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: Arc<Resolver>,

    connector_map:
        Arc<RwLock<HashMap<String, hyper_rustls::HttpsConnector<LocalConnector>>>>,
}

impl ProxyManager {
    pub fn new(ctx: Arc<Context>, dns_resolver: Arc<Resolver>) -> Self {
        Self {
            ctx,
            dns_resolver,
            proxy_state: Arc::new(RwLock::new(HashMap::new())),
            connector_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check(
        &self,
        proxies: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Option<Duration>,
    ) {
        let mut futs = vec![];
        for proxy in proxies {
            let proxy = proxy.clone();
            let url = url.to_owned();
            let manager = self.clone();
            futs.push(tokio::spawn(async move {
                manager
                    .url_test(proxy, url.as_str(), timeout)
                    .await
                    .map_err(|e| debug!("healthcheck failed: {}", e))
            }));
        }

        let futs: FuturesUnordered<_> = futs.into_iter().collect();
        let _: Vec<_> = futs.collect().await;
    }

    pub async fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.alive.load(Ordering::Relaxed))
            .unwrap_or(true) // if not found, assume it's alive
    }

    pub async fn report_alive(&self, name: &str, alive: bool) {
        let mut state = self.proxy_state.write().await;
        let state = state.entry(name.to_owned()).or_default();
        state.alive.store(alive, Ordering::Relaxed)
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.delay_history.clone())
            .unwrap_or_default()
            .into()
    }

    pub async fn last_delay(&self, name: &str) -> u16 {
        let max = u16::MAX;
        if !self.alive(name).await {
            return max;
        }
        self.delay_history(name)
            .await
            .last()
            .map(|x| x.delay)
            .unwrap_or(max)
    }

    #[instrument(skip(self, proxy))]
    pub async fn url_test(
        &self,
        proxy: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(u16, u16)> {
        let name = proxy.name().to_owned();
        let name_clone = name.clone();
        let default_timeout = Duration::from_secs(5);

        let dns_resolver = self.dns_resolver.clone();
        let tester = async move {
            let name = name_clone;
            let connector =
                LocalConnector(proxy.clone(), dns_resolver, self.ctx.clone());

            let connector = {
                use crate::common::tls::GLOBAL_ROOT_STORE;

                let mut tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                    .with_no_client_auth();

                tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

                let connector = hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls_config)
                    .https_or_http()
                    .enable_all_versions()
                    .wrap_connector(connector);

                let mut g = self.connector_map.write().await;
                let connector = g.entry(name.clone()).or_insert(connector);
                connector.clone()
            };

            // Build the hyper client from the HTTPS connector.
            let client: Client<_, Empty<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);

            let req = Request::get(url)
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(Empty::new())
                .unwrap();

            let resp = TimedFuture::new(client.request(req), None);

            let delay: u16 =
                match tokio::time::timeout(timeout.unwrap_or(default_timeout), resp)
                    .await
                {
                    Ok((res, delay)) => match res {
                        Ok(res) => {
                            let delay = delay
                                .as_millis()
                                .try_into()
                                .expect("delay is too large");
                            trace!(
                                "urltest for proxy {} with url {} returned \
                                 response {} in {}ms",
                                &name,
                                url,
                                res.status(),
                                delay
                            );
                            Ok(delay)
                        }
                        Err(e) => {
                            debug!(
                                "urltest for proxy {} with url {} failed: {}",
                                &name, url, e
                            );
                            trace!(
                                "urltest for proxy {} with url {} failed: {:?}, \
                                 stack: {:?}",
                                &name,
                                url,
                                e,
                                e.source()
                            );
                            Err(new_io_error(format!("{}: {}", url, e).as_str()))
                        }
                    },
                    Err(_) => {
                        Err(new_io_error(format!("timeout for {}", url).as_str()))
                    }
                }?;

            let req2 = Request::get(url)
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(Empty::new())
                .unwrap();
            let resp2 = TimedFuture::new(client.request(req2), None);

            let mean_delay: u16 = match tokio::time::timeout(
                timeout.unwrap_or(default_timeout),
                resp2,
            )
            .await
            {
                Ok((res, delay2)) => match res {
                    Ok(_) => ((delay2.as_millis() + delay as u128) / 2)
                        .try_into()
                        .expect("delay is too large"),
                    Err(_) => 0,
                },
                Err(_) => 0,
            };

            Ok((delay, mean_delay))
        };

        let result = tester.await;

        self.report_alive(&name, result.is_ok()).await;

        let ins = DelayHistory {
            time: Utc::now(),
            delay: result.as_ref().map(|x| x.0).unwrap_or(0),
            mean_delay: result.as_ref().map(|x| x.1).unwrap_or(0),
        };

        let mut state = self.proxy_state.write().await;
        let state = state.entry(name.to_owned()).or_default();

        state.delay_history.push_back(ins);
        if state.delay_history.len() > 10 {
            state.delay_history.pop_front();
        }

        result
    }
}
