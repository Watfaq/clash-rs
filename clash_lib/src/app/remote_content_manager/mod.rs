use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use boring::ssl::{SslConnector, SslMethod};

use chrono::{DateTime, Utc};

use futures::{stream::FuturesUnordered, StreamExt};
use hyper::Request;
use hyper_boring::HttpsConnector;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument};

use crate::{
    common::{
        errors::{map_io_error, new_io_error},
        timed_future::TimedFuture,
    },
    proxy::AnyOutboundHandler,
};

use self::http_client::LocalConnector;

use super::dns::ThreadSafeDNSResolver;

pub mod healthcheck;
mod http_client;
pub mod providers;

#[macro_export]
macro_rules! pm_debug {
    ($($arg:tt)*) => ({
        debug!(target: "proxy_manager", $($arg)*);
    });
}

#[macro_export]
macro_rules! pm_warn {
    ($($arg:tt)*) => ({
        warn!(target: "proxy_manager", $($arg)*);
    });
}

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
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: ThreadSafeDNSResolver,

    connector_map: Arc<RwLock<HashMap<String, HttpsConnector<LocalConnector>>>>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver) -> Self {
        Self {
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
        pm_debug!(
            "testing {} with url {}, timeout {:?}",
            proxy.name(),
            url,
            timeout
        );
        let name = proxy.name().to_owned();
        let name_clone = name.clone();
        let default_timeout = Duration::from_secs(5);

        let dns_resolver = self.dns_resolver.clone();
        let tester = async move {
            let name = name_clone;
            let connector = LocalConnector(proxy.clone(), dns_resolver);

            let mut ssl = SslConnector::builder(SslMethod::tls()).map_err(map_io_error)?;
            ssl.set_alpn_protos(b"\x02h2\x08http/1.1")
                .map_err(map_io_error)?;

            let mut g = self.connector_map.write().await;
            let connector = g
                .entry(name.clone())
                .or_insert(HttpsConnector::with_connector(connector, ssl).map_err(map_io_error)?);

            let connector = connector.clone();
            drop(g);

            let client = hyper::Client::builder().build::<_, hyper::Body>(connector);

            let req = Request::get(url)
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(hyper::Body::empty())
                .unwrap();

            let resp = TimedFuture::new(client.request(req), None);

            let delay: u16 =
                match tokio::time::timeout(timeout.unwrap_or(default_timeout), resp).await {
                    Ok((res, delay)) => match res {
                        Ok(res) => {
                            let delay = delay.as_millis().try_into().expect("delay is too large");
                            pm_debug!(
                                "urltest for proxy {} with url {} returned response {} in {}ms",
                                &name,
                                url,
                                res.status(),
                                delay
                            );
                            Ok(delay)
                        }
                        Err(e) => {
                            pm_debug!("urltest for proxy {} with url {} failed: {}", &name, url, e);
                            Err(new_io_error(format!("{}: {}", url, e).as_str()))
                        }
                    },
                    Err(_) => Err(new_io_error(format!("timeout for {}", url).as_str())),
                }?;

            let req2 = Request::get(url)
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(hyper::Body::empty())
                .unwrap();
            let resp2 = TimedFuture::new(client.request(req2), None);

            let mean_delay: u16 =
                match tokio::time::timeout(timeout.unwrap_or(default_timeout), resp2).await {
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

        pm_debug!("{} alive: {}, delay: {:?}", name, result.is_ok(), result);

        result
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use futures::TryFutureExt;

    use crate::{
        app::{dispatcher::ChainedStreamWrapper, dns::MockClashResolver, remote_content_manager},
        config::internal::proxy::PROXY_DIRECT,
        proxy::{direct, mocks::MockDummyOutboundHandler},
    };

    #[tokio::test]
    async fn test_proxy_manager_alive() {
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::new(172, 217, 167, 67)))));

        let manager = remote_content_manager::ProxyManager::new(Arc::new(mock_resolver));

        let mock_handler = direct::Handler::new();

        manager
            .url_test(
                mock_handler.clone(),
                "http://www.gstatic.com/generate_204",
                None,
            )
            .await
            .expect("test failed");

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(manager.last_delay(PROXY_DIRECT).await > 0);
        assert!(!manager.delay_history(PROXY_DIRECT).await.is_empty());

        manager.report_alive(PROXY_DIRECT, false).await;
        assert!(!manager.alive(PROXY_DIRECT).await);

        for _ in 0..10 {
            manager
                .url_test(
                    mock_handler.clone(),
                    "http://www.gstatic.com/generate_204",
                    None,
                )
                .await
                .expect("test failed");
        }

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(manager.last_delay(PROXY_DIRECT).await > 0);
        assert!(manager.delay_history(PROXY_DIRECT).await.len() == 10);
    }

    #[tokio::test]
    async fn test_proxy_manager_timeout() {
        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))));

        let manager = remote_content_manager::ProxyManager::new(Arc::new(mock_resolver));

        let mut mock_handler = MockDummyOutboundHandler::new();
        mock_handler
            .expect_name()
            .return_const(PROXY_DIRECT.to_owned());
        mock_handler.expect_connect_stream().returning(|_, _| {
            Ok(Box::new(ChainedStreamWrapper::new(
                tokio_test::io::Builder::new()
                    .wait(Duration::from_secs(10))
                    .build(),
            )))
        });

        let mock_handler = Arc::new(mock_handler);

        let result = manager
            .url_test(
                mock_handler.clone(),
                "http://www.gstatic.com/generate_204",
                Some(Duration::from_secs(3)),
            )
            .map_err(|x| assert!(x.to_string().contains("timeout")))
            .await;

        assert!(result.is_err());
        assert!(!manager.alive(PROXY_DIRECT).await);
        assert!(manager.last_delay(PROXY_DIRECT).await == u16::MAX);
        assert!(manager.delay_history(PROXY_DIRECT).await.len() == 1);
    }
}
