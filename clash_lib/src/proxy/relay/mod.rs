use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use futures::stream::{self, StreamExt};
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedDatagram,
            ChainedDatagramWrapper, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
        remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    },
    common::errors::new_io_error,
    session::Session,
};

use super::{
    utils::{
        provider_helper::get_proxies_from_providers, DirectConnector,
        ProxyConnector, RemoteConnector,
    },
    AnyOutboundHandler, ConnectorType, DialWithConnector, OutboundHandler,
    OutboundType,
};

#[derive(Default)]
pub struct HandlerOptions {
    pub shared_opts: super::options::HandlerSharedOptions,
    pub name: String,
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
    ) -> AnyOutboundHandler {
        Arc::new(Self { opts, providers })
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        self.opts.name.as_str()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Relay
    }

    async fn support_udp(&self) -> bool {
        for proxy in self.get_proxies(false).await {
            match proxy.support_connector().await {
                ConnectorType::All => return true,
                ConnectorType::None | ConnectorType::Tcp => (),
            }
            if !proxy.support_udp().await {
                return false;
            }
        }
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let proxies: Vec<AnyOutboundHandler> =
            stream::iter(self.get_proxies(true).await).collect().await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("tcp relay `{}` via proxy `{}`", self.name(), proxy.name());
                proxy.connect_stream(sess, resolver).await
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "tcp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let s = last[0]
                    .connect_stream_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedStreamWrapper::new(s);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        let proxies: Vec<AnyOutboundHandler> =
            stream::iter(self.get_proxies(true).await).collect().await;

        match proxies.len() {
            0 => Err(new_io_error("no proxy available")),
            1 => {
                let proxy = proxies[0].clone();
                debug!("udp relay `{}` via proxy `{}`", self.name(), proxy.name());
                proxy.connect_datagram(sess, resolver).await
            }
            _ => {
                let mut connector: Box<dyn RemoteConnector> =
                    Box::new(DirectConnector::new());
                let (proxies, last) = proxies.split_at(proxies.len() - 1);
                for proxy in proxies {
                    debug!(
                        "udp relay `{}` via proxy `{}`",
                        self.name(),
                        proxy.name()
                    );
                    connector =
                        Box::new(ProxyConnector::new(proxy.clone(), connector));
                }

                debug!("relay `{}` via proxy `{}`", self.name(), last[0].name());
                let d = last[0]
                    .connect_datagram_with_connector(
                        sess,
                        resolver,
                        connector.as_ref(),
                    )
                    .await?;

                let chained = ChainedDatagramWrapper::new(d);
                chained.append_to_chain(self.name()).await;
                Ok(Box::new(chained))
            }
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;

        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );

        m
    }

    fn icon(&self) -> Option<String> {
        self.opts.shared_opts.icon.clone()
    }
}

#[cfg(feature = "shadowsocks")]
#[cfg(all(test, not(ci)))]
mod tests {

    use tokio::sync::RwLock;

    use crate::proxy::{
        mocks::MockDummyProxyProvider,
        utils::test_utils::{
            consts::*,
            docker_runner::{DockerTestRunner, DockerTestRunnerBuilder},
            run_test_suites_and_cleanup, Suite,
        },
    };

    use super::*;

    const PASSWORD: &str = "FzcLbKs2dY9mhL";
    const CIPHER: &str = "aes-256-gcm";

    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_relay_1_tcp() -> anyhow::Result<()> {
        let ss_opts = crate::proxy::shadowsocks::HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 10002,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin_opts: Default::default(),
            udp: false,
        };
        let port = ss_opts.port;
        let ss_handler: AnyOutboundHandler =
            Arc::new(crate::proxy::shadowsocks::Handler::new(ss_opts)) as _;

        let mut provider = MockDummyProxyProvider::new();

        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());

        provider.expect_proxies().returning(move || {
            let mut proxies = Vec::new();
            proxies.push(ss_handler.clone());
            proxies
        });

        let handler =
            Handler::new(Default::default(), vec![Arc::new(RwLock::new(provider))]);
        run_test_suites_and_cleanup(
            handler,
            get_ss_runner(port).await?,
            Suite::tcp_tests(),
        )
        .await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_relay_2_tcp() -> anyhow::Result<()> {
        let ss_opts = crate::proxy::shadowsocks::HandlerOptions {
            name: "test-ss".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 10002,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin_opts: Default::default(),
            udp: false,
        };
        let port = ss_opts.port;
        let ss_handler: AnyOutboundHandler =
            Arc::new(crate::proxy::shadowsocks::Handler::new(ss_opts)) as _;

        let mut provider = MockDummyProxyProvider::new();

        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());

        provider.expect_proxies().returning(move || {
            let mut proxies = Vec::new();
            proxies.push(ss_handler.clone());
            proxies.push(ss_handler.clone());
            proxies
        });

        let handler =
            Handler::new(Default::default(), vec![Arc::new(RwLock::new(provider))]);
        run_test_suites_and_cleanup(
            handler,
            get_ss_runner(port).await?,
            Suite::tcp_tests(),
        )
        .await
    }
}
