mod stream;

use std::sync::Arc;

use arti_client::{StreamPrefs, TorClientConfig};
use async_trait::async_trait;

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream, ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    session::{Session, SocksAddr},
};

use self::stream::StreamWrapper;

use super::{AnyOutboundHandler, OutboundHandler, OutboundType};

pub struct HandlerOptions {
    pub name: String,
}

pub struct Handler {
    opts: HandlerOptions,

    client: arti_client::TorClient<tor_rtcompat::PreferredRuntime>,
}

impl Handler {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(opts: HandlerOptions) -> AnyOutboundHandler {
        Arc::new(Self {
            opts,
            client: arti_client::TorClient::builder()
                .config(TorClientConfig::default())
                .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
                .create_unbootstrapped()
                .unwrap(),
        })
    }
}
#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tor
    }

    async fn remote_addr(&self) -> Option<SocksAddr> {
        None
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedStream> {
        let s = self
            .client
            .connect_with_prefs(
                (sess.destination.host(), sess.destination.port()),
                #[cfg(feature = "onion")]
                StreamPrefs::new()
                    .any_exit_country()
                    .connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true)),
                #[cfg(not(feature = "onion"))]
                StreamPrefs::new().any_exit_country(),
            )
            .await
            .map_err(|x| new_io_error(&x.to_string()))?;
        let s = ChainedStreamWrapper::new(StreamWrapper::new(s));
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(new_io_error("Tor outbound handler does not support UDP"))
    }
}
