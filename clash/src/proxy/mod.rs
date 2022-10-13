use crate::proxy::utils::Interface;
use crate::session::Session;
use crate::ThreadSafeDNSResolver;
use async_trait::async_trait;
use std::io;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub mod direct;
pub mod reject;

pub mod http;
//pub mod shadowsocks;
pub mod utils;

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type AnyStream = Box<dyn ProxyStream>;

pub struct CommonOption {
    so_mark: Option<u32>,
    iface: Option<Interface>,
}

#[async_trait]
pub trait InboundListener: Send + Sync + Unpin {
    async fn listen_tcp(&self) -> io::Result<()>;
    async fn listen_udp(&self) -> io::Result<()>;
}

pub type AnyInboundListener = Arc<dyn InboundListener>;

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin {
    fn name(&self) -> &str;

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<AnyStream>;
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[async_trait]
pub trait ProxyChain: Sync + Send + Unpin {
    async fn chain(&self, s: AnyStream, sess: &Session) -> io::Result<AnyStream>;
}
