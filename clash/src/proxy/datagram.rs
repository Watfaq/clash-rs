use crate::app::ThreadSafeDNSResolver;
use crate::proxy::{
    InboundDatagram, InboundDatagramRecvHalf, InboundDatagramSendHalf, OutboundDatagram,
    OutboundDatagramRecvHalf, OutboundDatagramSendHalf, ProxyError, ProxyResult,
};
use crate::session::{DatagramSource, SocksAddr};
use async_trait::async_trait;
use futures::TryFutureExt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct SimpleOutboundDatagram {
    inner: UdpSocket,
    destination: Option<SocksAddr>,
    resolver: ThreadSafeDNSResolver,
}

impl SimpleOutboundDatagram {
    pub fn new(
        inner: UdpSocket,
        destination: Option<SocksAddr>,
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        Self {
            inner,
            destination,
            resolver,
        }
    }
}

impl OutboundDatagram for SimpleOutboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.inner);
        let s = r.clone();
        (
            Box::new(SimpleOutboundDatagramRecvHalf(r, self.destination)),
            Box::new(SimpleOutboundDatagramSendHalf(s, self.resolver)),
        )
    }
}

pub struct SimpleOutboundDatagramRecvHalf(Arc<UdpSocket>, Option<SocksAddr>);

#[async_trait]
impl OutboundDatagramRecvHalf for SimpleOutboundDatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match self.0.recv_from(buf).await {
            Ok((n, a)) => {
                if self.1.is_some() {
                    Ok((n, self.1.as_ref().unwrap().clone()))
                } else {
                    Ok((n, SocksAddr::Ip(a)))
                }
            }
            Err(e) => Err(e),
        }
    }
}

pub struct SimpleOutboundDatagramSendHalf(Arc<UdpSocket>, ThreadSafeDNSResolver);

#[async_trait]
impl OutboundDatagramSendHalf for SimpleOutboundDatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let addr = match target {
            SocksAddr::Domain(domain, port) => {
                let ip = self
                    .1
                    .read()
                    .await
                    .resolve(domain)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("lookup {} failed: {}", domain, e),
                        )
                    })
                    .await?;

                if let Some(ip) = ip {
                    SocketAddr::new(ip, port.to_owned())
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "could not resolve to any address",
                    ));
                }
            }
            SocksAddr::Ip(a) => a.to_owned(),
        };
        self.0.send_to(buf, &addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct SimpleInboundDatagram(pub UdpSocket);

impl InboundDatagram for SimpleInboundDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let r = Arc::new(self.0 as UdpSocket);
        let s = r.clone();
        (
            Box::new(SimpleInboundDatagramRecvHalf(r)),
            Box::new(SimpleInboundDatagramSendHalf(s)),
        )
    }

    fn into_std(self: Box<Self>) -> std::io::Result<std::net::UdpSocket> {
        self.0.into_std()
    }
}

pub struct SimpleInboundDatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramRecvHalf for SimpleInboundDatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (n, src_addr) = self
            .0
            .recv_from(buf)
            .map_err(|e| ProxyError::DatagramFatal(e.into()))
            .await?;
        Ok((
            n,
            DatagramSource::new(src_addr, None),
            // This should be the target address which is decoded by proxy
            // protocol layers, since this is a plain UDP socket, we use an
            // empty address as a workaround to avoid introducing the Option type.
            // The final address would be override by a proxy handler anyway.
            SocksAddr::any_ipv4(),
        ))
    }
}

pub struct SimpleInboundDatagramSendHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramSendHalf for SimpleInboundDatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send_to(buf, dst_addr).await
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
