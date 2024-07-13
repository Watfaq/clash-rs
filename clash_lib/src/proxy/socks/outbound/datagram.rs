use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;
use tracing::{error, trace};

use crate::{
    proxy::{datagram::UdpPacket, socks::Socks5UDPCodec},
    session::SocksAddr,
};

pub(crate) struct Socks5Datagram {
    remote: SocketAddr,
    inner: UdpFramed<Socks5UDPCodec>,
}

impl Socks5Datagram {
    pub(crate) fn new(remote: SocketAddr, udp_socket: UdpSocket) -> Self {
        let framed = UdpFramed::new(udp_socket, Socks5UDPCodec);

        Self {
            remote,
            inner: framed,
        }
    }
}

impl Sink<UdpPacket> for Socks5Datagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let remote = self.remote;
        let pin = self.get_mut();
        pin.start_send_unpin(UdpPacket {
            src_addr: item.src_addr,
            dst_addr: SocksAddr::Ip(remote),
            data: item.data,
        })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_flush_unpin(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_close_unpin(cx)
    }
}

impl Stream for Socks5Datagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        pin.inner.poll_next_unpin(cx).map(|opt| {
            opt.map(|res| match res {
                Ok(((src, data), dst)) => {
                    trace!("received UDP packet from {} to {}", src, dst,);
                    UdpPacket {
                        src_addr: src,
                        dst_addr: SocksAddr::Ip(dst),
                        data: data.into(),
                    }
                }
                Err(_) => {
                    error!("failed to decode UDP packet from remote");
                    UdpPacket {
                        src_addr: SocksAddr::any_ipv4(),
                        dst_addr: SocksAddr::any_ipv4(),
                        data: Vec::new(),
                    }
                }
            })
        })
    }
}
