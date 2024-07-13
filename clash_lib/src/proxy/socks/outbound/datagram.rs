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
    proxy::{datagram::UdpPacket, socks::Socks5UDPCodec, AnyStream},
    session::SocksAddr,
};

pub(crate) struct Socks5Datagram {
    // hold the socket to keep it alive and drop it when this is dropped
    _socket: AnyStream,
    remote: SocketAddr,
    inner: UdpFramed<Socks5UDPCodec>,
}

impl Socks5Datagram {
    pub(crate) fn new(
        socket: AnyStream,
        remote: SocketAddr,
        udp_socket: UdpSocket,
    ) -> Self {
        let framed = UdpFramed::new(udp_socket, Socks5UDPCodec);

        Self {
            _socket: socket,
            remote,
            inner: framed,
        }
    }
}

impl Drop for Socks5Datagram {
    fn drop(&mut self) {
        // this should drop the inner socket too.
        // https://datatracker.ietf.org/doc/html/rfc1928
        // A UDP association terminates when the TCP connection that the UDP
        // ASSOCIATE request arrived on terminates.
        // ideally we should be able to shutdown the UDP association
        // when the TCP connection is closed, but we don't have a way to do that
        // as there is no close() method on UdpSocket.
        trace!("UDP relay to {} closed, closing socket", self.remote);
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
        trace!(
            "sending UDP packet to {}, item dst: {}",
            remote,
            item.dst_addr
        );
        let pin = self.get_mut();
        pin.inner
            .start_send_unpin(((item.data.into(), item.dst_addr), remote))
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
