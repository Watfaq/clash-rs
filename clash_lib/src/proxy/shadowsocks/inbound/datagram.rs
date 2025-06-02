use crate::{
    common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::ready;
use shadowsocks::{ProxySocket, relay::udprelay::options::UdpSocketControlData};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
use tracing::{debug, error};

pub(crate) struct InboundShadowsocksDatagram {
    control: UdpSocketControlData,
    socket: ProxySocket<shadowsocks::net::UdpSocket>,

    // for Sink
    flushed: bool,
    pkt: Option<UdpPacket>,

    // for Stream
    buf: bytes::BytesMut,
}

impl std::fmt::Debug for InboundShadowsocksDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundShadowsocksDatagram")
            .field("control", &self.control)
            .field("socket", &self.socket)
            .finish()
    }
}

impl InboundShadowsocksDatagram {
    pub fn new(socket: ProxySocket<shadowsocks::net::UdpSocket>) -> Self {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random::<u64>();

        Self {
            buf: bytes::BytesMut::with_capacity(65535),
            socket,
            control,

            flushed: false,
            pkt: None,
        }
    }
}

impl futures::Stream for InboundShadowsocksDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let &mut Self {
            ref mut buf,
            ref socket,
            ..
        } = self.get_mut();

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(socket.poll_recv(cx, &mut buf));
        debug!("recv udp packet from inbound: {:?}", rv);

        match rv {
            Ok((n, src, ..)) => Poll::Ready(Some(UdpPacket {
                data: buf.filled()[..n].to_vec(),
                src_addr: match src {
                    shadowsocks::relay::Address::SocketAddress(a) => a.into(),
                    _ => SocksAddr::any_ipv4(),
                },
                dst_addr: SocksAddr::any_ipv4(),
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}

impl futures::Sink<UdpPacket> for InboundShadowsocksDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut socket,
            ref mut pkt,
            ref mut flushed,

            ref mut control,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let data = pkt.data.as_ref();
            let addr: shadowsocks::relay::Address =
                (pkt.dst_addr.host(), pkt.dst_addr.port()).into();

            let n = ready!(socket.poll_send_with_ctrl(&addr, control, data, cx))?;

            debug!("send udp packet to client {}", pkt);

            control.packet_id = match control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "packet_id overflow",
                    )));
                }
            };

            let wrote_all = n == data.len();
            *pkt_container = None;
            *flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {}",
                    n
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "no packet to send",
            )))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
