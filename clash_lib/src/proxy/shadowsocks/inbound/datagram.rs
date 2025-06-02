use crate::{
    common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::ready;
use shadowsocks::{
    ProxySocket,
    relay::udprelay::{
        options::UdpSocketControlData, proxy_socket::ProxySocketResult,
    },
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
use tracing::{debug, error};

pub(crate) struct InboundShadowsocksDatagram {
    control: UdpSocketControlData,
    socket: ProxySocket<tokio::net::UdpSocket>,

    // for Sink
    flushed: bool,
    pkt: Option<UdpPacket>,

    // for Stream
    buf: bytes::BytesMut,
}

impl InboundShadowsocksDatagram {
    pub fn new(socket: ProxySocket<tokio::net::UdpSocket>) -> Self {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random::<u64>();

        Self {
            buf: bytes::BytesMut::new(),
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
        let mut this = self.get_mut();
        let mut buf = tokio::io::ReadBuf::new(&mut this.buf);
        let socket = &mut this.socket;
        match socket.poll_recv(cx, &mut buf) {
            Poll::Ready(Ok((payload_len, src, _))) => Poll::Ready(Some(UdpPacket {
                data: buf.filled().to_vec(),
                src_addr: match src {
                    shadowsocks::relay::Address::SocketAddress(a) => a.into(),
                    _ => crate::session::SocksAddr::any_ipv4(),
                },
                dst_addr: crate::session::SocksAddr::any_ipv4(),
            })),
            Poll::Ready(Err(e)) => {
                error!("Failed to receive UDP packet: {}", e);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::Sink<UdpPacket> for InboundShadowsocksDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let &mut Self {
            ref mut buf,
            ref socket,
            ..
        } = self.get_mut();

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(socket.poll_recv(cx, &mut buf));
        debug!("recv udp packet from remote ss server: {:?}", rv);

        match rv {
            Ok((n, src, ..)) => Poll::Ready(Some(UdpPacket {
                data: buf.filled()[..n].to_vec(),
                src_addr: match src {
                    shadowsocks::relay::Address::SocketAddress(a) => a.into(),
                    _ => SocksAddr::any_ipv4(),
                },
                dst_addr: SocksAddr::any_ipv4(),
            })),
            Err(e) => Poll::Ready(Err(new_io_error(e.to_string()))),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
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

            debug!("send udp packet {}", pkt);

            control.packet_id = match control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
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
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
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
