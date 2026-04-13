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
        // Both IDs are overwritten on the first received packet; set random
        // values here so any accidental early send is at least non-trivially
        // predictable.
        control.client_session_id = rand::random::<u64>();
        control.server_session_id = rand::random::<u64>();

        Self {
            buf: bytes::BytesMut::with_capacity(65535),
            socket,
            control,

            flushed: true,
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
        let Self {
            ref mut buf,
            ref socket,
            ref mut control,
            ..
        } = *self.get_mut();

        loop {
            buf.resize(buf.capacity(), 0);
            let mut read_buf = ReadBuf::new(buf);

            let rv = ready!(socket.poll_recv_from_with_ctrl(cx, &mut read_buf));
            debug!("recv udp packet from inbound: {:?}", rv);

            match rv {
                Ok((n, src, target, _, ctrl)) => {
                    // Propagate the sender's session context into self.control
                    // so that the subsequent response is encrypted with the
                    // correct user key (uPSK) and echoes the correct
                    // client_session_id. Without this, multi-user SS2022 UDP
                    // responses are encrypted with the server iPSK, causing
                    // MAC failure on clients that expect uPSK-encrypted replies
                    // (e.g. sing-shadowsocks).
                    if let Some(ref c) = ctrl {
                        control.client_session_id = c.client_session_id;
                        control.user = c.user.clone();
                    }

                    return Poll::Ready(Some(UdpPacket {
                        data: read_buf.filled()[..n].to_vec(),
                        src_addr: src.into(),
                        dst_addr: match target {
                            shadowsocks::relay::Address::SocketAddress(a) => {
                                a.into()
                            }
                            shadowsocks::relay::Address::DomainNameAddress(
                                domain,
                                port,
                            ) => SocksAddr::Domain(domain, port),
                        },
                        inbound_user: ctrl
                            .and_then(|c| c.user)
                            .map(|u| u.name().to_owned()),
                    }));
                }
                Err(e) => {
                    // Log the error but keep the stream alive. Without looping
                    // here, returning Poll::Pending would leave the task without
                    // a registered waker (the waker was consumed when data
                    // arrived), permanently suspending the UDP dispatch loop.
                    error!("failed to receive udp packet: {}", e);
                    // Fall through to the next loop iteration: if the socket
                    // is empty, poll_recv_from_with_ctrl will re-register the
                    // waker and return Poll::Pending via ready!().
                }
            }
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
        debug!("start sending udp packet: {:?}", pin.pkt);
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
            let addr: shadowsocks::relay::Address = match &pkt.src_addr {
                SocksAddr::Ip(addr) => {
                    shadowsocks::relay::Address::SocketAddress(*addr)
                }
                SocksAddr::Domain(host, port) => {
                    shadowsocks::relay::Address::DomainNameAddress(
                        host.clone(),
                        *port,
                    )
                }
            };

            let n = ready!(socket.poll_send_to_with_ctrl(
                pkt.dst_addr.clone().must_into_socket_addr(),
                &addr,
                control,
                pkt.data.as_ref(),
                cx
            ))?;

            debug!("send udp packet to client {}", pkt);

            control.packet_id = match control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(std::io::Error::other(
                        "packet_id overflow",
                    )));
                }
            };

            let wrote_all = n == pkt.data.len();
            *pkt_container = None;
            *flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {n}"
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(std::io::Error::other("no packet to send")))
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
