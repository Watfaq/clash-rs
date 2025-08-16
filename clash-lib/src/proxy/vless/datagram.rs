use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncReadExt, AsyncWrite};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::{SocksAddr, SocksAddrType},
};

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Read state machine
    read_state: ReadState,
    read_buf: BytesMut,

    // Write state
    written: Option<usize>,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            read_state: ReadState::Length,
            read_buf: BytesMut::new(),
            written: None,
            flushed: true,
            pkt: None,
        }
    }

    fn encode_packet(pkt: &UdpPacket) -> Vec<u8> {
        let mut buf = BytesMut::new();

        // VLESS UDP packet format:
        // Length (2 bytes) + Address type + Address + Port + Data

        let addr_len = match &pkt.dst_addr {
            SocksAddr::Ip(socket_addr) => {
                match socket_addr.ip() {
                    std::net::IpAddr::V4(_) => 1 + 4 + 2, // type + ipv4 + port
                    std::net::IpAddr::V6(_) => 1 + 16 + 2, // type + ipv6 + port
                }
            }
            SocksAddr::Domain(domain, _) => 1 + 1 + domain.len() + 2, /* type + len + domain + port */
        };

        buf.put_u16((addr_len + pkt.data.len()) as u16);

        pkt.dst_addr.write_buf(&mut buf);

        buf.put_slice(&pkt.data);
        buf.to_vec()
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

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
            ref mut inner,
            ref mut pkt,
            ref mut written,
            ref mut flushed,
            ref remote_addr,
            ..
        } = *self;

        let mut inner = Pin::new(inner);

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let payload = Self::encode_packet(pkt);

            if written.is_none() {
                *written = Some(0);
            }

            let mut remaining = &payload[*written.as_ref().unwrap()..];

            while !remaining.is_empty() {
                let n = ready!(inner.as_mut().poll_write(cx, remaining))?;
                *written.as_mut().unwrap() += n;
                remaining = &remaining[n..];

                trace!(
                    "written {} bytes to vless stream, remaining {}, data len {}",
                    n,
                    remaining.len(),
                    pkt.data.len()
                );
            }

            if !*flushed {
                ready!(inner.as_mut().poll_flush(cx))?;
                *flushed = true;
            }

            debug!(
                "sent UDP packet to remote VLESS server, len: {}, remote_addr: {}, \
                 dst_addr: {}",
                pkt.data.len(),
                remote_addr,
                pkt.dst_addr
            );

            *written = None;
            *pkt_container = None;

            Poll::Ready(Ok(()))
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
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

enum ReadState {
    Length,
    Atyp,
    Addr(u8),
    Port(SocksAddr),
    Data(SocksAddr, usize),
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut read_buf,
            ref mut inner,
            ref remote_addr,
            ref mut read_state,
            ..
        } = *self;

        let mut pin = Pin::new(inner);

        loop {
            match read_state {
                ReadState::Length => {
                    let fut = pin.read_u16();
                    futures::pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(length) => {
                            *read_state = ReadState::Atyp;
                            read_buf.resize(length as usize, 0);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read length from VLESS stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::Atyp => {
                    let fut = pin.read_u8();
                    futures::pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(atyp) => {
                            *read_state = ReadState::Addr(atyp);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read address type from VLESS stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::Addr(atyp) => match *atyp {
                    SocksAddrType::V4 => {
                        let fut = pin.read_u32();
                        futures::pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = std::net::Ipv4Addr::from(ip);
                                *read_state = ReadState::Port(SocksAddr::Ip(
                                    SocketAddr::from((ip, 0)),
                                ));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read IPv4 address from VLESS \
                                     stream: {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::V6 => {
                        let fut = pin.read_u128();
                        futures::pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = std::net::Ipv6Addr::from(ip);
                                *read_state = ReadState::Port(SocksAddr::Ip(
                                    SocketAddr::from((ip, 0)),
                                ));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read IPv6 address from VLESS \
                                     stream: {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::DOMAIN => {
                        let fut = pin.read_u8();
                        futures::pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(domain_len) => {
                                let mut buf = vec![0u8; domain_len as usize];
                                let fut = pin.read_exact(&mut buf);
                                futures::pin_mut!(fut);
                                match ready!(fut.poll(cx)) {
                                    Ok(_) => {
                                        let domain = String::from_utf8(buf);
                                        match domain {
                                            Ok(domain) => {
                                                *read_state = ReadState::Port(
                                                    SocksAddr::Domain(domain, 0),
                                                );
                                            }
                                            Err(err) => {
                                                debug!(
                                                    "failed to parse domain from \
                                                     VLESS stream: {}",
                                                    err
                                                );
                                                return Poll::Ready(None);
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        debug!(
                                            "failed to read domain from VLESS \
                                             stream: {}",
                                            err
                                        );
                                        return Poll::Ready(None);
                                    }
                                }
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read domain length from VLESS \
                                     stream: {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    _ => {
                        debug!("invalid address type: {}", atyp);
                        return Poll::Ready(None);
                    }
                },
                ReadState::Port(addr) => {
                    let fut = pin.read_u16();
                    futures::pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(port) => {
                            let addr = match addr {
                                SocksAddr::Ip(socket_addr) => {
                                    match socket_addr.ip() {
                                        std::net::IpAddr::V4(ip) => SocksAddr::Ip(
                                            SocketAddr::from((ip, port)),
                                        ),
                                        std::net::IpAddr::V6(ip) => SocksAddr::Ip(
                                            SocketAddr::from((ip, port)),
                                        ),
                                    }
                                }
                                SocksAddr::Domain(domain, _) => {
                                    SocksAddr::Domain(domain.to_owned(), port)
                                }
                            };

                            let data_len = read_buf.len()
                                - (1 + // atyp
                                 match &addr {
                                     SocksAddr::Ip(sa) => match sa.ip() {
                                         std::net::IpAddr::V4(_) => 4,
                                         std::net::IpAddr::V6(_) => 16,
                                     },
                                     SocksAddr::Domain(d, _) => 1 + d.len(),
                                 } + 2); // port

                            *read_state = ReadState::Data(addr, data_len);
                        }
                        Err(err) => {
                            debug!("failed to read port from VLESS stream: {}", err);
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::Data(addr, data_len) => {
                    let mut data_buf = vec![0u8; *data_len];
                    let fut = pin.read_exact(&mut data_buf);
                    futures::pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(_) => {
                            let addr = addr.to_owned();
                            *read_state = ReadState::Length;

                            return Poll::Ready(Some(UdpPacket {
                                data: data_buf,
                                src_addr: remote_addr.clone(),
                                dst_addr: addr,
                            }));
                        }
                        Err(err) => {
                            debug!("failed to read data from VLESS stream: {}", err);
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}
