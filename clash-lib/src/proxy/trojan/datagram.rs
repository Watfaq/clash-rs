use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::Poll,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Future, Sink, Stream, pin_mut, ready};
use tracing::{debug, trace};

use tokio::io::{AsyncReadExt, AsyncWrite};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::{SocksAddr, SocksAddrType},
};

pub struct OutboundDatagramTrojan {
    inner: AnyStream,
    remote_addr: SocksAddr,

    state: ReadState,
    read_buf: BytesMut,

    written: Option<usize>,
    flushed: bool,
    pkt: Option<UdpPacket>,
}

impl OutboundDatagramTrojan {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,

            read_buf: BytesMut::new(),
            state: ReadState::Atyp,

            written: None,
            flushed: true,
            pkt: None,
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramTrojan {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref mut written,
            ref mut flushed,
            ..
        } = *self;

        let mut inner = Pin::new(inner);

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let data = &pkt.data;

            let mut payload = BytesMut::new();
            pkt.dst_addr.write_buf(&mut payload);
            payload.put_u16(data.len() as u16);
            payload.put_slice(b"\r\n");
            payload.put_slice(data);

            if let Some(w) = *written {
                payload.advance(w);
            } else {
                *written = Some(0);
            }

            while !payload.is_empty() {
                let n = ready!(inner.as_mut().poll_write(cx, payload.as_ref()))?;
                if n == 0 {
                    // poll_write returning Ok(0) means the stream is closed
                    // (per AsyncWrite contract). Without this check, the loop
                    // would spin forever since payload.advance(0) makes no
                    // progress. Mirror std::io::Write::write_all behavior.
                    *pkt_container = None;
                    *written = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole trojan udp packet: stream closed",
                    )));
                }
                *written.as_mut().unwrap() += n;
                payload.advance(n);

                trace!(
                    "written {} bytes to trojan stream, remaining {}, data len {}",
                    n,
                    payload.len(),
                    data.len()
                );
            }

            if !*flushed {
                ready!(inner.as_mut().poll_flush(cx))?;
                *flushed = true;
            }
            *written = None;
            *pkt_container = None;

            Poll::Ready(Ok(()))
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

enum Addr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}
enum ReadState {
    Atyp,
    Addr(u8),
    Port(Addr),
    DataLen(SocksAddr),
    Data(SocksAddr, usize),
}

impl Stream for OutboundDatagramTrojan {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut read_buf,
            ref mut inner,
            ref remote_addr,
            ref mut state,
            ..
        } = *self;

        let mut pin = Pin::new(inner.as_mut());

        loop {
            match state {
                ReadState::Atyp => {
                    let fut = pin.read_u8();
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(atyp) => {
                            *state = ReadState::Addr(atyp);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::Addr(atyp) => match *atyp {
                    SocksAddrType::V4 => {
                        let fut = pin.read_u32();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = Ipv4Addr::from(ip);
                                *state = ReadState::Port(Addr::V4(ip));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::V6 => {
                        let fut = pin.read_u128();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(ip) => {
                                let ip = Ipv6Addr::from(ip);
                                *state = ReadState::Port(Addr::V6(ip));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    SocksAddrType::DOMAIN => {
                        let fut = pin.read_u8();
                        pin_mut!(fut);
                        match ready!(fut.poll(cx)) {
                            Ok(domain_len) => {
                                let mut buf = vec![0u8; domain_len as usize];
                                let fut = pin.read_exact(&mut buf);
                                pin_mut!(fut);
                                let n = match ready!(fut.poll(cx)) {
                                    Ok(n) => n,
                                    Err(err) => {
                                        debug!(
                                            "failed to read socks addr from Trojan \
                                             stream: {}",
                                            err
                                        );
                                        return Poll::Ready(None);
                                    }
                                };
                                if n != domain_len as usize {
                                    return Poll::Ready(None);
                                }
                                let domain = String::from_utf8(buf);
                                let domain = match domain {
                                    Ok(domain) => domain,
                                    Err(err) => {
                                        debug!(
                                            "failed to read socks addr from Trojan \
                                             stream: {}",
                                            err
                                        );
                                        return Poll::Ready(None);
                                    }
                                };
                                *state = ReadState::Port(Addr::Domain(domain));
                            }
                            Err(err) => {
                                debug!(
                                    "failed to read socks addr from Trojan stream: \
                                     {}",
                                    err
                                );
                                return Poll::Ready(None);
                            }
                        }
                    }
                    _ => {
                        debug!("invalid socks addr type: {:?}", atyp);
                        return Poll::Ready(None);
                    }
                },
                ReadState::Port(addr) => {
                    let fut = pin.read_u16();
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(port) => {
                            let addr = match addr {
                                Addr::V4(ip) => SocksAddr::from((*ip, port)),
                                Addr::V6(ip) => SocksAddr::from((*ip, port)),
                                Addr::Domain(domain) => {
                                    match SocksAddr::try_from((
                                        domain.to_owned(),
                                        port,
                                    )) {
                                        Ok(addr) => addr,
                                        Err(err) => {
                                            debug!(
                                                "failed to read socks addr from \
                                                 Trojan stream: {}",
                                                err
                                            );
                                            return Poll::Ready(None);
                                        }
                                    }
                                }
                            };
                            *state = ReadState::DataLen(addr);
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
                ReadState::DataLen(addr) => {
                    // TODO: this is error prone, make this a more accurate
                    // state machine
                    let fut = pin.read_u16();
                    pin_mut!(fut);
                    let data_len = match ready!(fut.poll(cx)) {
                        Ok(data_len) => data_len,
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    };
                    read_buf.resize(2, 0);
                    let fut = pin.read_exact(read_buf);
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(_) => {
                            if &read_buf[..2] != b"\r\n" {
                                debug!("invalid trojan data");
                                return Poll::Ready(None);
                            }
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    };

                    read_buf.resize(data_len as usize, 0);
                    *state = ReadState::Data(addr.to_owned(), data_len as usize);
                }
                ReadState::Data(addr, len) => {
                    let fut = pin.read_exact(read_buf);
                    pin_mut!(fut);
                    match ready!(fut.poll(cx)) {
                        Ok(n) => {
                            if n != *len {
                                debug!("invalid trojan data");
                                return Poll::Ready(None);
                            }

                            let addr = addr.to_owned();
                            let len = len.to_owned();

                            *state = ReadState::Atyp;

                            let data = read_buf.split_to(len);

                            return Poll::Ready(Some(UdpPacket {
                                data: data.to_vec(),
                                src_addr: remote_addr.clone(),
                                dst_addr: addr,
                                inbound_user: None,
                            }));
                        }
                        Err(err) => {
                            debug!(
                                "failed to read socks addr from Trojan stream: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    struct ChunkedStream {
        buf: Vec<u8>,
        chunk_size: usize,
    }

    impl AsyncWrite for ChunkedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let to_write = std::cmp::min(buf.len(), self.chunk_size);
            self.buf.extend_from_slice(&buf[..to_write]);
            Poll::Ready(Ok(to_write))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl crate::proxy::ProxyStream for ChunkedStream {}

    #[tokio::test]
    async fn test_trojan_datagram_sink_partial_writes() {
        let stream: AnyStream = Box::new(ChunkedStream {
            buf: Vec::new(),
            chunk_size: 3,
        });
        let remote_addr: SocksAddr = "1.1.1.1:443".parse().unwrap();
        let mut sink = OutboundDatagramTrojan::new(stream, remote_addr.clone());

        let dst_addr: SocksAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"hello trojan udp payload with enough length";
        let packet = UdpPacket {
            data: payload.to_vec(),
            src_addr: remote_addr.clone(),
            dst_addr: dst_addr.clone(),
            inbound_user: None,
        };

        sink.send(packet).await.expect("send must succeed");
    }

    #[tokio::test]
    async fn test_trojan_datagram_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let remote_addr: SocksAddr = "1.1.1.1:443".parse().unwrap();
        let mut client =
            OutboundDatagramTrojan::new(Box::new(client_io), remote_addr.clone());
        let mut server =
            OutboundDatagramTrojan::new(Box::new(server_io), remote_addr.clone());

        let dst_addr: SocksAddr = "8.8.8.8:53".parse().unwrap();
        let test_payload = b"roundtrip trojan udp packet data";
        let packet = UdpPacket {
            data: test_payload.to_vec(),
            src_addr: remote_addr.clone(),
            dst_addr: dst_addr.clone(),
            inbound_user: None,
        };

        client.send(packet).await.expect("send should succeed");

        let received = server.next().await.expect("should receive packet");
        assert_eq!(received.data, test_payload);
        assert_eq!(received.dst_addr, dst_addr);
        assert_eq!(received.src_addr, remote_addr);
    }
}
