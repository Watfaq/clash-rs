use crate::{proxy::datagram::UdpPacket, session::TargetAddr};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};
use watfaq_utils::TargetAddrExt as _;

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
//
// The fields in the UDP request header are:
//
// o  RSV  Reserved X'0000'
// o  FRAG    Current fragment number
// o  ATYP    address type of following addresses:
// o  IP V4 address: X'01'
// o  DOMAINNAME: X'03'
// o  IP V6 address: X'04'
// o  DST.ADDR       desired destination address
// o  DST.PORT       desired destination port
// o  DATA     user data
pub struct Socks5UDPCodec;

impl Encoder<(Bytes, TargetAddr)> for Socks5UDPCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: (Bytes, TargetAddr),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.reserve(3 + item.1.size() + item.0.len());
        dst.put_slice(&[0x0, 0x0, 0x0]);
        item.1.write_buf(dst);
        dst.put_slice(item.0.as_ref());

        Ok(())
    }
}

impl Decoder for Socks5UDPCodec {
    type Error = std::io::Error;
    type Item = (TargetAddr, BytesMut);

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 3 {
            return Ok(None);
        }

        if src[2] != 0 {
            return Err(std::io::Error::new(
                io::ErrorKind::Other,
                "unsupported FRAG",
            ));
        }

        src.advance(3);
        let addr = TargetAddr::peek_read(src)?;
        src.advance(addr.size());
        let packet = std::mem::take(src);
        Ok(Some((addr, packet)))
    }
}

pub struct InboundUdp<I> {
    inner: I,
}

impl<I> InboundUdp<I>
where
    I: Stream + Unpin,
    I: Sink<((Bytes, TargetAddr), SocketAddr)>,
{
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundUdp").finish()
    }
}

impl Stream for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        match pin.inner.poll_next_unpin(cx) {
            Poll::Ready(item) => match item {
                None => Poll::Ready(None),
                Some(item) => match item {
                    Ok(((dst, pkt), src)) => Poll::Ready(Some(UdpPacket {
                        data: pkt.to_vec(),
                        src_addr: TargetAddr::Socket(src),
                        dst_addr: dst,
                    })),
                    Err(_) => Poll::Ready(None),
                },
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<UdpPacket> for InboundUdp<UdpFramed<Socks5UDPCodec>> {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.inner.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.inner.start_send_unpin((
            (item.data.into(), item.src_addr),
            item.dst_addr.must_into_socket_addr(),
        ))
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
