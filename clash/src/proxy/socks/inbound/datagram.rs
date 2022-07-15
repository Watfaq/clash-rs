use crate::proxy::{
    AnyInboundDatagram, AnyInboundTransport, AnyStream, InboundDatagram, InboundDatagramHandler,
    InboundDatagramRecvHalf, InboundDatagramSendHalf, InboundTransport, ProxyError, ProxyResult,
};
use crate::session::{DatagramSource, SocksAddr};
use async_trait::async_trait;

use bytes::{BufMut, BytesMut};
use std::net::{SocketAddr, UdpSocket};

pub struct Handler;

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle(&self, socket: AnyInboundDatagram) -> std::io::Result<AnyInboundTransport> {
        Ok(InboundTransport::Datagram(
            Box::new(Datagram { socket }),
            None,
        ))
    }
}

pub struct Datagram {
    socket: AnyInboundDatagram,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (rh, sh) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(rh)),
            Box::new(DatagramRecvHalf(sh)),
        )
    }

    fn into_std(self: Box<Self>) -> std::io::Result<UdpSocket> {
        self.socket.into_std()
    }
}

pub struct DatagramRecvHalf(Box<dyn InboundDatagramRecvHalf>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let mut recv_buf = vec![0u8; buf.len()];
        let (n, src_addr, _) = self.0.recv_from(&mut recv_buf).await?;
        if n < 3 {
            return Err(ProxyError::DatagramWarn(anyhow!("msg too short")));
        }
        // skip RSV + FRAG
        let dst_addr = SocksAddr::try_from(&recv_buf[3..])
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("malformed socks5 UDP data: {}", e)))?;
        let header_size = 3 + dst_addr.size();
        let payload_size = n - header_size;
        buf[..payload_size].copy_from_slice(&recv_buf[header_size..header_size + payload_size]);
        Ok((payload_size, src_addr, dst_addr))
    }
}

pub struct DatagramSendHalf(Box<dyn InboundDatagramSendHalf>);

#[async_trait]

impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> std::io::Result<usize> {
        let mut send_buf = BytesMut::new();
        send_buf.put_u16(0); // RSV
        send_buf.put_u8(0); //FRAG not implemented
        src_addr.write_buf(&mut send_buf);
        send_buf.put_slice(buf);
        self.0.send_to(&send_buf[..], src_addr, dst_addr).await
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.0.close().await
    }
}
