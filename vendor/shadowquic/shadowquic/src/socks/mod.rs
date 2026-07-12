use std::{io::Cursor, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::OnceCell};
use tracing::warn;

use crate::{
    UdpRecv, UdpSend,
    error::SError,
    msgs::socks5::{self, SocksAddr, UdpReqHeader},
};

use crate::msgs::{SDecode, SEncode};
pub mod inbound;
pub mod outbound;

#[derive(Clone)]
pub struct UdpSocksWrap(Arc<UdpSocket>, OnceCell<SocketAddr>); // remote addr
#[async_trait]
impl UdpRecv for UdpSocksWrap {
    async fn recv_from(&mut self) -> Result<(Bytes, SocksAddr), SError> {
        let mut buf = BytesMut::new();
        buf.resize(2000, 0);

        let (len, dst) = self.0.recv_from(&mut buf).await?;
        let mut cur = Cursor::new(buf);
        let req = socks5::UdpReqHeader::decode(&mut cur).await?;
        if req.frag != 0 {
            warn!("dropping fragmented udp datagram ");
            return Err(SError::ProtocolUnimpl);
        }
        let headsize: usize = cur.position().try_into().unwrap();
        let buf = cur.into_inner();
        self.1
            .get_or_init(|| async {
                let _ = self.0.connect(dst).await;
                dst
            })
            .await;
        let buf = buf.freeze();
        // assert!(len < buf.len());
        Ok((buf.slice(headsize..len), req.dst))
    }
}
#[async_trait]
impl UdpSend for UdpSocksWrap {
    async fn send_to(&self, buf: Bytes, addr: SocksAddr) -> Result<usize, SError> {
        let reply = UdpReqHeader {
            rsv: 0,
            frag: 0,
            dst: addr,
        };
        let mut buf_new = BytesMut::with_capacity(1600);
        let header = Vec::new();
        let mut cur = Cursor::new(header);
        reply.encode(&mut cur).await?;
        let header = cur.into_inner();
        buf_new.put(Bytes::from(header));
        buf_new.put(buf);

        Ok(self.0.send(&buf_new).await?)
    }
}
