use std::io;

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream};
use shadowquic::msgs::socks5::SocksAddr as SQAddr;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::PollSender;
use tracing::warn;

use crate::{
    common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr,
};

use super::{to_clash_socks_addr, to_sq_socks_addr};

pub struct UdpSessionWrapper {
    pub s: PollSender<(Bytes, SQAddr)>,
    pub r: Receiver<(Bytes, SQAddr)>,
    pub src_addr: SocksAddr, /* source address of local socket, bound during
                              * associate task
                              * started */
}
impl Sink<UdpPacket> for UdpSessionWrapper {
    type Error = io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_ready_unpin(cx).map_err(new_io_error)
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let dst = to_sq_socks_addr(item.dst_addr)?;
        self.get_mut()
            .s
            .start_send_unpin((item.data.into(), dst))
            .map_err(new_io_error)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_flush_unpin(cx).map_err(new_io_error)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.get_mut().s.poll_close_unpin(cx).map_err(new_io_error)
    }
}

impl Stream for UdpSessionWrapper {
    type Item = UdpPacket;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match self.r.poll_recv(cx) {
                std::task::Poll::Ready(Some((data, src))) => {
                    let src_addr = match to_clash_socks_addr(src) {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!(
                                "shadowquic outbound dropped UDP packet with invalid source: {e}"
                            );
                            continue;
                        }
                    };
                    return std::task::Poll::Ready(Some(UdpPacket {
                        data: data.into(),
                        src_addr,
                        dst_addr: self.src_addr.clone(),
                        inbound_user: None,
                    }));
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}
