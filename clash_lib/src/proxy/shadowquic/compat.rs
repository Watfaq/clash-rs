use std::io;

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream};
use shadowquic::msgs::socks5::SocksAddr as SQAddr;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::PollSender;

use crate::{
    common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr,
};

use super::{to_clash_socks_addr, to_sq_socks_addr};

pub struct UdpSessionWrapper {
    pub s: PollSender<(Bytes, SQAddr)>,
    pub r: Receiver<(Bytes, SQAddr)>,
    pub src_addr: SocksAddr, /* source addres of local socket, binded during
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
        self.get_mut()
            .s
            .start_send_unpin((item.data.into(), to_sq_socks_addr(item.dst_addr)))
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
        self.r.poll_recv(cx).map(|x| {
            x.map(|x| UdpPacket {
                data: x.0.into(),
                src_addr: self.src_addr.clone(),
                dst_addr: to_clash_socks_addr(x.1),
            })
        })
    }
}
