use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};

use crate::{common::errors::new_io_error, proxy::datagram::UdpPacket};

use super::TuicDatagramOutbound;

impl Sink<UdpPacket> for TuicDatagramOutbound {
    type Error = std::io::Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|v| new_io_error(&format!("{v:?}")))
    }
    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|v| new_io_error(&format!("{v:?}")))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|v| new_io_error(&format!("{v:?}")))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|v| new_io_error(&format!("{v:?}")))
    }
}

impl Stream for TuicDatagramOutbound {
    type Item = UdpPacket;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}
