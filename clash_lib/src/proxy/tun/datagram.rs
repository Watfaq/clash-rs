use std::task::Poll;

use futures::{ready, Sink, Stream};

use crate::{
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, InboundDatagram},
};

#[derive(Debug)]
pub struct TunDatagram {
    rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    tx: tokio::sync::mpsc::Sender<UdpPacket>,

    pkt: Option<UdpPacket>,
    flushed: bool,
}

// TODO: make this work
impl TunDatagram {
    pub fn new(
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    ) -> Self {
        Self {
            rx,
            tx,
            pkt: None,
            flushed: true,
        }
    }
}

impl InboundDatagram<UdpPacket> for TunDatagram {}

impl Stream for TunDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for TunDatagram {
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

    fn start_send(self: std::pin::Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut tx,
            ref mut pkt,
            ref mut flushed,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container.take() {
            match tx.blocking_send(pkt) {
                Ok(_) => Poll::Ready(Ok(())),
                Err(err) => Poll::Ready(Err(new_io_error(err.to_string().as_str()))),
            }
        } else {
            Poll::Ready(Err(new_io_error("no packet to send".into())))
        }
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
