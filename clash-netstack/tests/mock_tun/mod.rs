use bytes::Bytes;
use futures::{Sink, Stream};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;

pub struct MockTun {
    rx: mpsc::UnboundedReceiver<Bytes>,
    tx: mpsc::UnboundedSender<Bytes>,
}

impl MockTun {
    pub fn new() -> (
        Self,
        mpsc::UnboundedSender<Bytes>,
        mpsc::UnboundedReceiver<Bytes>,
    ) {
        let (to_tun_tx, to_tun_rx) = mpsc::unbounded_channel();
        let (from_tun_tx, from_tun_rx) = mpsc::unbounded_channel();
        (
            MockTun {
                rx: to_tun_rx,
                tx: from_tun_tx,
            },
            to_tun_tx,   // Send packets into the TUN (simulate OS->TUN)
            from_tun_rx, // Receive packets from the TUN (simulate TUN->OS)
        )
    }
}

impl Stream for MockTun {
    type Item = Bytes;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        Pin::new(&mut me.rx).poll_recv(cx)
    }
}

impl Sink<Bytes> for MockTun {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let me = self.get_mut();
        me.tx
            .send(item)
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
