use std::{
    pin::Pin,
    sync::{atomic::AtomicU32, Arc},
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};

use crate::{
    common::errors::new_io_error, proxy::datagram::UdpPacket, session::SocksAddr,
};

use super::{
    codec::{Defragger, HysUdpPacket},
    HysteriaConnection,
};

pub struct UdpSession {
    pub incoming: tokio::sync::mpsc::Sender<UdpPacket>,
    pub local_addr: SocksAddr,
    pub defragger: Defragger,
}

impl UdpSession {
    pub fn feed(&mut self, pkt: HysUdpPacket) -> Option<HysUdpPacket> {
        self.defragger.feed(pkt)
    }
}

#[derive(Debug)]
pub struct HysteriaDatagramOutbound {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl HysteriaDatagramOutbound {
    pub async fn new(
        session_id: u32,
        conn: Arc<HysteriaConnection>,
        local_addr: SocksAddr,
    ) -> Self {
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let udp_sessions = conn.udp_sessions.clone();
        udp_sessions.lock().await.insert(
            session_id,
            UdpSession {
                incoming: recv_tx,
                local_addr,
                defragger: Defragger::default(),
            },
        );
        tokio::spawn(async move {
            // capture vars
            let mut send_rx = send_rx;

            // use u32 to avoid overflow
            let next_pkt_id = AtomicU32::new(0);
            while let Some(next_send) = send_rx.recv().await {
                let pkt_id =
                    next_pkt_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let pkt_id = (pkt_id % u16::MAX as u32) as u16;
                if let Err(e) = conn.send_packet(
                    next_send.data.into(),
                    next_send.dst_addr,
                    session_id,
                    pkt_id,
                ) {
                    tracing::warn!(
                        "err in outgoing_udp of HysteriaDatagramOutbound, msg: {:?}",
                        e
                    );
                    break;
                }
            }
            // TuicDatagramOutbound dropped or outgoing_udp occurs error
            tracing::info!(
                "[udp] [dissociate] closing UDP session [{session_id:#06x}]"
            );
            let entry = udp_sessions.lock().await.remove(&session_id);
            debug_assert!(entry.is_some());
            anyhow::Ok(())
        });

        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        }
    }
}

impl Sink<UdpPacket> for HysteriaDatagramOutbound {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }
}

impl Stream for HysteriaDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}
