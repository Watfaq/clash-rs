use std::sync::atomic::Ordering;

use bytes::Bytes;
use quinn::{RecvStream, SendStream, VarInt};
use register_count::Register;
use tuic_quinn::Task;

use crate::proxy::tuic::types::UdpRelayMode;

use super::types::TuicConnection;

impl TuicConnection {
    pub async fn accept_uni_stream(&self) -> anyhow::Result<(RecvStream, Register)> {
        let max = self.max_concurrent_uni_streams.load(Ordering::Relaxed);

        if self.remote_uni_stream_cnt.count() as u32 == max {
            self.max_concurrent_uni_streams
                .store(max * 2, Ordering::Relaxed);

            self.conn
                .set_max_concurrent_uni_streams(VarInt::from(max * 2));
        }

        let recv = self.conn.accept_uni().await?;
        let reg = self.remote_uni_stream_cnt.reg();
        Ok((recv, reg))
    }

    pub async fn accept_bi_stream(&self) -> anyhow::Result<(SendStream, RecvStream, Register)> {
        let max = self.max_concurrent_bi_streams.load(Ordering::Relaxed);

        if self.remote_bi_stream_cnt.count() as u32 == max {
            self.max_concurrent_bi_streams
                .store(max * 2, Ordering::Relaxed);

            self.conn
                .set_max_concurrent_bi_streams(VarInt::from(max * 2));
        }

        let (send, recv) = self.conn.accept_bi().await?;
        let reg = self.remote_bi_stream_cnt.reg();
        Ok((send, recv, reg))
    }

    pub async fn accept_datagram(&self) -> anyhow::Result<Bytes> {
        Ok(self.conn.read_datagram().await?)
    }

    pub async fn handle_uni_stream(self, recv: RecvStream, _reg: Register) {
        tracing::debug!("[relay] incoming unidirectional stream");

        let res = match self.inner.accept_uni_stream(recv).await {
            Err(err) => Err(anyhow!(err)),
            Ok(Task::Packet(pkt)) => match self.udp_relay_mode {
                UdpRelayMode::Quic => {
                    self.incoming_udp(pkt).await;
                    Ok(())
                }
                UdpRelayMode::Native => Err(anyhow!("wrong packet source")),
            },
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            tracing::warn!("[relay] incoming unidirectional stream error: {err}");
        }
    }

    pub async fn handle_bi_stream(self, send: SendStream, recv: RecvStream, _reg: Register) {
        tracing::debug!("[relay] incoming bidirectional stream");

        let res = match self.inner.accept_bi_stream(send, recv).await {
            Err(err) => Err::<(), _>(anyhow!(err)),
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            tracing::warn!("[relay] incoming bidirectional stream error: {err}");
        }
    }

    pub async fn handle_datagram(self, dg: Bytes) {
        tracing::debug!("[relay] incoming datagram");

        let res = match self.inner.accept_datagram(dg) {
            Err(err) => Err(anyhow!(err)),
            Ok(Task::Packet(pkt)) => match self.udp_relay_mode {
                UdpRelayMode::Native => {
                    self.incoming_udp(pkt).await;
                    Ok(())
                }
                UdpRelayMode::Quic => Err(anyhow!("wrong packet source")),
            },
            _ => unreachable!(), // already filtered in `tuic_quinn`
        };

        if let Err(err) = res {
            tracing::warn!("[relay] incoming datagram error: {err}");
        }
    }
}
