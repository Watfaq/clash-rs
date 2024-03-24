use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use quinn::ZeroRttAccepted;

use anyhow::Result;
use tuic::Address;
use tuic_quinn::{Connect, Packet};

use crate::proxy::datagram::UdpPacket;
use crate::session::SocksAddr as ClashSocksAddr;

use super::types::{TuicConnection, UdpRelayMode};

impl TuicConnection {
    pub async fn tuic_auth(self: Arc<Self>, zero_rtt_accepted: Option<ZeroRttAccepted>) {
        if let Some(zero_rtt_accepted) = zero_rtt_accepted {
            tracing::debug!("[auth] waiting for connection to be fully established");
            zero_rtt_accepted.await;
        }

        tracing::debug!("[auth] sending authentication");

        match self
            .inner
            .authenticate(self.uuid, self.password.clone())
            .await
        {
            Ok(()) => tracing::info!("[auth] {uuid}", uuid = self.uuid),
            Err(err) => {
                tracing::warn!("[auth] authentication sending error: {err}")
            }
        }
    }

    pub async fn connect_tcp(&self, addr: Address) -> Result<Connect> {
        let addr_display = addr.to_string();
        tracing::info!("[tcp] {addr_display}");

        match self.inner.connect(addr).await {
            Ok(conn) => Ok(conn),
            Err(err) => {
                tracing::warn!("[tcp] failed initializing relay to {addr_display}: {err}");
                Err(anyhow!(err))
            }
        }
    }

    pub async fn outgoing_udp(
        &self,
        pkt: Bytes,
        addr: Address,
        assoc_id: u16,
    ) -> anyhow::Result<()> {
        let addr_display = addr.to_string();

        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                tracing::info!("[udp] [{assoc_id:#06x}] [to-native] to {addr_display}");
                match self.inner.packet_native(pkt, addr, assoc_id) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        tracing::warn!(
                            "[udp] [{assoc_id:#06x}] [to-native] to {addr_display}: {err}"
                        );
                        Err(anyhow!(err))
                    }
                }
            }
            UdpRelayMode::Quic => {
                tracing::info!("[udp] [{assoc_id:#06x}] [to-quic] {addr_display}");
                match self.inner.packet_quic(pkt, addr, assoc_id).await {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        tracing::warn!(
                            "[udp] [{assoc_id:#06x}] [to-quic] to {addr_display}: {err}"
                        );
                        Err(anyhow!(err))
                    }
                }
            }
        }
    }

    pub async fn incoming_udp(&self, pkt: Packet) {
        let assoc_id = pkt.assoc_id();
        let pkt_id = pkt.pkt_id();

        let mode = if pkt.is_from_native() {
            "native"
        } else if pkt.is_from_quic() {
            "quic"
        } else {
            unreachable!()
        };

        tracing::info!(
            "[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}",
            frag_id = pkt.frag_id() + 1,
            frag_total = pkt.frag_total(),
        );
        match pkt.accept().await {
            Ok(Some((data, remote_addr, _))) => {
                tracing::info!("[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] from {remote_addr}");
                let (session, local_addr) = match self.udp_sessions.read().await.get(&assoc_id) {
                    Some(v) => (v.incoming.clone(), v.local_addr.clone()),
                    None => {
                        tracing::error!("[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] unable to find udp session");
                        return;
                    },
                };
                let remote_addr = match remote_addr {
                    Address::None => unreachable!(),
                    Address::DomainAddress(domain, port) => ClashSocksAddr::Domain(domain, port),
                    Address::SocketAddress(socket) => ClashSocksAddr::Ip(socket),
                };
                if let Err(err) = session.send(UdpPacket::new(data.into(), remote_addr, local_addr)).await {
                    tracing::error!("[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] failed sending packet: {err}")
                };
            },
            Ok(None) => {}
            Err(err) => tracing::error!("[udp] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] packet receiving error: {err}"),
        }
    }

    pub async fn dissociate(&self, assoc_id: u16) -> Result<()> {
        tracing::info!("[udp] [dissociate] [{assoc_id:#06x}]");
        match self.inner.dissociate(assoc_id).await {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!("[udp] [dissociate] [{assoc_id:#06x}] {err}");
                Err(err)?
            }
        }
    }

    async fn heartbeat(&self) -> Result<()> {
        self.check_open()?;
        if self.inner.task_connect_count() + self.inner.task_associate_count() == 0 {
            return Ok(());
        }

        match self.inner.heartbeat().await {
            Ok(()) => tracing::trace!("[heartbeat]"),
            Err(err) => tracing::error!("[heartbeat] {err}"),
        }
        Ok(())
    }

    fn collect_garbage(&self, gc_lifetime: Duration) -> Result<()> {
        self.check_open()?;
        tracing::trace!("[gc]");
        self.inner.collect_garbage(gc_lifetime);
        Ok(())
    }
    /// Tasks triggered by timer
    /// Won't return unless occurs error
    pub async fn cyclical_tasks(
        self: Arc<Self>,
        heartbeat_interval: Duration,
        gc_interval: Duration,
        gc_lifetime: Duration,
    ) -> anyhow::Error {
        let mut heartbeat_interval = tokio::time::interval(heartbeat_interval);
        let mut gc_interval = tokio::time::interval(gc_interval);
        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => match self.heartbeat().await {
                    Ok(_) => { },
                    Err(err) => break err,
                },
                _ = gc_interval.tick() => match self.collect_garbage(gc_lifetime) {
                    Ok(_) => { },
                    Err(err) => break err,
                },
            }
        }
    }
}
