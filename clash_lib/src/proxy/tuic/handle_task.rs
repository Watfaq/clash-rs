use bytes::Bytes;
use quinn::ZeroRttAccepted;

use anyhow::Result;
use std::time::Duration;
use tokio::time;
use tuic::Address;
use tuic_quinn::{Connect, Packet};

use super::types::{TuicConnection, UdpRelayMode};

impl TuicConnection {
    pub async fn authenticate(self, zero_rtt_accepted: Option<ZeroRttAccepted>) {
        if let Some(zero_rtt_accepted) = zero_rtt_accepted {
            tracing::debug!(
                "[authenticate] waiting for connection to be fully established"
            );
            zero_rtt_accepted.await;
        }

        tracing::debug!("[authenticate] sending authentication");

        match self
            .inner
            .authenticate(self.uuid, self.password.clone())
            .await
        {
            Ok(()) => tracing::info!("[authenticate] {uuid}", uuid = self.uuid),
            Err(err) => {
                tracing::warn!("[authenticate] authentication sending error: {err}")
            }
        }
    }

    pub async fn connect(&self, addr: Address) -> Result<Connect> {
        let addr_display = addr.to_string();
        tracing::info!("[connect] {addr_display}");

        match self.inner.connect(addr).await {
            Ok(conn) => Ok(conn),
            Err(err) => {
                tracing::warn!(
                    "[connect] failed initializing relay to {addr_display}: {err}"
                );
                Err(anyhow!(err))
            }
        }
    }

    pub async fn packet(&self, pkt: Bytes, addr: Address, assoc_id: u16) -> anyhow::Result<()> {
        let addr_display = addr.to_string();

        match self.udp_relay_mode {
            UdpRelayMode::Native => {
                tracing::info!("[packet] [{assoc_id:#06x}] [to-native] to {addr_display}");
                match self.inner.packet_native(pkt, addr, assoc_id) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        tracing::warn!("[packet] [{assoc_id:#06x}] [to-native] to {addr_display}: {err}");
                        Err(anyhow!(err))
                    }
                }
            }
            UdpRelayMode::Quic => {
                tracing::info!("[packet] [{assoc_id:#06x}] [to-quic] {addr_display}");
                match self.inner.packet_quic(pkt, addr, assoc_id).await {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        tracing::warn!(
                            "[packet] [{assoc_id:#06x}] [to-quic] to {addr_display}: {err}"
                        );
                        Err(anyhow!(err))
                    }
                }
            }
        }
    }

    pub async fn dissociate(&self, assoc_id: u16) -> anyhow::Result<()> {
        tracing::info!("[dissociate] [{assoc_id:#06x}]");
        match self.inner.dissociate(assoc_id).await {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!("[dissociate] [{assoc_id:#06x}] {err}");
                Err(anyhow!(err))
            }
        }
    }

    pub async fn heartbeat(self, heartbeat: Duration) {
        loop {
            time::sleep(heartbeat).await;

            if self.is_closed() {
                break;
            }

            if self.inner.task_connect_count() + self.inner.task_associate_count() == 0 {
                continue;
            }

            match self.inner.heartbeat().await {
                Ok(()) => tracing::debug!("[heartbeat]"),
                Err(err) => tracing::warn!("[heartbeat] {err}"),
            }
        }
    }

    pub async fn handle_packet(pkt: Packet) {
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
            "[packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] fragment {frag_id}/{frag_total}",
            frag_id = pkt.frag_id() + 1,
            frag_total = pkt.frag_total(),
        );
        todo!()
        // match pkt.accept().await {
        //     Ok(Some((pkt, addr, _))) => {
        //         tracing::info!("[relay] [packet] [{assoc_id:#06x}] [from-{mode}] [{pkt_id:#06x}] from {addr}");

        //         let addr = match addr {
        //             Address::None => unreachable!(),
        //             Address::DomainAddress(domain, port) => {
        //                 Socks5Address::DomainAddress(domain, port)
        //             }
        //             Address::SocketAddress(addr) => Socks5Address::SocketAddress(addr),
        //         };

        //         let session = SOCKS5_UDP_SESSIONS
        //             .get()
        //             .unwrap()
        //             .lock()
        //             .get(&assoc_id)
        //             .cloned();

        //         if let Some(session) = session {
        //             if let Err(err) = session.send(pkt, addr).await {
        //                 tracing::warn!(
        //                     "[relay] [packet] [{assoc_id:#06x}] [from-native] [{pkt_id:#06x}] failed sending packet to socks5 client: {err}",
        //                 );
        //             }
        //         } else {
        //             tracing::warn!("[relay] [packet] [{assoc_id:#06x}] [from-native] [{pkt_id:#06x}] unable to find socks5 associate session");
        //         }
        //     }
        //     Ok(None) => {}
        //     Err(err) => tracing::warn!("[relay] [packet] [{assoc_id:#06x}] [from-native] [{pkt_id:#06x}] packet receiving error: {err}"),
        // }
    }
}
