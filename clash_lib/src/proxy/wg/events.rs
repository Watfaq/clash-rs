use std::sync::{atomic::AtomicU32, Arc};

use bytes::Bytes;
use tracing::error;

/// Layer 7 protocols for ports.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PortProtocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
}

#[derive(Clone)]
pub struct Bus {
    counter: Arc<AtomicU32>,
    bus: tokio::sync::broadcast::Sender<(u32, Event)>,
}

impl Bus {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            counter: Arc::new(AtomicU32::new(0)),
            bus: tx,
        }
    }

    pub fn new_endpoint(&self) -> BusEndpoint {
        let id = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let tx = self.bus.clone();
        let rx = self.bus.subscribe();

        let tx = BusSender { id, tx };
        BusEndpoint { id, tx, rx }
    }
}

pub struct BusEndpoint {
    id: u32,
    tx: BusSender,
    rx: tokio::sync::broadcast::Receiver<(u32, Event)>,
}

impl BusEndpoint {
    /// Sends the event on the bus. Note that the messages sent by this endpoint won't reach itself.
    pub fn send(&self, event: Event) {
        self.tx.send(event)
    }

    /// Returns the unique sequential ID of this endpoint.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Awaits the next `Event` on the bus to be read.
    pub async fn recv(&mut self) -> Event {
        loop {
            match self.rx.recv().await {
                Ok((id, event)) => {
                    if id == self.id {
                        // If the event was sent by this endpoint, it is skipped
                        continue;
                    } else {
                        return event;
                    }
                }
                Err(_) => {
                    error!("Failed to read event bus from endpoint #{}", self.id);
                    return futures::future::pending().await;
                }
            }
        }
    }

    /// Creates a new sender for this endpoint that can be cloned.
    pub fn sender(&self) -> BusSender {
        self.tx.clone()
    }
}

/// Events that go on the bus between the local server, smoltcp, and WireGuard.
#[derive(Debug, Clone)]
pub enum Event {
    InboundInternetPacket(PortProtocol, Bytes),
    /// IP packet to be sent through the WireGuard tunnel as crafted by the virtual device.
    OutboundInternetPacket(Bytes),
}

#[derive(Clone)]
pub struct BusSender {
    id: u32,
    tx: tokio::sync::broadcast::Sender<(u32, Event)>,
}

impl BusSender {
    /// Sends the event on the bus. Note that the messages sent by this endpoint won't reach itself.
    pub fn send(&self, event: Event) {
        match self.tx.send((self.id, event)) {
            Ok(_) => {}
            Err(_) => error!("Failed to send event to bus from endpoint #{}", self.id),
        }
    }
}
