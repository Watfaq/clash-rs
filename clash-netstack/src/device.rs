use crate::Packet;
use smoltcp::{
    phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
    },
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_sender: mpsc::UnboundedSender<Packet>,
    rx_queue: mpsc::UnboundedReceiver<Packet>,

    tx_sender: mpsc::UnboundedSender<Packet>,
    capabilities: DeviceCapabilities,
}

impl NetstackDevice {
    pub fn new(tx_sender: mpsc::UnboundedSender<Packet>) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1500;
        capabilities.medium = Medium::Ip;
        capabilities.checksum = ChecksumCapabilities::ignored();

        let (rx_sender, rx_queue) = mpsc::unbounded_channel::<Packet>();

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
        }
    }

    pub fn inject_packet(&self, packet: Packet) {
        if let Err(err) = self.rx_sender.send(packet) {
            log::warn!("Failed to inject packet: {err}");
        }
    }

    pub fn create_injector(&self) -> mpsc::UnboundedSender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl;

    fn receive(
        &mut self,
        _timestamp: Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.try_recv().ok() {
            let rx_token = RxTokenImpl { packet };
            let tx_token = TxTokenImpl {
                tx_sender: self.tx_sender.clone(),
            };
            return Some((rx_token, tx_token));
        }

        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl {
            tx_sender: self.tx_sender.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl {
    tx_sender: mpsc::UnboundedSender<Packet>,
}

impl TxToken for TxTokenImpl {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        let packet = Packet::new(buffer);
        let _ = self.tx_sender.send(packet);

        result
    }
}
