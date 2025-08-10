use crate::{Packet, stack::IfaceEvent};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_sender: mpsc::UnboundedSender<Packet>,
    rx_queue: mpsc::UnboundedReceiver<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

    iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl NetstackDevice {
    pub fn new(
        tx_sender: mpsc::Sender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1500;
        capabilities.medium = Medium::Ip;

        let (rx_sender, rx_queue) = mpsc::unbounded_channel::<Packet>();

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
            iface_notifier,
        }
    }

    pub fn create_injector(&self) -> mpsc::UnboundedSender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(
        &mut self,
        _timestamp: Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let (Ok(packet), Ok(permit)) =
            (self.rx_queue.try_recv(), self.tx_sender.try_reserve())
        {
            let rx_token = RxTokenImpl { packet };
            let tx_token = TxTokenImpl { tx_sender: permit };
            self.iface_notifier
                .send(IfaceEvent::DeviceReady)
                .expect("Failed to notify iface event");
            return Some((rx_token, tx_token));
        }

        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
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

pub struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
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
