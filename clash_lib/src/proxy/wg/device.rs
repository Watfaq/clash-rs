use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bytes::Bytes;

use super::events::BusSender;

pub struct VirtualIpDevice {
    mtu: usize,
    bus_sender: BusSender,
    queue: Arc<Mutex<VecDeque<Bytes>>>,
}
