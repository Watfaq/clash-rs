use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use quinn_proto::congestion::{Bbr, BbrConfig, Controller, ControllerFactory};

#[allow(dead_code)]
pub struct DynCongestion;

impl ControllerFactory for DynCongestion {
    fn build(
        self: Arc<Self>,
        _now: Instant,
        current_mtu: u16,
    ) -> Box<dyn Controller> {
        let bbr = Bbr::new(Arc::new(BbrConfig::default()), current_mtu);
        Box::new(DynController(Arc::new(RwLock::new(Box::new(bbr)))))
    }
}

const SLOT_COUNT: u64 = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACKRATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: u64 = 2;
const INITIAL_PACKET_SIZE_IPV4: u64 = 1252;

#[derive(Copy, Clone)]
struct SlotInfo {
    time: u64,
    lost: u64,
    ack: u64,
}

pub struct Burtal {
    ack: u64,
    last_lost_packet_num: u64,
    slots: [SlotInfo; SLOT_COUNT as usize],
    ack_rate: f64,
    bps: u64,
    max_datagram_size: u64,
    last_send_time: Option<Instant>,
    budget_at_last_sent: u64,
    rtt: u64,
    in_flight: u64,
    #[allow(dead_code)]
    send_now: Instant,

    sess: quinn::Connection,
}

impl Burtal {
    pub fn new(bps: u64, sess: quinn::Connection) -> Self {
        Self {
            sess,
            ack: 0,
            max_datagram_size: INITIAL_PACKET_SIZE_IPV4,
            last_lost_packet_num: 0,
            slots: [SlotInfo {
                time: 0,
                lost: 0,
                ack: 0,
            }; SLOT_COUNT as usize],
            ack_rate: 0.0,
            bps,
            rtt: 0,
            last_send_time: None,
            budget_at_last_sent: 0,
            in_flight: 0,
            send_now: Instant::now(),
        }
    }

    fn get_bandwidth(&self) -> f64 {
        self.bps as f64 / self.ack_rate
    }
}

impl Controller for Burtal {
    fn initial_window(&self) -> u64 {
        self.window()
    }

    // https://github.com/quinn-rs/quinn/blob/55234e178fdca81cd51a5bfb520cb912de14f72e/quinn-proto/src/connection/mod.rs#L641
    // https://github.com/apernet/hysteria/blob/405572dc6e335c29ab28011bcfa9e0db2c45a4b4/core/internal/congestion/brutal/brutal.go#L72
    fn window(&self) -> u64 {
        if self.budget_at_last_sent >= self.max_datagram_size
            || self.last_send_time.is_none()
        {
            if self.rtt == 0 {
                return 10240;
            }
            ((self.bps * self.rtt * CONGESTION_WINDOW_MULTIPLIER) as f64
                / self.ack_rate) as u64
        } else {
            0
        }

        // let last_send_time = self.last_send_time.unwrap();
    }

    fn on_sent(&mut self, now: Instant, _bytes: u64, _last_packet_number: u64) {
        let max = (2000000.0 * self.get_bandwidth() / 1e9)
            .max((10 * self.max_datagram_size) as f64);
        let budget = if let Some(last_send_time) = self.last_send_time {
            let budget = self.budget_at_last_sent.saturating_add(
                now.duration_since(last_send_time).as_secs()
                    * self.get_bandwidth() as u64,
            );

            max.min(budget as f64)
        } else {
            max
        };

        if _bytes > budget as u64 {
            self.budget_at_last_sent = 0;
        } else {
            self.budget_at_last_sent = budget as u64 - _bytes;
        }
        self.last_send_time = Some(now);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = new_mtu as u64;
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.in_flight = in_flight;
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        let current_lost_packet_num = self.sess.stats().path.lost_packets;
        let t = sent.elapsed().as_secs();
        let idx = (t % SLOT_COUNT) as usize;
        if self.slots[idx].time != t {
            self.slots[idx].time = t;
            self.slots[idx].lost =
                current_lost_packet_num - self.last_lost_packet_num;
            self.slots[idx].ack = self.ack;
        } else {
            self.slots[idx].time = t;
            self.slots[idx].lost +=
                current_lost_packet_num - self.last_lost_packet_num;
            self.ack += self.ack;
        }

        self.last_lost_packet_num = current_lost_packet_num;
        self.ack = 0;

        let (ack, lost) = self.slots.iter().filter(|x| x.time < 5).fold(
            (0, 0),
            |(mut ack, mut lost), x| {
                ack += x.ack;
                lost += x.lost;
                (ack, lost)
            },
        );

        self.ack_rate = if ack + lost < MIN_SAMPLE_COUNT {
            1.0
        } else {
            match ack as f64 / (ack + lost) as f64 {
                x if x < MIN_ACKRATE => MIN_ACKRATE,
                x => x,
            }
        }
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get().as_secs();
        self.ack += 1;
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        unreachable!()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        unreachable!()
    }
}

pub struct DynController(Arc<RwLock<Box<dyn Controller>>>);
impl DynController {
    pub fn set_controller(&self, controller: Box<dyn Controller>) {
        *self.0.write().unwrap() = controller;
    }
}

impl Controller for DynController {
    fn initial_window(&self) -> u64 {
        self.0.read().unwrap().initial_window()
    }

    fn window(&self) -> u64 {
        self.0.read().unwrap().window()
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.0
            .write()
            .unwrap()
            .on_sent(now, bytes, last_packet_number)
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.0.write().unwrap().on_mtu_update(new_mtu)
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.0.write().unwrap().on_end_acks(
            now,
            in_flight,
            app_limited,
            largest_packet_num_acked,
        )
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.0.write().unwrap().on_congestion_event(
            now,
            sent,
            is_persistent_congestion,
            lost_bytes,
        )
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.0
            .write()
            .unwrap()
            .on_ack(now, sent, bytes, app_limited, rtt)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(DynController(self.0.clone()))
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
