use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use quinn_proto::congestion::{Bbr, BbrConfig, Controller, ControllerFactory};

pub struct DynCongestion;

impl ControllerFactory for DynCongestion {
    fn build(&self, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let bbr = Bbr::new(Arc::new(BbrConfig::default()), current_mtu);
        Box::new(DynController(Arc::new(RwLock::new(Box::new(bbr)))))
    }
}

struct Burtal;

impl Controller for Burtal {
    fn initial_window(&self) -> u64 {
        0
    }

    fn window(&self) -> u64 {
        999
    }

    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {}

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        _rtt: &quinn_proto::RttEstimator,
    ) {
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        unreachable!()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        unreachable!()
    }
}

pub struct DynController(Arc<RwLock<Box<dyn Controller>>>);
unsafe impl Send for DynController {}

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
        self.0
            .write()
            .unwrap()
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.0
            .write()
            .unwrap()
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
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

#[test]
fn test_dyn() {
    let r = DynCongestion.build(Instant::now(), 1);
    let r = r
        .clone_box()
        .into_any()
        .downcast::<DynController>()
        .unwrap();

    println!("{:?}", r.0.read().unwrap().window());

    let b = Box::new(Burtal);
    *r.0.write().unwrap() = b;

    assert!(r.window() == 999);
}
