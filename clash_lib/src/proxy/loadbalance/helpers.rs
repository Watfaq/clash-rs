use std::io::Cursor;

use futures::future::BoxFuture;
use murmur3::murmur3_32;
use public_suffix::{EffectiveTLDProvider, DEFAULT_PROVIDER};

use crate::{proxy::AnyOutboundHandler, session::Session};

pub type StrategyFn = Box<
    dyn FnMut(
            Vec<AnyOutboundHandler>,
            &Session,
        ) -> BoxFuture<'static, std::io::Result<AnyOutboundHandler>>
        + Send
        + Sync,
>;

fn get_key(sess: &Session) -> String {
    match &sess.destination {
        crate::session::SocksAddr::Ip(addr) => addr.ip().to_string(),
        crate::session::SocksAddr::Domain(host, _) => DEFAULT_PROVIDER
            .effective_tld_plus_one(&host)
            .map(|s| s.to_string())
            .unwrap_or_default(),
    }
}

fn jump_hash(key: u64, buckets: i32) -> i32 {
    let mut key = key;
    let mut b = -1i64;
    let mut j = 0i64;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b + 1) as f64 * (1i64 << 31) as f64 / ((key >> 33) + 1) as f64) as i64;
    }
    b as i32
}

pub fn strategy_rr() -> StrategyFn {
    let mut index = 0;
    Box::new(move |proxies: Vec<AnyOutboundHandler>, sess: &Session| {
        let len = proxies.len();
        index = (index + 1) % len;
        Box::pin(futures::future::ok(proxies[index].clone()))
    })
}

pub fn strategy_consistent_hashring() -> StrategyFn {
    let max_retry = 5;
    Box::new(move |proxies, sess| {
        let key = murmur3_32(&mut Cursor::new(get_key(&sess)), 0).unwrap() as u64;
        let buckets = proxies.len() as i32;
        for _ in 0..max_retry {
            let index = jump_hash(key, buckets);
            if let Some(proxy) = proxies.get(index as usize) {
                return Box::pin(futures::future::ok(proxy.clone()));
            }
        }
        return Box::pin(futures::future::err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no proxy found",
        )));
    })
}
