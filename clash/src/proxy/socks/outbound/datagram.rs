use crate::app::ThreadSafeDNSResolver;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub dns_client: ThreadSafeDNSResolver,
}
