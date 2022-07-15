use crate::app::ThreadSafeAsyncDnsClient;

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub dns_client: ThreadSafeAsyncDnsClient,
}


