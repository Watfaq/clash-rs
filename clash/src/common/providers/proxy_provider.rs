use crate::common::providers::Provider;
use crate::config::internal::proxy::OutboundProxy;



pub trait ProxyProvider: Provider {
    fn proxies(&self) -> Vec<OutboundProxy>;
    fn touch(&self);
    fn healthcheck(&self);
}
