use crate::{
    app::remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    proxy::AnyOutboundHandler,
};
use std::collections::HashSet;

pub async fn get_proxies_from_providers(
    providers: &Vec<ThreadSafeProxyProvider>,
    touch: bool,
) -> Vec<AnyOutboundHandler> {
    let mut proxies = vec![];
    let mut proxy_names = HashSet::new();
    for provider in providers {
        let p = provider.read().await;
        if touch {
            p.touch().await;
        }

        let mut proxies_from_provider = p.proxies().await.to_vec();

        proxies_from_provider.retain(|p| proxy_names.insert(p.name().to_owned()));

        proxies.append(&mut proxies_from_provider);
    }
    proxies
}
