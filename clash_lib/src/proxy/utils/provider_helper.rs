use crate::{
    app::remote_content_manager::providers::proxy_provider::ThreadSafeProxyProvider,
    proxy::AnyOutboundHandler,
};

pub async fn get_proxies_from_providers(
    providers: &Vec<ThreadSafeProxyProvider>,
    touch: bool,
) -> Vec<AnyOutboundHandler> {
    let mut proxies = vec![];
    for provider in providers {
        if touch {
            provider.read().await.touch().await;
        }

        let mut proxies_from_provider =
            provider.read().await.proxies().await.to_vec();
        proxies.append(&mut proxies_from_provider);
    }
    proxies
}
