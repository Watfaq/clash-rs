use super::ThreadSafeProxy;

trait ProxyProvider {
    fn get_proxies(&self) -> anyhow::Result<Vec<ThreadSafeProxy>>;
}
