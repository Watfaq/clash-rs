use std::path::PathBuf;

use crate::common::providers::proxy_provider::ProxyProvider;

struct FileProvider {
    path: PathBuf,
}

impl FileProvider {
    pub fn new(path: String) -> anyhow::Result<Self> {
        let path = PathBuf::from(path);
        if !path.exists() {
            anyhow::bail!("{} does not exist", path.display());
        }
        Ok(Self { path })
    }
}

impl ProxyProvider for FileProvider {
    fn proxies(&self) -> Vec<crate::config::internal::proxy::OutboundProxy> {
        todo!()
    }

    fn touch(&self) {
        todo!()
    }

    fn healthcheck(&self) {
        todo!()
    }
}
