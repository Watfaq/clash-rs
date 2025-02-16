use crate::Error;
use std::{path::PathBuf, sync::Arc};
use tracing::debug;

use crate::{
    app::{
        dns::{self, ClashResolver, SystemResolver},
        profile,
    },
    common::{http::new_http_client, mmdb},
    Config,
};

pub fn root_dir() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR").to_owned());
    // remove the clash_lib
    root.pop();
    root
}

pub fn test_config_base_dir() -> PathBuf {
    root_dir().join("clash/tests/data/config")
}

// load the config from test dir
// and return the dns resolver for the proxy
pub async fn build_dns_resolver() -> anyhow::Result<Arc<dyn ClashResolver>> {
    let root = root_dir();
    let test_base_dir = test_config_base_dir();
    let config_path = test_base_dir
        .join("empty.yaml")
        .to_str()
        .unwrap()
        .to_owned();
    let config = Config::File(config_path).try_parse()?;
    let mmdb_path = test_base_dir.join("Country.mmdb");
    let system_resolver = Arc::new(
        SystemResolver::new(false).map_err(|x| Error::DNSError(x.to_string()))?,
    );
    let client = new_http_client(system_resolver)
        .map_err(|x| Error::DNSError(x.to_string()))?;

    let mmdb = Arc::new(
        mmdb::Mmdb::new(mmdb_path, config.general.mmdb_download_url.clone(), client)
            .await?,
    );

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        root.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let dns_resolver = Arc::new(
        dns::EnhancedResolver::new(config.dns, cache_store.clone(), mmdb.clone())
            .await,
    );

    Ok(dns_resolver)
}
