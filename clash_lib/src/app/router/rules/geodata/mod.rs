use std::fmt::{Display, Formatter};
use std::path::Path;
use prost::Message;
use crate::app::router::RuleMatcher;
use crate::session::Session;

pub(crate) mod geodata_proto {
    include!(concat!(env!("OUT_DIR"), "/geodata.rs"));
}

use geodata_proto::*;
use crate::app::router::rules::geodata::attribute::{AndAttrMatcher, AttrMatcher};
use crate::app::router::rules::geodata::matcher_group::{DomainGroupMatcher, SuccinctMatcherGroup};

mod strmatcher;
mod matcher_group;
mod attribute;

pub struct CachedGeoDataLoader {
    cache: GeoSiteList,
}

impl CachedGeoDataLoader {
    pub async fn try_new(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bytes = tokio::fs::read(path).await?;
        let cache = GeoSiteList::decode(bytes.as_slice())?;
        Ok(Self {
            cache
        })
    }

    pub fn get(&self, list: &str) -> Option<&GeoSite> {
        self.cache.entry.iter().find(|x| x.country_code.eq_ignore_ascii_case(list))
    }
}

// if country_code is empty, return None
// or will return the parsed **real** code and the attr list and if the code is negated
fn parse(country_code: &str) -> Option<(bool, String, Box<dyn AttrMatcher>)> {
    let country_code = country_code.trim().to_lowercase();
    let mut country_code = country_code.as_str();
    let mut not = false;

    if country_code.is_empty() {
        return None;
    }

    if country_code.as_bytes()[0] == b'!' {
        not = true;
        country_code = &country_code[1..];
    }
    let parts = country_code.split('@').collect::<Vec<&str>>();
    let code = parts[0].to_owned();
    let attrs = if parts.len() > 1 {
        parts[1].split(',').map(|x| x.to_owned()).collect()
    } else {
        Vec::new()
    };
    let attr_matcher = Box::new(AndAttrMatcher::from(attrs)) as _;

    Some((not, code, attr_matcher))
}

pub struct GeoSiteMatcher {
    pub country_code: String,
    pub target: String,
    pub matcher: Box<dyn DomainGroupMatcher>,
}

impl GeoSiteMatcher {
    pub fn new(country_code: &str, target: &str, loader: &CachedGeoDataLoader) -> anyhow::Result<Self> {
        let (not, code, attr_matcher) = parse(country_code).unwrap();
        let list = loader.get(&code).cloned().unwrap();
        let domains = list.domain.into_iter().filter(|domain|
        attr_matcher.matches(domain)
        ).collect::<Vec<_>>();

        let matcher_group: Box<dyn DomainGroupMatcher> = Box::new(SuccinctMatcherGroup::try_new(domains, not).unwrap());
        Ok(Self { country_code: country_code.to_string(), target: target.to_string(), matcher: matcher_group })
    }
}

impl Display for GeoSiteMatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GeoSite({})", self.country_code)
    }
}

impl RuleMatcher for GeoSiteMatcher {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            crate::session::SocksAddr::Ip(_) => false,
            crate::session::SocksAddr::Domain(domain, _) => self.matcher.apply(domain.as_str()),
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.country_code.clone()
    }

    fn type_name(&self) -> &str {
        "GeoSite"
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use async_recursion::async_recursion;
    use hyper::body::HttpBody;
    use crate::app::dns::SystemResolver;
    use crate::app::router::rules::geodata::{CachedGeoDataLoader, parse};
    use crate::app::router::rules::geodata::matcher_group::{SuccinctMatcherGroup, DomainGroupMatcher};
    use crate::common::errors::new_io_error;
    use crate::common::http::{HttpClient, new_http_client};
    use crate::Error;

    const GEOSITE_URL: &str =
        "https://github.com/Watfaq/v2ray-rules-dat/releases/download/test/geosite.dat";

    #[async_recursion]
    async fn download(url: &str, out: &mut File, http_client: &HttpClient) -> anyhow::Result<usize> {
        let uri = url.parse::<hyper::Uri>()?;

        let mut res = http_client.get(uri).await?;

        if res.status().is_redirection() {
            return download(
                res.headers()
                    .get("Location")
                    .ok_or(new_io_error(
                        format!("failed to download from {}", url).as_str(),
                    ))?
                    .to_str()?,
                out,
                http_client,
            )
                .await;
        }

        if !res.status().is_success() {
            return Err(
                Error::InvalidConfig(format!("{} download failed: {}", url, res.status())).into(),
            );
        }

        let mut size = 0;
        while let Some(chunk) = res.body_mut().data().await {
            let chunk = chunk?;
            size += chunk.len();
            out.write_all(&chunk)?;
        }
        out.flush()?;

        Ok(size)
    }

    async fn prepare_geodata() -> anyhow::Result<String> {
        std::env::set_var("GEOSITE_FILE", "/tmp/geosite.dat");
        let local_file = std::env::var("GEOSITE_FILE");

        Ok(match local_file {
            Ok(path) => {
                path
            }
            Err(_) => {
                let system_resolver =
                    Arc::new(SystemResolver::new().map_err(|x| Error::DNSError(x.to_string())).unwrap());
                let client = new_http_client(system_resolver).map_err(|x| Error::DNSError(x.to_string())).unwrap();
                let mut out = tempfile::Builder::new()
                    .append(true)
                    .tempfile()?;
                let _ = download(GEOSITE_URL, out.as_file_mut(), &client).await?;
                let geosite_bytes = tokio::fs::read(out.as_ref()).await?;
                out.path().to_str().unwrap().to_owned()
            }
        })
    }

    struct TestSuite<'a> {
        country_code: &'a str,
        expected_results: Vec<(&'a str, bool)>,
    }


    #[tokio::test]
    async fn test_read_from_url() -> anyhow::Result<()> {
        let path = prepare_geodata().await?;
        let loader = CachedGeoDataLoader::try_new(path).await?;

        let suites = [
            TestSuite {
                country_code: "CN",
                expected_results: vec![
                    ("www.bilibili.com", true),
                    ("www.baidu.com", true),
                    ("www.youtube.com", false),
                    ("www.google.com", false),
                ],
            },
            TestSuite {
                country_code: "microsoft@cn",
                expected_results: vec![
                    ("www.microsoft.com", true),
                    ("dcg.microsoft.com", true),
                    ("www.bilibili.com", false),
                ],
            },
            TestSuite {
                country_code: "youtube",
                expected_results: vec![
                    ("www.youtube.com", true),
                    ("www.bilibili.com", false),
                ],
            },
            TestSuite {
                country_code: "!youtube",
                expected_results: vec![
                    ("www.youtube.com", false),
                    ("www.bilibili.com", true),
                ],
            },
        ];

        for suite in suites.iter() {
            // the same code of GeoMatcher
            let (not, code, attr_matcher) = parse(suite.country_code).unwrap();
            let list = loader.get(&code).cloned().unwrap();
            let domains = list.domain.into_iter().filter(|domain|
            attr_matcher.matches(domain)
            ).collect::<Vec<_>>();

            let matcher_group: Box<dyn DomainGroupMatcher> = Box::new(SuccinctMatcherGroup::try_new(domains, not).unwrap());

            for (domain, expected) in suite.expected_results.iter() {
                assert_eq!(matcher_group.apply(domain), *expected);
            }
        }

        Ok(())
    }
}
