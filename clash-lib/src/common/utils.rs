use async_recursion::async_recursion;
use futures::StreamExt;
use http_body_util::BodyDataStream;
use std::{
    fmt::Write,
    num::ParseIntError,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{Error, common::errors::new_io_error};
use rand::{
    Fill, Rng,
    distr::uniform::{SampleRange, SampleUniform},
};
use sha2::Digest;
use tracing::debug;

pub fn rand_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    let mut rng = rand::rng();
    rng.random_range(range)
}

pub fn rand_fill<T>(buf: &mut T)
where
    T: Fill + ?Sized,
{
    let mut rng = rand::rng();
    rng.fill(buf)
}

#[allow(dead_code)]
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn md5_str(bytes: &[u8]) -> String {
    let mut hasher = md5::Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Default value true for bool on serde
/// use this if you don't want do deal with Option<bool>
/// Use Default::default() for false
pub fn default_bool_true() -> bool {
    true
}

#[async_recursion]
pub async fn download<P>(
    url: &str,
    path: P,
    http_client: &HttpClient,
) -> anyhow::Result<()>
where
    P: AsRef<Path> + std::marker::Send,
{
    use std::io::Write;

    let uri = url.parse::<hyper::Uri>()?;
    let mut out = std::fs::File::create(&path)?;

    let res = http_client.get(uri).await?;

    if res.status().is_redirection() {
        return download(
            res.headers()
                .get("Location")
                .ok_or(new_io_error(
                    format!("failed to download from {}", url).as_str(),
                ))?
                .to_str()?,
            path,
            http_client,
        )
        .await;
    }

    if !res.status().is_success() {
        return Err(Error::InvalidConfig(format!(
            "data download failed: {}",
            res.status()
        ))
        .into());
    }

    debug!("downloading data to {}", path.as_ref().to_string_lossy());

    let mut stream = BodyDataStream::new(res.into_body());
    while let Some(chunk) = stream.next().await {
        out.write_all(&chunk?)?;
    }

    Ok(())
}

use super::http::HttpClient;
