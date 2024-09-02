use async_recursion::async_recursion;
use std::{fmt::Write, num::ParseIntError, path::Path};

use crate::{common::errors::new_io_error, Error};
use rand::{
    distributions::uniform::{SampleRange, SampleUniform},
    Fill, Rng,
};
use sha2::Digest;
use tracing::debug;

pub fn rand_range<T, R>(range: R) -> T
where
    T: SampleUniform,
    R: SampleRange<T>,
{
    let mut rng = rand::thread_rng();
    rng.gen_range(range)
}

pub fn rand_fill<T>(buf: &mut T)
where
    T: Fill + ?Sized,
{
    let mut rng = rand::thread_rng();
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

    let mut res = http_client.get(uri).await?;

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

    while let Some(chunk) = res.body_mut().data().await {
        out.write_all(&chunk?)?;
    }

    Ok(())
}

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;

use super::http::HttpClient;

pub fn load_cert_chain(
    cert_path: &Path,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let cert_chain =
        fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        vec![CertificateDer::from(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };
    Ok(cert_chain)
}

pub fn load_priv_key(key_path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let key = fs::read(key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .context("malformed PKCS #1 private key")?
            .ok_or_else(|| anyhow::Error::msg("no private keys found"))?
    };
    Ok(key)
}
