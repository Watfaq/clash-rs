use std::{
    fs,
    io::Cursor,
    path::{Component, Path, PathBuf},
};

use rand::Rng;
use tracing::{info, warn};

use crate::{
    Error,
    common::{http::HttpClient, utils::download},
};

/// Downloads and extracts a dashboard archive (zip or tgz) to `dir`.
///
/// The download is skipped when `dir` already exists and is non-empty,
/// unless the URL fragment contains `force=true`.
pub async fn download_dashboard<P: AsRef<Path>>(
    dir: P,
    download_url: &str,
    http_client: &HttpClient,
) -> Result<(), Error> {
    let dir = dir.as_ref();

    let needs_download = !dir.exists()
        || dir.read_dir().map_or(true, |mut d| d.next().is_none())
        || download_url.contains("force=true");

    if !needs_download {
        return Ok(());
    }

    info!("downloading dashboard from {}", download_url);

    let rand_part: u64 = rand::rng().random();
    let tmp_path = dir
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("_dashboard_tmp_{rand_part:016x}"));

    download(download_url, &tmp_path, http_client)
        .await
        .map_err(|e| {
            Error::InvalidConfig(format!("dashboard download failed: {e}"))
        })?;

    let bytes = fs::read(&tmp_path)?;
    if let Err(e) = fs::remove_file(&tmp_path) {
        warn!(
            "failed to remove dashboard temp file {}: {}",
            tmp_path.display(),
            e
        );
    }

    // Replace target dir
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;

    // Strip URL fragment before checking the extension (e.g. url#force=true)
    let url_base = download_url.split('#').next().unwrap_or(download_url);
    if url_base.ends_with(".zip") || is_zip(&bytes) {
        extract_zip(&bytes, dir)?;
    } else {
        extract_tgz(&bytes, dir)?;
    }

    info!("dashboard extracted to {}", dir.display());
    Ok(())
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04])
}

/// Creates parent directory of `path` if it doesn't already exist.
fn ensure_parent(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn extract_zip(bytes: &[u8], target_dir: &Path) -> Result<(), Error> {
    let cursor = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| Error::InvalidConfig(format!("zip open failed: {e}")))?;

    // Detect a common single top-level directory to strip (e.g. "dist/")
    let strip_prefix: Option<String> = {
        let first = archive
            .by_index(0)
            .map(|f| f.name().split('/').next().unwrap_or("").to_string())
            .ok();
        match first {
            Some(ref prefix) if !prefix.is_empty() => {
                let all_share = (0..archive.len()).all(|i| {
                    archive
                        .by_index(i)
                        .map(|f| f.name().starts_with(prefix.as_str()))
                        .unwrap_or(false)
                });
                if all_share {
                    Some(format!("{prefix}/"))
                } else {
                    None
                }
            }
            _ => None,
        }
    };

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| Error::InvalidConfig(format!("zip entry failed: {e}")))?;

        // `enclosed_name` returns None for paths with ".." or absolute paths
        let enclosed = match file.enclosed_name() {
            Some(p) => p,
            None => continue,
        };

        // Strip the common prefix if present
        let rel: PathBuf = match strip_prefix {
            Some(ref prefix) => {
                let s = enclosed.to_string_lossy();
                PathBuf::from(s.strip_prefix(prefix.as_str()).unwrap_or(s.as_ref()))
            }
            None => enclosed.clone(),
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = target_dir.join(&rel);
        let is_dir = file.name().ends_with('/');
        if is_dir {
            fs::create_dir_all(&dest)?;
        } else {
            ensure_parent(&dest)?;
            let mut out = fs::File::create(&dest)?;
            std::io::copy(&mut file, &mut out)?;
        }
    }
    Ok(())
}

fn extract_tgz(bytes: &[u8], target_dir: &Path) -> Result<(), Error> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);

    for entry in archive
        .entries()
        .map_err(|e| Error::InvalidConfig(format!("tgz open failed: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| Error::InvalidConfig(format!("tgz entry failed: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Error::InvalidConfig(format!("tgz entry path: {e}")))?
            .to_path_buf();

        // Strip the leading top-level directory component
        let rel: PathBuf = path.components().skip(1).collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        // Guard against path traversal
        if rel
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
        {
            continue;
        }
        let dest = target_dir.join(&rel);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&dest)?;
        } else {
            ensure_parent(&dest)?;
            let mut out = fs::File::create(&dest)?;
            std::io::copy(&mut entry, &mut out)?;
        }
    }
    Ok(())
}
