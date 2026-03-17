use std::str::FromStr;

use url::Url;

use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RigbyUri {
    pub server_static_pubkey: String,
    pub host: String,
    pub port: u16,
    pub sni: Option<String>,
    pub padding: bool,
    pub mux: bool,
}

impl RigbyUri {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let url = Url::parse(input)
            .map_err(|e| Error::InvalidConfig(format!("invalid rigby URI: {e}")))?;
        if url.scheme() != "rigby" {
            return Err(Error::InvalidConfig(
                "rigby URI must start with rigby://".to_string(),
            ));
        }

        let server_static_pubkey = url.username().trim().to_string();
        if server_static_pubkey.is_empty() {
            return Err(Error::InvalidConfig(
                "rigby URI missing server static public key".to_string(),
            ));
        }

        let host = url
            .host_str()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Error::InvalidConfig("rigby URI missing host".to_string())
            })?
            .to_string();
        let port = url.port().ok_or_else(|| {
            Error::InvalidConfig("rigby URI missing port".to_string())
        })?;
        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        let sni = query.get("sni").cloned().filter(|v| !v.trim().is_empty());
        let padding = parse_bool(query.get("padding").map(String::as_str), true)?;
        let mux = parse_bool(query.get("mux").map(String::as_str), true)?;

        Ok(Self {
            server_static_pubkey,
            host,
            port,
            sni,
            padding,
            mux,
        })
    }
}

impl FromStr for RigbyUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn parse_bool(value: Option<&str>, default: bool) -> Result<bool, Error> {
    let Some(raw) = value else {
        return Ok(default);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => Ok(default),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::InvalidConfig(format!(
            "invalid boolean value: {raw}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::RigbyUri;

    #[test]
    fn parse_rigby_uri() {
        let uri = RigbyUri::parse(
            "rigby://abc123@example.com:8443?sni=cdn.example.com&padding=true&mux=false",
        )
        .unwrap();
        assert_eq!(uri.server_static_pubkey, "abc123");
        assert_eq!(uri.host, "example.com");
        assert_eq!(uri.port, 8443);
        assert_eq!(uri.sni.as_deref(), Some("cdn.example.com"));
        assert!(uri.padding);
        assert!(!uri.mux);
    }
}
