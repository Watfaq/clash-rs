use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};

use crate::{
    Error,
    config::internal::proxy::OutboundRigby,
    proxy::{
        HandlerCommonOptions,
        rigby::{Handler, HandlerOptions},
    },
};

fn decode_key32(raw: &str, field: &str) -> Result<[u8; 32], Error> {
    let text = raw.trim();
    let candidates = [
        URL_SAFE_NO_PAD.decode(text).ok(),
        URL_SAFE.decode(text).ok(),
        STANDARD_NO_PAD.decode(text).ok(),
        STANDARD.decode(text).ok(),
        hex::decode(text).ok(),
    ];

    for bytes in candidates.into_iter().flatten() {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }

    Err(Error::InvalidConfig(format!(
        "{field} must be a 32-byte key encoded as base64/base64url/hex"
    )))
}

impl TryFrom<OutboundRigby> for Handler {
    type Error = Error;

    fn try_from(value: OutboundRigby) -> Result<Self, Self::Error> {
        let server_static_pubkey =
            decode_key32(&value.server_static_pubkey, "rigby server-static-pubkey")?;
        let client_private_key = value
            .client_private_key
            .as_deref()
            .map(|v| decode_key32(v, "rigby client-private-key"))
            .transpose()?;

        Ok(Handler::new(HandlerOptions {
            name: value.common_opts.name.clone(),
            common_opts: HandlerCommonOptions {
                connector: value.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: value.common_opts.server,
            port: value.common_opts.port,
            server_static_pubkey,
            client_private_key,
            sni: value.sni,
            padding: value.padding,
            mux: value.mux,
            udp: value.udp,
        }))
    }
}
