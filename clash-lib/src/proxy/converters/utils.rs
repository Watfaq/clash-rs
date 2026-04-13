use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::uri::InvalidUri;

use crate::{
    Error,
    config::proxy::{CommonConfigOptions, GrpcOpt, H2Opt, WsOpt},
    proxy::transport::{self, GrpcClient, H2Client, WsClient},
};

impl TryFrom<(&WsOpt, &CommonConfigOptions)> for WsClient {
    type Error = std::io::Error;

    fn try_from(pair: (&WsOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let headers = x.headers.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let max_early_data = x.max_early_data.unwrap_or_default() as usize;
        let early_data_header_name = x
            .early_data_header_name
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or_default();

        let client = transport::WsClient::new(
            common.server.to_owned(),
            common.port,
            path,
            headers,
            None,
            max_early_data,
            early_data_header_name,
        );
        Ok(client)
    }
}

impl TryFrom<(Option<String>, &GrpcOpt, &CommonConfigOptions)> for GrpcClient {
    type Error = InvalidUri;

    fn try_from(
        opt: (Option<String>, &GrpcOpt, &CommonConfigOptions),
    ) -> Result<Self, Self::Error> {
        let (sni, x, common) = opt;
        let client = transport::GrpcClient::new(
            sni.as_ref().unwrap_or(&common.server).to_owned(),
            x.grpc_service_name
                .as_ref()
                .map(|x| x.to_owned())
                .unwrap_or_default()
                .try_into()?,
        );
        Ok(client)
    }
}

impl TryFrom<(&H2Opt, &CommonConfigOptions)> for H2Client {
    type Error = InvalidUri;

    fn try_from(pair: (&H2Opt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .host
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or(vec![common.server.to_owned()]);
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();

        Ok(H2Client::new(
            host,
            std::collections::HashMap::new(),
            http::Method::GET,
            path.try_into()?,
        ))
    }
}

pub fn decode_base64_public_key(base64_public_key: &str) -> Result<[u8; 32], Error> {
    URL_SAFE_NO_PAD
        .decode(base64_public_key)
        .map_err(|e| {
            Error::InvalidConfig(format!("reality public-key base64: {e}"))
        })?
        .try_into()
        .map_err(|_| {
            Error::InvalidConfig("reality public-key must decode to 32 bytes".into())
        })
}

pub fn decode_short_id(hex_short_id: &str) -> Result<Vec<u8>, Error> {
    hex::decode(hex_short_id)
        .map_err(|e| Error::InvalidConfig(format!("reality short-id hex: {e}")))
}
