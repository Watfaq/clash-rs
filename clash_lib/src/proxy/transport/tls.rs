use std::io;

use boring::ssl::{SslConnector, SslMethod};
use futures::TryFutureExt;

use serde::Serialize;

use crate::{common::errors::map_io_error, proxy::AnyStream};

#[derive(Serialize, Clone)]
pub struct TLSOptions {
    pub skip_cert_verify: bool,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
}

pub async fn wrap_stream(
    stream: AnyStream,
    opt: TLSOptions,
    expected_alpn: Option<&str>,
) -> io::Result<AnyStream> {
    let mut ssl = SslConnector::builder(SslMethod::tls()).map_err(map_io_error)?;

    if let Some(alpns) = opt.alpn.as_ref() {
        let wire = alpns
            .into_iter()
            .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
            .collect::<Vec<Vec<u8>>>()
            .concat();
        ssl.set_alpn_protos(&wire).map_err(map_io_error)?;
    }

    if opt.skip_cert_verify {
        ssl.set_verify(boring::ssl::SslVerifyMode::NONE);
    }

    let c = tokio_boring::connect(ssl.build().configure().unwrap(), &opt.sni, stream)
        .map_err(map_io_error)
        .await
        .and_then(|x| {
            if let Some(expected_alpn) = expected_alpn {
                if x.ssl().selected_alpn_protocol() != Some(expected_alpn.as_bytes()) {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "unexpected alpn protocol: {:?}, expected: {:?}",
                            x.ssl().selected_alpn_protocol(),
                            expected_alpn
                        ),
                    ));
                }
            }

            Ok(x)
        });
    c.map(|x| Box::new(x) as _)
}
