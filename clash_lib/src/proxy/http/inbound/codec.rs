use bytes::Buf;
use http::{Method, Request};

use hyper::Body;
use tokio_util::codec::Decoder;

#[derive(thiserror::Error, Debug)]
pub enum HttpError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed http request: {0}")]
    Malformed(String),
}

static MAX_HEADER_SIZE_BYTES: usize = 1024 * 10;
const MAX_HEADERS: usize = 100;

pub struct ReqDecoder;

impl ReqDecoder {
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for ReqDecoder {
    type Item = Request<Body>;

    type Error = HttpError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];

        let mut req = httparse::Request::new(&mut headers);
        let bytes = src.as_ref();
        let mut consumed = 0;

        let rv = match req
            .parse(bytes)
            .map_err(|x| HttpError::Malformed(format!("invalid http headers: {}", x)))?
        {
            httparse::Status::Complete(n) => {
                consumed += n;

                let mut rv = http::Request::builder()
                    .method(
                        match req
                            .method
                            .ok_or(HttpError::Malformed("invalid http method".into()))?
                        {
                            "GET" => Method::GET,
                            "POST" => Method::POST,
                            "PUT" => Method::PUT,
                            "DELETE" => Method::DELETE,
                            "HEAD" => Method::HEAD,
                            "OPTIONS" => Method::OPTIONS,
                            "CONNECT" => Method::CONNECT,
                            "PATCH" => Method::PATCH,
                            "TRACE" => Method::TRACE,
                            _ => return Err(HttpError::Malformed("invalid http method".into())),
                        },
                    )
                    .version(
                        match req
                            .version
                            .ok_or(HttpError::Malformed("invalid http version".into()))?
                        {
                            1 => http::Version::HTTP_11,
                            _ => http::Version::HTTP_10,
                        },
                    )
                    .uri(req.path.unwrap())
                    .body(Body::empty())
                    .map_err(|e| HttpError::Malformed(e.to_string()))?;

                for h in req.headers.iter() {
                    rv.headers_mut().append(
                        http::header::HeaderName::from_bytes(h.name.as_bytes())
                            .map_err(|_| HttpError::Malformed("invalid http header name".into()))?,
                        http::header::HeaderValue::from_bytes(h.value.clone()).map_err(|_| {
                            HttpError::Malformed("invalid http header value".into())
                        })?,
                    );
                }

                Ok(Some(rv))
            }
            httparse::Status::Partial => {
                if bytes.len() > MAX_HEADER_SIZE_BYTES {
                    return Err(HttpError::Malformed("http header too large".into()));
                }

                Ok(None)
            }
        };

        src.advance(consumed);

        rv
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_http_header_codec() {
        use super::ReqDecoder;
        use bytes::BytesMut;
        use tokio_util::codec::Decoder;

        let mut codec = ReqDecoder::new();

        let mut buf = BytesMut::new();

        let data = b"GET /test HTTP/1.1\r\nHost: www.example.com\r\n";

        buf.extend_from_slice(data);

        let req = codec.decode(&mut buf).unwrap();

        assert!(req.is_none());

        let more_data = b"\r\nbody";
        buf.extend_from_slice(more_data);

        let req = codec.decode(&mut buf).unwrap();
        assert!(req.is_some());
        let req = req.unwrap();

        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(req.uri().path(), "/test");
        assert_eq!(req.version(), http::Version::HTTP_11);
        assert_eq!(req.headers().len(), 1);
        assert_eq!(
            req.headers().get("Host").unwrap(),
            http::HeaderValue::from_static("www.example.com")
        );
        assert_eq!(buf, "body".as_bytes());
    }
}
