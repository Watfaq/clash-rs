use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use http::Uri;

use tower::Service;

use crate::{
    app::ThreadSafeDNSResolver,
    proxy::{AnyOutboundHandler, AnyStream},
    session::Session,
};

#[derive(Clone)]
pub struct LocalConnector(pub AnyOutboundHandler, pub ThreadSafeDNSResolver);

impl Service<Uri> for LocalConnector {
    type Response = AnyStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, remote: Uri) -> Self::Future {
        let port = remote.port_u16().unwrap_or(match remote.scheme_str() {
            None => 80,
            Some(s) => match s {
                s if s == "http" => 80,
                s if s == "https" => 443,
                _ => panic!("invalid url: {}", remote),
            },
        });

        let sess = Session {
            destination: (remote.to_string(), port)
                .try_into()
                .expect(format!("invalid url: {}", remote.to_string()).as_str()),
            ..Default::default()
        };
        let handler = self.0.clone();
        let resolver = self.1.clone();

        Box::pin(async move { handler.connect_stream(&sess, resolver).await })
    }
}
