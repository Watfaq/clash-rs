#[macro_export]
macro_rules! impl_default_connector {
    ($handler:ident) => {
        #[async_trait]
        impl DialWithConnector for $handler {
            fn support_dialer(&self) -> Option<&str> {
                self.opts.common_opts.connector.as_deref()
            }

            async fn register_connector(&self, connector: Arc<dyn RemoteConnector>) {
                let mut m = self.connector.lock().await;
                *m = Some(connector);
            }
        }
    };
}
