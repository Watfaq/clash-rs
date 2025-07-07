use russh::{client, keys::ssh_key};

pub struct Client {
    pub server_public_key: Option<Vec<ssh_key::PublicKey>>,
}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match self.server_public_key {
            None => Ok(true),
            Some(ref key) if key.iter().any(|k| k == server_public_key) => Ok(true),
            _ => Err(russh::Error::UnknownKey),
        }
    }
}
