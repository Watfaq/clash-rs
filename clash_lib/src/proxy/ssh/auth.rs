use std::{collections::HashSet, io, ops::Deref, sync::Arc};

use async_trait::async_trait;
use russh::{
    client::{AuthResult, Handle, Prompt},
    keys::{load_secret_key, PrivateKey, PrivateKeyWithHashAlg},
    MethodKind,
};

use crate::common::errors::new_io_error;

use super::{connector::Client, HandlerOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MethodKindAdapter {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
}

impl From<MethodKind> for MethodKindAdapter {
    fn from(value: MethodKind) -> Self {
        match value {
            MethodKind::None => MethodKindAdapter::None,
            MethodKind::Password => MethodKindAdapter::Password,
            MethodKind::PublicKey => MethodKindAdapter::PublicKey,
            MethodKind::HostBased => MethodKindAdapter::HostBased,
            MethodKind::KeyboardInteractive => {
                MethodKindAdapter::KeyboardInteractive
            }
        }
    }
}

impl From<MethodKindAdapter> for MethodKind {
    fn from(value: MethodKindAdapter) -> Self {
        match value {
            MethodKindAdapter::None => MethodKind::None,
            MethodKindAdapter::Password => MethodKind::Password,
            MethodKindAdapter::PublicKey => MethodKind::PublicKey,
            MethodKindAdapter::HostBased => MethodKind::HostBased,
            MethodKindAdapter::KeyboardInteractive => {
                MethodKind::KeyboardInteractive
            }
        }
    }
}

const PASSWORD_PROMPT: &str = "Password: ";
const VERIFICATION_CODE_PROMPT: &str = "Verification code: ";

pub async fn authenticate(
    client: &mut Handle<Client>,
    opts: &HandlerOptions,
) -> core::result::Result<AuthResult, russh::Error> {
    let mut auth: &dyn Auth = &NoneAuth;
    let mut tried: HashSet<MethodKindAdapter> = HashSet::new();

    let prompt_handler = move |name: String,
                               _: String,
                               prompts: Vec<Prompt>,
                               opts: &HandlerOptions|
          -> Vec<String> {
        tracing::trace!(
            "ssh interactive auth, name: {}, prompts: {:?}",
            name,
            prompts
        );
        if prompts.iter().any(|p| p.prompt.contains(PASSWORD_PROMPT)) {
            opts.password.clone().map(|p| vec![p]).unwrap_or_default()
        } else if prompts
            .iter()
            .any(|p| p.prompt.contains(VERIFICATION_CODE_PROMPT))
        {
            opts.totp
                .clone()
                .map(|t| t.generate_current().unwrap())
                .map(|t| vec![t])
                .unwrap_or_default()
        } else {
            vec![]
        }
    };
    let config_auth = vec![
        Box::new(PasswordAuth) as Box<dyn Auth>,
        Box::new(PublicKeyAuth) as Box<dyn Auth>,
        Box::new(KeyboardInteractiveAuth {
            handler: prompt_handler,
            mac_retry: 5,
        }) as Box<dyn Auth>,
    ];
    loop {
        let result = auth.auth(client, opts).await;
        tracing::trace!(
            "trying method: {:?}, ssh auth result: {:?}",
            auth.method(),
            result
        );
        let remaining_methods: Vec<MethodKindAdapter> = match result {
            Ok(AuthResult::Success) => return Ok(AuthResult::Success),
            Ok(AuthResult::Failure {
                remaining_methods: methods,
            }) => {
                tried.insert(auth.method().into());
                methods
                    .deref()
                    .iter()
                    .map(|m| (*m).into())
                    .collect::<Vec<_>>()
            }
            Err(e) => return Err(e),
        };

        let mut find = false;

        // find next method
        'outer: for a in &config_auth {
            let method = a.method().into();
            if tried.contains(&method) {
                continue;
            }

            for remaining_method in &remaining_methods {
                if *remaining_method == method {
                    auth = a.as_ref();
                    find = true;
                    break 'outer;
                }
            }
        }
        if !find {
            return Err(russh::Error::NoAuthMethod);
        }
    }
}

#[async_trait]
trait Auth: Send + Sync {
    fn method(&self) -> russh::MethodKind;

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        opts: &HandlerOptions,
    ) -> core::result::Result<AuthResult, russh::Error>;
}

struct NoneAuth;

#[async_trait]
impl Auth for NoneAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::None
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        opts: &HandlerOptions,
    ) -> core::result::Result<AuthResult, russh::Error> {
        client.authenticate_none(opts.username.clone()).await
    }
}

struct PasswordAuth;

#[async_trait]
impl Auth for PasswordAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::Password
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        opts: &HandlerOptions,
    ) -> core::result::Result<AuthResult, russh::Error> {
        match opts.password.clone() {
            None => return Err(russh::Error::NoAuthMethod),
            Some(password) => {
                client
                    .authenticate_password(opts.username.clone(), password)
                    .await
            }
        }
    }
}

struct PublicKeyAuth;

#[async_trait]
impl Auth for PublicKeyAuth {
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::PublicKey
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        opts: &HandlerOptions,
    ) -> core::result::Result<AuthResult, russh::Error> {
        let private_key = load_private_key(opts);
        match private_key {
            Err(_) => return Err(russh::Error::CouldNotReadKey),
            Ok(private_key) => {
                client
                    .authenticate_publickey(
                        &opts.username,
                        PrivateKeyWithHashAlg::new(
                            Arc::new(private_key),
                            client
                                .best_supported_rsa_hash()
                                .await
                                .unwrap()
                                .flatten(),
                        ),
                    )
                    .await
            }
        }
    }
}

fn load_private_key(opts: &HandlerOptions) -> io::Result<PrivateKey> {
    let key_path_or_content = match opts.private_key.clone() {
        Some(key_path) => key_path,
        None => return Err(new_io_error("private key not found")),
    };
    if key_path_or_content.contains("PRIVATE KEY") {
        // raw content
        PrivateKey::from_openssh(&key_path_or_content)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    } else {
        // file path
        let key_path = if key_path_or_content.starts_with("~") {
            let home = dirs::home_dir()
                .ok_or_else(|| new_io_error("home directory not found"))?;
            key_path_or_content.replacen(
                "~",
                home.to_str()
                    .ok_or_else(|| new_io_error("home directory not found"))?,
                1,
            )
        } else {
            key_path_or_content
        };
        load_secret_key(key_path, opts.private_key_passphrase.as_deref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

struct KeyboardInteractiveAuth<T> {
    mac_retry: u32,
    handler: T,
}

// (name, instruction, prompts) -> response

#[async_trait]
impl<T> Auth for KeyboardInteractiveAuth<T>
where
    T: Sync + Send + Fn(String, String, Vec<Prompt>, &HandlerOptions) -> Vec<String>,
{
    fn method(&self) -> russh::MethodKind {
        russh::MethodKind::KeyboardInteractive
    }

    async fn auth(
        &self,
        client: &mut Handle<Client>,
        opts: &HandlerOptions,
    ) -> core::result::Result<AuthResult, russh::Error> {
        let start_resp = client
            .authenticate_keyboard_interactive_start(&opts.username, None)
            .await;

        let mut resp = start_resp;
        let mut tried = 0;
        loop {
            if tried >= self.mac_retry {
                return Err(russh::Error::NoAuthMethod);
            }
            tracing::debug!("KeyboardInteractiveAuth loop, resp: {:?}", resp);
            match resp {
                Ok(r) => {
                    match r {
                        russh::client::KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
                        russh::client::KeyboardInteractiveAuthResponse::Failure{remaining_methods} => return Ok(AuthResult::Failure{remaining_methods}),
                        russh::client::KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                            let response = (self.handler)(name, instructions, prompts, opts);
                            resp = client.authenticate_keyboard_interactive_respond(response).await;
                            tried += 1;
                        },
                    }
                },
                Err(e) => return Err(e),
            }
        }
    }
}
