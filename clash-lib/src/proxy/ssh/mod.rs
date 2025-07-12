use std::{borrow::Cow, io, pin::Pin, sync::Arc, time::Duration};

use async_trait::async_trait;

mod auth;
mod connector;
use connector::Client;
use russh::{
    ChannelStream, Preferred,
    client::{self, Handle, Msg},
    kex::*,
    keys::Algorithm,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    app::{
        dispatcher::{
            BoxedChainedDatagram, BoxedChainedStream, ChainedStream,
            ChainedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    session::Session,
};

use super::{
    ConnectorType, DialWithConnector, HandlerCommonOptions, OutboundHandler,
    OutboundType, ProxyStream, utils::RemoteConnector,
};

/// Wrapper for `ChannelStream` for `Debug` trait
struct ChannelStreamWrapper {
    inner: ChannelStream<Msg>,
}

impl std::fmt::Debug for ChannelStreamWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelStreamWrapper").finish()
    }
}

impl AsyncRead for ChannelStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
#[derive(Debug)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub username: String,
    /// try public key first, then password
    pub password: Option<String>,
    /// TOTP secret, support full config and Rfc6238
    pub totp: Option<totp_rs::TOTP>,
    /// key content or path
    /// if contains "PRIVATE KEY", it's raw content, otherwise it's a file path
    /// if so, it can start with "~" to represent home directory,
    pub private_key: Option<String>,
    /// password to protect private key file when `private_key` is a file path
    pub private_key_passphrase: Option<String>,
    /// if empty, will not verify host key
    pub host_key: Option<Vec<String>>,
    /// supported host key algorithms:
    ///   * `ssh-ed25519`
    ///   * `rsa-sha2-256`
    ///   * `rsa-sha2-512`
    ///   * `ssh-rsa` ✨
    ///   * `ecdsa-sha2-nistp256` ✨
    ///   * `ecdsa-sha2-nistp384` ✨
    ///   * `ecdsa-sha2-nistp521` ✨
    pub host_key_algorithms: Option<Vec<Algorithm>>,
}

#[derive(Debug)]
pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::Mutex<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::Mutex::new(None),
        }
    }
}

/// default values defined in golang's crypto/ssh (used by mihomo)
/// https://github.com/golang/crypto/blob/9290511cd23ab9813a307b7f2615325e3ca98902/ssh/common.go#L65
const KEX_ALGORITHMS: &[Name] = &[
    CURVE25519,
    CURVE25519_PRE_RFC_8731,
    DH_GEX_SHA1,
    DH_GEX_SHA256,
    DH_G14_SHA1,
    DH_G14_SHA256,
    ECDH_SHA2_NISTP256,
    ECDH_SHA2_NISTP384,
    ECDH_SHA2_NISTP521,
    NONE,
    EXTENSION_SUPPORT_AS_CLIENT,
];

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Ssh
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        // key exchange algorithms
        let kex = Cow::Borrowed(KEX_ALGORITHMS);
        // host key algorithms
        let key = match self.opts.host_key_algorithms.clone() {
            Some(host_key_algorithms) => Cow::Owned(host_key_algorithms),
            None => Default::default(),
        };
        // TODO: make inactivity_timeout configurable
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred: Preferred {
                kex,
                key,
                ..Default::default()
            },
            ..<_>::default()
        };

        let config = Arc::new(config);

        let server_public_key = self.opts.host_key.as_ref().map(|x| {
            x.iter()
                .filter_map(|x| {
                    russh::keys::ssh_key::PublicKey::from_openssh(x).ok()
                })
                .collect::<Vec<_>>()
        });
        let sh = connector::Client { server_public_key };

        // TODO: adding fw_mark
        let mut session =
            client::connect(config, (self.opts.server.as_str(), self.opts.port), sh)
                .await
                .map_err(|ssh_e| io::Error::other(ssh_e))?;

        auth0(&mut session, &self.opts).await?;

        let dst = sess.destination.clone();
        let channel = session
            .channel_open_direct_tcpip(
                dst.host(),
                sess.destination.port() as _,
                "0.0.0.0",
                0,
            )
            .await
            .map_err(|ssh_e| io::Error::other(ssh_e))?;
        let s = Box::new(ChannelStreamWrapper {
            inner: channel.into_stream(),
        });
        let chained: ChainedStreamWrapper<Box<dyn ProxyStream>> =
            ChainedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedChainedDatagram> {
        Err(new_io_error("ssh udp is not implemented yet"))
    }
}

async fn auth0(
    client: &mut Handle<Client>,
    opts: &HandlerOptions,
) -> io::Result<()> {
    let res = auth::authenticate(client, opts).await;

    match res {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!("ssh auth failed: {:?}", e);
            Err(new_io_error("ssh auth failed"))
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::path::PathBuf;

    use aead::rand_core::SeedableRng;
    use russh::keys::HashAlg;
    use tempfile::tempdir;

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::proxy::utils::test_utils::{
        Suite,
        config_helper::test_config_base_dir,
        docker_runner::{DockerTestRunnerBuilder, MultiDockerTestRunner},
        run_test_suites_and_cleanup,
    };

    use super::*;

    const PASSWORD: &str = "123456789";

    /// equals to:
    /// docker run -d \
    /// --name=openssh-server \
    /// --hostname=openssh-server `#optional` \
    /// -e PUID=1000 \
    /// -e PGID=1000 \
    /// -e TZ=Etc/UTC \
    /// -e SUDO_ACCESS=true `#optional` \
    /// -e PASSWORD_ACCESS=true `#optional` \
    /// -e USER_PASSWORD=123456789 `#optional` \
    /// -e LOG_STDOUT= `#optional` \
    /// -p 2222:2222 \
    /// -v /tmp/.xxx/ssh:/config \
    /// --restart unless-stopped \
    /// docker.io/linuxserver/openssh-server:latest
    ///
    /// /tmp/.xxx is the temporary directory generated by tempfile.
    /// in `clash/test/config/ssh/.ssh``, we have test_ed25519, test_rsa (the
    /// pub keys are already put in the authorized_keys for further test).
    /// `clash/test/config/ssh/ssh_host_keys/sshd_config" will be used as
    /// `/config/sshd/sshd_config` in the container.
    /// before starting the container, we need to generate host key pairs in
    /// /tmp/.xxx/ssh/ssh_host_keys.
    async fn get_openssh_server_runner(
        ssh_config_path: PathBuf,
    ) -> anyhow::Result<DockerTestRunner> {
        let password = format!("USER_PASSWORD={}", PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OPENSSH)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SUDO_ACCESS=true",
                "PASSWORD_ACCESS=true",
                &password,
            ])
            .mounts(&[(ssh_config_path.to_str().unwrap(), "/config")])
            .port(2222)
            .build()
            .await
    }

    fn gen_ssh_key_pair(
        algo: russh::keys::Algorithm,
    ) -> anyhow::Result<(String, String)> {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed(Default::default());
        let ssh_private_key = russh::keys::PrivateKey::random(&mut rng, algo)?;
        let ssh_public_key = ssh_private_key.public_key();

        let ssh_private_key_str = ssh_private_key
            .to_openssh(ring_compat::pkcs8::LineEnding::LF)?
            .to_string();
        let ssh_public_key_str = ssh_public_key.to_openssh()?;

        Ok((ssh_private_key_str, ssh_public_key_str))
    }

    #[derive(Debug)]
    struct TestOption {
        password: bool,                // password or private key
        rsa: bool,                     // rsa or ed25519
        host_key: Option<Vec<String>>, // host key
    }

    async fn test_ssh_inner(opt: TestOption) -> anyhow::Result<()> {
        tracing::info!("testing ssh, using option: {:?}", opt);
        // dirty works: prepare ssh config directory for the docker container &
        // generate host key pairs
        // under /tmp
        // it's ok for cross test's docker in docker, since we declared volume of
        // /tmp
        let temp_dir = tempdir()?;
        let test_config_base_dir = test_config_base_dir();
        let ssh_config_path = test_config_base_dir.join("ssh");
        let ssh_config_tmp_path = temp_dir.path().join("ssh");

        // cp files under ssh_config_path to temp_dir
        tokio::process::Command::new("cp")
            .args([
                "-r",
                ssh_config_path.to_str().unwrap(),
                ssh_config_tmp_path.to_str().unwrap(),
            ])
            .output()
            .await
            .expect("failed to copy ssh config files");
        tokio::process::Command::new("chmod")
            .args(["-R", "777", ssh_config_tmp_path.to_str().unwrap()])
            .output()
            .await
            .expect("failed to chmod ssh config files");
        tracing::info!("ssh_config tmp mounting path: {:?}", ssh_config_tmp_path);
        tokio::fs::create_dir_all(&ssh_config_tmp_path.join("logs").join("openssh"))
            .await?;

        // generate host key pairs
        // ignore rsa, it's too slow
        let name_and_key_pairs = [
            (
                "ecdsa",
                russh::keys::Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP256,
                },
            ),
            ("ed25519", russh::keys::Algorithm::Ed25519),
        ]
        .into_iter()
        .map(|(name, algo)| {
            let (private_key, public_key) = gen_ssh_key_pair(algo).unwrap();
            (name, private_key, public_key)
        })
        .collect::<Vec<_>>();
        let host_key_path = ssh_config_tmp_path.join("ssh_host_keys");
        for (name, private_key, public_key) in name_and_key_pairs {
            let private_key_path =
                host_key_path.join(format!("ssh_host_{}_key", name));
            tokio::fs::write(private_key_path, private_key).await?;
            let public_key_path =
                host_key_path.join(format!("ssh_host_{}_key.pub", name));
            tokio::fs::write(public_key_path, public_key).await?;
        }

        // now we are fine, real test starts

        let ssh_private_key_path = ssh_config_tmp_path
            .join(".ssh")
            .join(if opt.rsa { "test_rsa" } else { "test_ed25519" });
        let ssh_private_key_path = ssh_private_key_path.to_str().unwrap();
        let password = if opt.password {
            Some(PASSWORD.to_owned())
        } else {
            None
        };
        let private_key = if !opt.password {
            Some(ssh_private_key_path.to_owned())
        } else {
            None
        };

        let opts = HandlerOptions {
            name: "test-ssh".to_owned(),
            common_opts: Default::default(),
            server: LOCAL_ADDR.to_owned(),
            port: 2222, // in accordance with sshd_config'sport
            password,
            private_key,
            private_key_passphrase: None,
            username: "linuxserver.io".to_owned(),
            host_key: opt.host_key.clone(),
            host_key_algorithms: Some(vec![
                Algorithm::Ed25519,
                Algorithm::Rsa { hash: None },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
            ]),
            totp: None,
        };
        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));
        // we need to store all the runners in a container, to make sure all of
        // them can be destroyed after the test
        let mut chained = MultiDockerTestRunner::default();
        chained
            .add(get_openssh_server_runner(ssh_config_tmp_path))
            .await?;
        run_test_suites_and_cleanup(handler, chained, Suite::tcp_tests()).await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_ssh1() -> anyhow::Result<()> {
        test_ssh_inner(TestOption {
            password: true,
            rsa: false,
            host_key: None,
        })
        .await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "this does pass locally, but not in CI. TODO: #720"]
    async fn test_ssh2() -> anyhow::Result<()> {
        test_ssh_inner(TestOption {
            password: false,
            rsa: true,
            host_key: None,
        })
        .await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial_test::serial]
    #[ignore = "this does pass locally, but not in CI. TODO: #720"]
    async fn test_ssh3() -> anyhow::Result<()> {
        test_ssh_inner(TestOption {
            password: false,
            rsa: false,
            host_key: None,
        })
        .await
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_ssh4() -> anyhow::Result<()> {
        // config wrong host key, expect failure
        let host_key = Some(
            vec![
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtnezeRnexr9UgviTV66AcQ0uGQ9gx4t0GjVA29SstlBgZ5750DmKdxYt3PrCC2qslVOfnpW/1XNMSmRtuqM2C0/uaRBx/lAPyjEQ3IwLHTk7CxirzNw46nYBeIKBKYcdP6LIfdvZ9+avd6+SGIJVrBovBHzV2aIpDEG3dO+9op7gzGPpdRHP4WnOdAuSnLCaAvrSs+amFEmrD+nZLMwUMfX5H9huGJNxo1/ma4Ti3jclY8Utw+K6y2NUNB7YXuiJg2Ugfnu6d54VBg9lA2o481Ol0ys2i46sdmWhaVPRGlWTmQ1fAsbd+9u3/2ae6n9Oc6V88izGUrH8sFb23FmlAbHF5tT2nnOs1XzQPCiUsHgn2XVidEONe2Q/FJbfoA4fUYmoQPGprXzHcvtguUajww7dwYfyEXU6IxNRVl5H+64fnsQ2shVAnpJ10fzSrK1RtcnF3zWGvix2z/wOzgx2ydUV9lNp7tU3bOX2iL8CvYBFwnFqEHRGH5Ry9km1ujdE=".to_owned()
        ]);
        let res = test_ssh_inner(TestOption {
            password: false,
            rsa: false,
            host_key,
        })
        .await;
        assert!(res.is_err());
        Ok(())
    }
}
