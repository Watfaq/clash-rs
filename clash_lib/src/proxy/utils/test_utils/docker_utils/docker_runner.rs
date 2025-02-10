use std::collections::HashMap;

use bollard::{
    container::{Config, LogsOptions, RemoveContainerOptions},
    secret::{HostConfig, Mount, PortBinding},
    Docker,
};

use bollard::image::CreateImageOptions;

use anyhow::Result;
use futures::{Future, TryStreamExt};

const TIMEOUT_DURATION: u64 = 30;

pub struct DockerTestRunner {
    instance: Docker,
    id: String,
}

impl DockerTestRunner {
    pub async fn try_new(
        image_conf: Option<CreateImageOptions<'_, String>>,
        container_conf: Config<String>,
    ) -> Result<Self> {
        let docker: Docker = Docker::connect_with_socket_defaults()?;

        docker
            .create_image(image_conf, None, None)
            .try_collect::<Vec<_>>()
            .await?;

        let id = docker
            .create_container::<&str, String>(None, container_conf)
            .await?
            .id;
        docker.start_container::<String>(&id, None).await?;
        Ok(Self {
            instance: docker,
            id,
        })
    }

    // you can run the cleanup manually
    pub async fn cleanup(self) -> anyhow::Result<()> {
        let logs = self
            .instance
            .logs::<String>(
                &self.id,
                Some(LogsOptions {
                    follow: false,
                    stdout: true,
                    stderr: true,
                    ..Default::default()
                }),
            )
            .try_collect::<Vec<_>>()
            .await?;

        for log in logs {
            eprintln!("{}", log);
        }

        self.instance
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MultiDockerTestRunner {
    runners: Vec<DockerTestRunner>,
}

impl MultiDockerTestRunner {
    #[cfg(docker_test)]
    pub async fn add(
        &mut self,
        creator: impl Future<Output = anyhow::Result<DockerTestRunner>>,
    ) -> anyhow::Result<()> {
        match creator.await {
            Ok(runner) => {
                self.runners.push(runner);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "cannot start container, please check the docker environment, \
                     error: {:?}",
                    e
                );
                Err(e)
            }
        }
    }
}

#[async_trait::async_trait]
pub trait RunAndCleanup {
    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl RunAndCleanup for DockerTestRunner {
    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let fut = Box::pin(f);
        // let res = fut.await;
        // make sure the container is cleaned up
        let res = tokio::select! {
            res = fut => {
                res
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(TIMEOUT_DURATION))=> {
                tracing::warn!("timeout");
                Err(anyhow::anyhow!("timeout"))
            }
        };

        self.cleanup().await?;

        res
    }
}

#[async_trait::async_trait]
impl RunAndCleanup for MultiDockerTestRunner {
    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let fut = Box::pin(f);
        // let res = fut.await;
        // make sure the container is cleaned up
        let res = tokio::select! {
            res = fut => {
                res
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(TIMEOUT_DURATION))=> {
                tracing::warn!("timeout");
                Err(anyhow::anyhow!("timeout"))
            }
        };

        // cleanup all the docker containers
        for runner in self.runners {
            runner.cleanup().await?;
        }

        res
    }
}

const PORT: u16 = 10002;
const EXPOSED_TCP: &str = "10002/tcp";
const EXPOSED_UDP: &str = "10002/udp";
const EXPOSED_PORTS: &[&str] = &[EXPOSED_TCP, EXPOSED_UDP];

#[derive(Debug)]
pub struct DockerTestRunnerBuilder {
    image: String,
    host_config: HostConfig,
    exposed_ports: Vec<String>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    _server_port: u16,
}

impl Default for DockerTestRunnerBuilder {
    fn default() -> Self {
        Self {
            image: "hello-world".to_string(),
            host_config: get_host_config(PORT),
            exposed_ports: EXPOSED_PORTS
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            cmd: None,
            env: None,
            entrypoint: None,
            _server_port: PORT,
        }
    }
}

impl DockerTestRunnerBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn image(mut self, image: &str) -> Self {
        self.image = image.to_string();
        self
    }

    #[allow(unused)]
    pub fn port(mut self, port: u16) -> Self {
        self._server_port = port;
        self.exposed_ports = vec![format!("{}/tcp", port), format!("{}/udp", port)];
        let new_host_config = get_host_config(port);
        self.host_config.network_mode = new_host_config.network_mode;
        self.host_config.port_bindings = new_host_config.port_bindings;

        self
    }

    pub fn cmd(mut self, cmd: &[&str]) -> Self {
        self.cmd = Some(cmd.iter().map(|x| x.to_string()).collect());
        self
    }

    pub fn env(mut self, env: &[&str]) -> Self {
        self.env = Some(env.iter().map(|x| x.to_string()).collect());
        self
    }

    #[cfg(docker_test)]
    #[allow(unused)]
    pub fn entrypoint(mut self, entrypoint: &[&str]) -> Self {
        self.entrypoint = Some(entrypoint.iter().map(|x| x.to_string()).collect());
        self
    }

    pub fn mounts(mut self, pairs: &[(&str, &str)]) -> Self {
        self.host_config.mounts = Some(
            pairs
                .iter()
                .map(|(src, dst)| Mount {
                    target: Some(dst.to_string()),
                    source: Some(src.to_string()),
                    typ: Some(bollard::secret::MountTypeEnum::BIND),
                    read_only: Some(false),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );

        self
    }

    pub fn sysctls(mut self, sysctls: &[(&str, &str)]) -> Self {
        self.host_config.sysctls = Some(
            sysctls
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        );

        self
    }

    pub fn cap_add(mut self, caps: &[&str]) -> Self {
        self.host_config.cap_add =
            Some(caps.iter().map(|x| x.to_string()).collect());
        self
    }

    pub fn net_mode(mut self, mode: &str) -> Self {
        self.host_config.network_mode = Some(mode.to_string());
        self
    }

    pub async fn build(self) -> anyhow::Result<DockerTestRunner> {
        tracing::trace!("building docker test runner: {:?}", &self);
        let exposed = self
            .exposed_ports
            .into_iter()
            .map(|x| (x, Default::default()))
            .collect::<HashMap<_, _>>();

        DockerTestRunner::try_new(
            Some(CreateImageOptions {
                from_image: self.image.clone(),
                ..Default::default()
            }),
            Config {
                image: Some(self.image),
                tty: Some(true),
                entrypoint: self.entrypoint,
                cmd: self.cmd,
                env: self.env,
                exposed_ports: Some(exposed),
                host_config: Some(self.host_config),
                ..Default::default()
            },
        )
        .await
        .map_err(Into::into)
    }
}

pub fn get_host_config(port: u16) -> HostConfig {
    HostConfig {
        port_bindings: Some(
            [
                (
                    (format!("{}/tcp", port)),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", port)),
                    }]),
                ),
                (
                    (format!("{}/udp", port)),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", port)),
                    }]),
                ),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>(),
        ),
        // we need to use the host mode to enable the benchmark function
        #[cfg(not(target_os = "macos"))]
        network_mode: Some("host".to_owned()),
        ..Default::default()
    }
}
