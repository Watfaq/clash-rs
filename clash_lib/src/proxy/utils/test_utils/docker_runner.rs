//! This example will run a non-interactive command inside the container using `docker exec`

use std::collections::HashMap;

use bollard::container::{Config, RemoveContainerOptions};
use bollard::secret::{HostConfig, Mount, PortBinding};
use bollard::Docker;

use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::image::CreateImageOptions;

use anyhow::Result;
use futures::{Future, StreamExt, TryStreamExt};

pub struct DockerTestRunner {
    _instance: Docker,
    id: String,
}

impl DockerTestRunner {
    pub async fn new<
        'a,
        T1: serde::ser::Serialize + Into<std::string::String> + std::fmt::Debug + Clone,
        Z: Into<String> + std::hash::Hash + Eq + serde::Serialize,
    >(
        image_conf: Option<CreateImageOptions<'a, T1>>,
        container_conf: Config<Z>,
    ) -> Result<Self> {
        let docker: Docker = Docker::connect_with_socket_defaults()?;

        docker
            .create_image(image_conf, None, None)
            .try_collect::<Vec<_>>()
            .await?;

        let id = docker
            .create_container::<&str, Z>(None, container_conf)
            .await?
            .id;
        docker.start_container::<String>(&id, None).await?;
        Ok(Self {
            _instance: docker,
            id,
        })
    }

    #[allow(unused)]
    pub async fn exec(&self, cmd: Vec<&str>) -> anyhow::Result<()> {
        // non interactive
        let exec = self
            ._instance
            .create_exec(
                &self.id,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(cmd),
                    ..Default::default()
                },
            )
            .await?
            .id;
        if let StartExecResults::Attached { mut output, .. } =
            self._instance.start_exec(&exec, None).await?
        {
            while let Some(Ok(msg)) = output.next().await {
                print!("{msg}");
            }
            return Ok(());
        } else {
            anyhow::bail!("failed to execute cmd")
        }
    }

    // will make sure the container is cleaned up after the future is finished
    pub async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> 
    ) -> anyhow::Result<()> {
        let fut = Box::pin(f);
        let res = fut.await;
        // make sure the container is cleaned up
        // TODO: select a timeout future as well, make sure it can quit smoothly
        self.cleanup().await?;

        res
    }

    // you can run the cleanup manually
    pub async fn cleanup(self) -> anyhow::Result<()> {
        let s = self
            ._instance
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(s)
    }
}

pub fn mount_config(pairs: &[(&str, &str)]) -> Vec<Mount> {
    pairs
        .iter()
        .map(|(src, dst)| Mount {
            target: Some(dst.to_string()),
            source: Some(src.to_string()),
            typ: Some(bollard::secret::MountTypeEnum::BIND),
            read_only: Some(false),
            ..Default::default()
        })
        .collect::<Vec<_>>()
}

pub fn default_host_config() -> HostConfig {
    let mut host_config = HostConfig::default();
    // we need to use the host mode to enable the benchmark function
    #[cfg(not(target_os = "macos"))]
    {
        host_config.network_mode = Some("host".to_owned());
    }
    host_config.port_bindings = Some(
        [
            (
                "10002/tcp".to_owned(),
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_owned()),
                    host_port: Some("10002".to_owned()),
                }]),
            ),
            (
                "10002/udp".to_owned(),
                Some(vec![PortBinding {
                    host_ip: Some("0.0.0.0".to_owned()),
                    host_port: Some("10002".to_owned()),
                }]),
            ),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>(),
    );

    host_config
}

pub fn default_export_ports() -> HashMap<&'static str, HashMap<(), ()>> {
    let export_ports: HashMap<&str, HashMap<(), ()>> = [
        ("10002/tcp", Default::default()),
        ("10002/udp", Default::default()),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    export_ports
}
