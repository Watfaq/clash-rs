use russh::keys::{EcdsaCurve, HashAlg};
use totp_rs::{Rfc6238, Secret, TOTP};

use crate::{
    config::internal::proxy::{OutboundSsh, Totp},
    proxy::{
        HandlerCommonOptions,
        ssh::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundSsh> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundSsh) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

/// supported host key algorithms:
///   * `ssh-ed25519`
///   * `rsa-sha2-256`
///   * `rsa-sha2-512`
///   * `ssh-rsa` ✨
///   * `ecdsa-sha2-nistp256` ✨
///   * `ecdsa-sha2-nistp384` ✨
///   * `ecdsa-sha2-nistp521` ✨
fn str_to_algo(value: &str) -> Option<russh::keys::Algorithm> {
    match value {
        "ssh-ed25519" | "ed25519" => Some(russh::keys::Algorithm::Ed25519),
        "rsa-sha2-256" => Some(russh::keys::Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        }),
        "rsa-sha2-512" => Some(russh::keys::Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        }),
        "ssh-rsa" | "rsa" => Some(russh::keys::Algorithm::Rsa { hash: None }),
        "ecdsa-sha2-nistp256" => Some(russh::keys::Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }),
        "ecdsa-sha2-nistp384" => Some(russh::keys::Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        }),
        "ecdsa-sha2-nistp521" => Some(russh::keys::Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        }),
        _ => None,
    }
}

impl TryFrom<&OutboundSsh> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundSsh) -> Result<Self, Self::Error> {
        let host_key_algorithms = s.host_key_algorithms.clone().map(|algos| {
            algos
                .iter()
                .filter_map(|s| str_to_algo(s))
                .collect::<Vec<_>>()
        });
        let totp: Option<Result<TOTP, Self::Error>> =
            s.totp_opt.clone().map(|t| match t {
                crate::config::internal::proxy::TotpOption::OtpAuth(secret) => {
                    let rfc6238 = Rfc6238::with_defaults(
                        Secret::Encoded(secret).to_bytes().map_err(|e| {
                            crate::Error::InvalidConfig(format!(
                                "ssh totp, invalid secret {:?}",
                                e
                            ))
                        })?,
                    )
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "ssh totp, invalid totp: {}",
                            e
                        ))
                    })?;
                    TOTP::from_rfc6238(rfc6238).map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "ssh totp, invalid totp: {}",
                            e
                        ))
                    })
                }
                crate::config::internal::proxy::TotpOption::Common(common_opt) => {
                    let Totp {
                        secret,
                        screw,
                        step,
                        digits,
                        algorithm,
                    } = common_opt;
                    TOTP::new(
                        algorithm,
                        digits,
                        screw,
                        step,
                        Secret::Encoded(secret).to_bytes().map_err(|e| {
                            crate::Error::InvalidConfig(format!(
                                "ssh totp, invalid secret {:?}",
                                e
                            ))
                        })?,
                    )
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "ssh totp, invalid totp: {}",
                            e
                        ))
                    })
                }
            });

        let totp = match totp {
            Some(Ok(t)) => Some(t),
            Some(Err(e)) => return Err(e),
            None => None,
        };

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            username: s.username.clone(),
            port: s.common_opts.port,
            password: s.password.clone(),
            private_key: s.private_key.clone(),
            private_key_passphrase: s.private_key_passphrase.clone(),
            host_key: s.host_key.clone(),
            host_key_algorithms,
            totp,
        });

        Ok(h)
    }
}
