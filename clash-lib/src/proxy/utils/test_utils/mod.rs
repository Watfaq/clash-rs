pub mod echo;
pub mod noop;

#[cfg(docker_test)]
pub mod docker_utils;
#[cfg(docker_test)]
pub use docker_utils::*;

// `qemu_emulated` rustc-cfg
// =========================
// Emitted by `build.rs` when the target is Linux on an arch other than
// x86_64 / x86 (i686). In our CI matrix every such target is produced by
// `cross` and executed under qemu-user — QUIC timing, MTU discovery, and
// timer granularity all drift enough under emulation that
// timing-sensitive tests (TUIC ping-pong, hysteria2 handshake, …) flake.
// Gate them with `#[cfg_attr(qemu_emulated, ignore = "…")]`.
//
// The assumption "non-x86 Linux ⇒ qemu" holds as long as we don't add a
// native aarch64/armv7/riscv64 Linux CI runner; revisit if we do.

#[cfg(test)]
mod tests {
    /// build.rs is the single source of truth for `--cfg qemu_emulated`.
    /// Lock its emit rule against the target predicate so the flag and the
    /// docs above can't drift apart.
    #[test]
    fn cfg_matches_build_rs_emit_rule() {
        let expected_from_build = cfg!(target_os = "linux")
            && !cfg!(target_arch = "x86_64")
            && !cfg!(target_arch = "x86");
        assert_eq!(cfg!(qemu_emulated), expected_from_build);
    }
}
