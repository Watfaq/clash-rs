pub mod echo;
pub mod noop;

#[cfg(docker_test)]
pub mod docker_utils;
#[cfg(docker_test)]
pub use docker_utils::*;

/// Returns `true` when this test binary is built for Linux on an architecture
/// other than x86_64 / x86 (i686). In our CI matrix every such target is
/// produced by `cross` and executed under qemu-user — QUIC timing, MTU
/// discovery, and timer granularity all drift enough under emulation that
/// timing-sensitive tests (TUIC ping-pong, hysteria2 handshake, …) become
/// flaky. Gate those tests with `#[cfg_attr(condition, ignore = "…")]` or
/// an early-return on this predicate.
///
/// The assumption "non-x86 Linux ⇒ qemu" holds as long as we don't add a
/// native aarch64/armv7/riscv64 Linux CI runner; revisit if we do.
///
/// Backed by the `likely_qemu_emulated` rustc-cfg set in `build.rs`, so the
/// same flag is available at attribute position:
/// `#[cfg(likely_qemu_emulated)]` / `#[cfg_attr(likely_qemu_emulated, …)]`.
/// Use the const fn for runtime branches; use the cfg flag for compile-time
/// gating (e.g. `ignore`). They stay in sync because both come from build.rs.
#[allow(dead_code)]
pub const fn likely_qemu_emulated() -> bool {
    cfg!(likely_qemu_emulated)
}

#[cfg(test)]
mod tests {
    use super::likely_qemu_emulated;

    #[test]
    fn predicate_matches_build_rs_emit() {
        // build.rs emits `--cfg likely_qemu_emulated` iff target_os = linux
        // AND target_arch is neither x86_64 nor x86 (i686). The const fn must
        // agree with that emit so #[cfg(likely_qemu_emulated)] and the runtime
        // call can't drift apart.
        let expected_from_build = cfg!(target_os = "linux")
            && !cfg!(target_arch = "x86_64")
            && !cfg!(target_arch = "x86");
        assert_eq!(cfg!(likely_qemu_emulated), expected_from_build);
        assert_eq!(likely_qemu_emulated(), expected_from_build);
    }

    /// Const eval: confirm it folds at compile time and can be used in
    /// const contexts.
    #[test]
    fn usable_in_const_context() {
        const VALUE: bool = likely_qemu_emulated();
        assert_eq!(VALUE, likely_qemu_emulated());
    }
}
