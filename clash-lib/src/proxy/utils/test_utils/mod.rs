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
/// Evaluated purely from `cfg`, so it's `const` and folds at compile time —
/// the ignored tests are statically excluded on the affected targets.
#[allow(dead_code)]
pub const fn likely_qemu_emulated() -> bool {
    cfg!(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "x86"))
    ))
}

#[cfg(test)]
mod tests {
    use super::likely_qemu_emulated;

    #[test]
    fn predicate_matches_target_arch() {
        // Linux x86_64 / x86 (i686) and every non-Linux target: false.
        // Linux on aarch64 / arm / riscv64 / mips / s390x / …: true.
        let expected = cfg!(target_os = "linux")
            && !cfg!(target_arch = "x86_64")
            && !cfg!(target_arch = "x86");
        assert_eq!(likely_qemu_emulated(), expected);
    }

    /// Const eval: confirm it folds at compile time and can be used in
    /// const contexts.
    #[test]
    fn usable_in_const_context() {
        const VALUE: bool = likely_qemu_emulated();
        assert_eq!(VALUE, likely_qemu_emulated());
    }
}
