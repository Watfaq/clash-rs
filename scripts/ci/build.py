#!/usr/bin/env python3
"""
clash-rs CI target build and packaging script.

Reads .github/target.toml and compiles the specified target using `cargo` or `cross`,
then packages the resulting binary into `dist/` with proper release naming and SHA256 checksums.
"""

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

# Load TOML parser (built-in in Python 3.11+)
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


def parse_target_toml(config_path: Path) -> list:
    """Parse .github/target.toml into a list of target dictionaries."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    if tomllib is not None:
        data = tomllib.loads(raw_text)
        return data.get("target", [])

    # Minimal fallback parser if tomllib/tomli is not available
    targets = []
    current = None
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[target]]":
            if current is not None:
                targets.append(current)
            current = {}
            continue
        if current is not None and "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val == "true":
                val = True
            elif val == "false":
                val = False
            current[key] = val
    if current is not None:
        targets.append(current)
    return targets


def sha256_file(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def package_target(
    binary_path: Path,
    release_name: str,
    postfix: str,
    dist_dir: Path,
    is_windows: bool,
) -> list[Path]:
    """Package binary into dist/ archive and generate sha256."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    created_files = []

    # 1. Copy raw uncompressed binary (useful for Docker builds and direct invocation)
    raw_name = f"clash-rs-{release_name}{postfix}"
    raw_dest = dist_dir / raw_name
    shutil.copy2(binary_path, raw_dest)
    if not is_windows:
        os.chmod(raw_dest, 0o755)
    created_files.append(raw_dest)

    # 2. Create archive
    if is_windows:
        archive_name = f"clash-rs-{release_name}.zip"
        archive_path = dist_dir / archive_name
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(binary_path, arcname=f"clash-rs{postfix}")
        created_files.append(archive_path)
    else:
        archive_name = f"clash-rs-{release_name}.tar.gz"
        archive_path = dist_dir / archive_name
        with tarfile.open(archive_path, "w:gz") as tf:
            tar_info = tf.gettarinfo(str(binary_path), arcname="clash-rs")
            tar_info.mode = 0o755
            with open(binary_path, "rb") as f:
                tf.addfile(tar_info, f)
        created_files.append(archive_path)

    # 3. Create SHA256 checksum file for the archive
    sha = sha256_file(archive_path)
    sha_path = dist_dir / f"{archive_name}.sha256"
    sha_path.write_text(f"{sha}  {archive_name}\n", encoding="utf-8")
    created_files.append(sha_path)

    print(f"✓ Packaged: {archive_path.name} (SHA256: {sha[:16]}...)")
    return created_files


def run_build(target_cfg: dict, dist_dir: Path, dry_run: bool = False, run_tests: bool = False) -> int:
    """Execute the build for a target configuration."""
    target_triple = target_cfg["target"]
    release_name = target_cfg.get("release-name", target_triple)
    tool = target_cfg.get("tool", "cargo")
    extra_args = target_cfg.get("extra-args", "")
    rustflags = target_cfg.get("rustflags", "")
    postfix = target_cfg.get("postfix", "")
    is_windows = (postfix == ".exe") or ("windows" in target_triple)
    build_std = target_cfg.get("build-std", False)
    skip_test = target_cfg.get("skip-test", False)

    print(f"\n=======================================================")
    print(f"Building: {release_name}")
    print(f"Target:   {target_triple}")
    print(f"Tool:     {tool}")
    print(f"Extra:    {extra_args}")
    print(f"=======================================================\n")

    env = os.environ.copy()
    env["RUSTC_BOOTSTRAP"] = env.get("RUSTC_BOOTSTRAP", "1")
    env["RUST_LOG"] = env.get("RUST_LOG", "clash_lib=TRACE")

    # Set git version information for clash-bin/build.rs
    git_ref = env.get("CLASH_GIT_REF") or env.get("CIRCLE_TAG") or env.get("CIRCLE_BRANCH") or env.get("GITHUB_REF", "")
    git_sha = env.get("CLASH_GIT_SHA") or env.get("CIRCLE_SHA1") or env.get("GITHUB_SHA", "")
    if git_ref:
        env["CLASH_GIT_REF"] = git_ref
    if git_sha:
        env["CLASH_GIT_SHA"] = git_sha

    if rustflags:
        existing_flags = env.get("RUSTFLAGS", "")
        env["RUSTFLAGS"] = f"{existing_flags} {rustflags}".strip()

    # Construct build command
    cmd = [tool, "build", "--release", "--package", "clash-rs", "--target", target_triple]

    if build_std and "-Z build-std" not in extra_args:
        cmd.extend(["-Z", "build-std=std,panic_abort"])

    if extra_args:
        import shlex
        cmd.extend(shlex.split(extra_args))

    print(f"Command: {' '.join(cmd)}")
    print(f"Environment overrides: RUSTC_BOOTSTRAP={env.get('RUSTC_BOOTSTRAP')} RUSTFLAGS={env.get('RUSTFLAGS', '')}")

    if not dry_run:
        result = subprocess.run(cmd, env=env)
        if result.returncode != 0:
            print(f"❌ Build failed with exit code {result.returncode}", file=sys.stderr)
            return result.returncode

    # Optional test execution
    if run_tests and not skip_test:
        test_cmd = [tool, "test", "--package", "clash-rs", "--target", target_triple]
        if extra_args:
            test_cmd.extend(shlex.split(extra_args))
        print(f"\nRunning tests: {' '.join(test_cmd)}")
        if not dry_run:
            test_res = subprocess.run(test_cmd, env=env)
            if test_res.returncode != 0:
                print(f"❌ Tests failed with exit code {test_res.returncode}", file=sys.stderr)
                return test_res.returncode

    # Locate generated binary
    expected_binary = Path("target") / target_triple / "release" / f"clash-rs{postfix}"
    if not dry_run and not expected_binary.is_file():
        # Check if cargo output it in target/release without target directory prefix
        alt_binary = Path("target") / "release" / f"clash-rs{postfix}"
        if alt_binary.is_file():
            expected_binary = alt_binary
        else:
            print(f"❌ Expected binary not found at {expected_binary}", file=sys.stderr)
            return 1

    if not dry_run:
        package_target(expected_binary, release_name, postfix, dist_dir, is_windows)

    return 0


def main():
    parser = argparse.ArgumentParser(description="Build clash-rs targets from target.toml")
    parser.add_argument("--config", type=Path, default=Path(".github/target.toml"), help="Path to target.toml")
    parser.add_argument("--target-name", type=str, help="Specific release-name to build (e.g. x86_64-unknown-linux-gnu)")
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"), help="Output directory for packaged assets")
    parser.add_argument("--list", action="store_true", help="List available target release names")
    parser.add_argument("--test", action="store_true", help="Run tests for target if not skipped")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    args = parser.parse_args()

    targets = parse_target_toml(args.config)
    if not targets:
        print("No targets found in config.", file=sys.stderr)
        return 1

    if args.list:
        print("Available release targets:")
        for t in targets:
            print(f"  - {t.get('release-name', t['target'])} (OS: {t.get('os')}, tool: {t.get('tool', 'cargo')})")
        return 0

    if not args.target_name:
        print("Error: Specify --target-name or --list", file=sys.stderr)
        return 1

    matched = [t for t in targets if t.get("release-name") == args.target_name or t.get("target") == args.target_name]
    if not matched:
        print(f"Error: Target '{args.target_name}' not found in {args.config}", file=sys.stderr)
        return 1

    target_cfg = matched[0]
    return run_build(target_cfg, args.dist_dir, dry_run=args.dry_run, run_tests=args.test)


if __name__ == "__main__":
    sys.exit(main())
