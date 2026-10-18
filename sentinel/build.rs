use std::{env, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let ebpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../sentinel-ebpf");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());

    let status = Command::new("cargo")
        .current_dir(&ebpf_dir)
        .env_remove("RUSTC")
        .env_remove("CARGO")
        .env("RUSTUP_TOOLCHAIN", "nightly-x86_64-unknown-linux-gnu")
        .args(["build", "--release"])
        .status()
        .expect("failed to run cargo build for sentinel-ebpf");

    if !status.success() {
        panic!("sentinel-ebpf build failed");
    }

    let built = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("sentinel");

    std::fs::copy(&built, out_dir.join("sentinel"))
        .unwrap_or_else(|e| panic!("failed to copy {}: {e}", built.display()));
}
