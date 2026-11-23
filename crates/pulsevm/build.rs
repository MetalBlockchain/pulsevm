//! Records which source this binary was built from, so `getInfo` and the start-up
//! log can say so and a fleet can be checked for one build (the write-ahead log and
//! export formats changed with no gate between builds).
//!
//! `PULSEVM_BUILD_ID` overrides it (a build outside a git checkout, such as a
//! source tarball or a container build context, would otherwise report "unknown",
//! which cannot tell two builds apart).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PULSEVM_BUILD_ID");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");

    let from_env = std::env::var("PULSEVM_BUILD_ID")
        .ok()
        .filter(|id| !id.trim().is_empty());
    let id = from_env.unwrap_or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short=12", "HEAD"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
    });
    println!("cargo:rustc-env=PULSEVM_BUILD_ID={id}");
}
