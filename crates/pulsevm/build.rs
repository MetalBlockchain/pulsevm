use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    // PULSEVM_VERSION overrides for builds without a .git directory (e.g. from
    // a source tarball); otherwise derive from the checkout: a tagged release
    // build reports the tag (v0.3.5), anything else tag-distance + commit.
    let version = std::env::var("PULSEVM_VERSION")
        .ok()
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|| "unknown".to_string());
    let commit_long = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let commit_short = commit_long.get(0..8).unwrap_or("unknown").to_string();

    println!("cargo:rustc-env=PULSEVM_VERSION={version}");
    println!("cargo:rustc-env=PULSEVM_COMMIT={commit_short}");
    println!("cargo:rustc-env=PULSEVM_COMMIT_LONG={commit_long}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
    println!("cargo:rerun-if-env-changed=PULSEVM_VERSION");
}
