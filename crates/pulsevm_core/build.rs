fn main() {
    // Apple Silicon Homebrew path; adjust if needed
    println!("cargo:rustc-link-search=native=/opt/homebrew/opt/libffi/lib");
    println!("cargo:rustc-link-lib=ffi");
}