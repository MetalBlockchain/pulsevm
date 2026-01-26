use std::path::{Path, PathBuf};
use std::{env, fs};

fn build_libraries(root: &PathBuf) -> PathBuf {
    // Only run CMake if the build directory doesn't exist or if CMakeLists.txt changed
    cmake::Config::new(&root.join("pulsevm"))
        .define("CMAKE_BUILD_TYPE", "Release")
        .build()
}

fn main() {
    let target = env::var("TARGET").unwrap();

    // IMPORTANT: Tell cargo when to rerun this build script
    println!("cargo:rerun-if-changed=build.rs");

    // Tell cargo to look for shared libraries in the specified directory
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(&project_dir);
    let libraries_root = project_root.join("pulsevm/libraries");

    // Build libfc if it hasn't been built yet
    let libraries_dest = build_libraries(&project_root);

    cxx_build::bridges([
        "src/types.rs",
        "src/bridge.rs",
        "src/iterator_cache.rs",
        "src/name.rs",
        "src/objects.rs",
    ])
    // Bridge implementation
    .file("authority.cpp")
    .file("database.cpp")
    .file("name.cpp")
    .file("block_log.cpp")
    .file("genesis_state.cpp")
    .file("genesis_state_root_key.cpp")
    // Include directories
    .include(libraries_root.join("chainbase/include")) // Add chainbase source headers
    .include(libraries_root.join("libfc/include")) // Add fc source headers
    .include(libraries_root.join("libfc/libraries/boringssl/bssl/include")) // Add boring ssl headers
    .include(libraries_root.join("softfloat/source/include"))
    .include(&project_dir)
    // Compiler flags
    .std("c++20")
    .cpp(true)
    .flag("-pthread")
    .flag("-Wall")
    .flag_if_supported("-Wno-missing-template-arg-list-after-template-kw")
    .flag_if_supported("-Wno-deprecated-declarations")
    .flag_if_supported("-Wno-unused-variable")
    // Compile everything into one library
    .compile("ffi");

    println!("cargo:rustc-link-search=native={}", "/usr/local/lib");
    println!("cargo:rustc-link-lib=pthread");
    println!(
        "cargo:rustc-link-search=native={}",
        "/opt/homebrew/opt/zlib/lib"
    );
    println!("cargo:rustc-link-lib=z");
    println!(
        "cargo:rustc-link-search=native={}",
        "/opt/homebrew/opt/libffi/lib"
    );
    println!("cargo:rustc-link-lib=ffi");
    println!(
        "cargo:rustc-link-search=native={}",
        "/opt/homebrew/opt/boost@1.85/lib"
    );
    println!("cargo:rustc-link-lib=boost_system");
    println!("cargo:rustc-link-lib=boost_chrono");
    println!("cargo:rustc-link-lib=boost_iostreams");
    println!("cargo:rustc-link-search=native={}", "/usr/local/lib");
    println!("cargo:rustc-link-lib=static=bn256");
    println!("cargo:rustc-link-lib=static=bscrypto");
    println!("cargo:rustc-link-lib=static=secp256k1");
    println!("cargo:rustc-link-lib=static=decrepit");
    println!(
        "cargo:rustc-link-search=native={}",
        libraries_dest.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=fc");
    println!("cargo:rustc-link-lib=static=chainbase");
    println!("cargo:rustc-link-lib=static=softfloat");
    println!("cargo:rustc-link-lib=static=bls12-381");

    // C++ standard library
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
