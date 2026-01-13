use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let target = env::var("TARGET").unwrap();

    // Tell cargo to look for shared libraries in the specified directory
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(&project_dir);
    let libraries_root = project_root.join("pulsevm/libraries");
    let chainbase_root = libraries_root.join("chainbase");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=database.hpp");
    println!("cargo:rerun-if-changed=name.hpp");
    println!("cargo:rerun-if-changed=types.hpp");
    println!("cargo:rerun-if-changed=objects.hpp");

    // Chainbase source and include directories
    let include_dir = chainbase_root.join("include");

    // Find dependencies
    let boost_root = env::var("BOOST_ROOT")
        .unwrap_or_else(|_| "/opt/homebrew/opt/boost@1.85/include".to_string());

    cxx_build::bridges([
        "src/bridge.rs",
        "src/contract_table_objects.rs",
        "src/iterator_cache.rs",
        "src/name.rs",
        "src/objects.rs",
    ])
    // Bridge implementation
    .file("database.cpp")
    .file("pulsevm/libraries/chainbase/src/chainbase.cpp")
    .file("pulsevm/libraries/chainbase/src/pinnable_mapped_file.cpp")
    // Include directories
    .include(&include_dir)
    .include(&boost_root)
    .include(&project_dir) // For chainbase_bridge.hpp
    .include(&libraries_root.join("libfc/include"))
    .include(&libraries_root.join("libfc/libraries/boringssl/bssl/include"))
    .include(&libraries_root.join("softfloat/source/include"))
    .include(&libraries_root.join("chainbase/include"))
    .include(&libraries_root.join("chain/include"))
    // Compiler flags
    .flag("-std=c++20")
    .flag("-pthread")
    .flag_if_supported("-Wno-missing-template-arg-list-after-template-kw")
    .flag_if_supported("-Wno-deprecated-declarations")
    .flag_if_supported("-Wno-unused-variable")
    // Compile everything into one library
    .compile("ffi");

    let boost_lib = env::var("BOOST_LIB_PATH")
        .unwrap_or_else(|_| "/opt/homebrew/opt/boost@1.85/lib".to_string());
    println!("cargo:rustc-link-search=native={}", boost_lib);

    println!("cargo:rustc-link-lib=boost_system");
    println!("cargo:rustc-link-lib=boost_chrono");
    println!("cargo:rustc-link-lib=boost_iostreams");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-search=native={}", "/usr/local/lib");
    println!("cargo:rustc-link-lib=static=bls12-381");
    println!("cargo:rustc-link-lib=static=bn256");
    println!("cargo:rustc-link-lib=static=fc");
    println!("cargo:rustc-link-lib=static=chainbase");
    println!("cargo:rustc-link-lib=static=chain");

    // C++ standard library
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
