use std::{env, fs};
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap();

    // Tell cargo to look for shared libraries in the specified directory
    let project_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_root = PathBuf::from(&project_dir);
    let libraries_root = project_root.join("pulsevm/libraries");
    let chainbase_root = project_root.join("chaindb");
    
    //println!("cargo:rustc-link-search=native={}/lib", chainbase_dir);
    println!("cargo:rustc-link-lib=dylib=chainbase");
    
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=chaindb/include/chainbase/chainbase.hpp");
    println!("cargo:rerun-if-changed=database.hpp");
    println!("cargo:rerun-if-changed=database.cpp");
    println!("cargo:rerun-if-env-changed=CHAINBASE_DIR");

    // Chainbase source and include directories
    let src_dir = chainbase_root.join("src");
    let include_dir = chainbase_root.join("include");

    // Find dependencies
    let boost_root = env::var("BOOST_ROOT")
        .unwrap_or_else(|_| "/opt/homebrew/opt/boost@1.85/include".to_string());

    cxx_build::bridge("src/bridge.rs")
        // Chainbase source files
        .file(src_dir.join("chainbase.cpp"))
        .file(src_dir.join("pinnable_mapped_file.cpp"))
        // Bridge implementation
        .file("database.cpp")
        // Include directories
        .include(&include_dir)
        .include(&boost_root)
        .include(&project_dir)  // For chainbase_bridge.hpp
        .include(&libraries_root.join("libfc/include"))
        .include(&libraries_root.join("libfc/libraries/boringssl/bssl/include"))
        .include(&libraries_root.join("softfloat/source/include"))
        .include(&libraries_root.join("chain/include"))
        // Compiler flags
        .flag("-std=c++20")
        .flag("-pthread")
        .flag_if_supported("-Wno-missing-template-arg-list-after-template-kw")
        .flag_if_supported("-Wno-deprecated-declarations")
        .flag_if_supported("-Wno-unused-variable")
        // Compile everything into one library
        .compile("chainbase");

    let boost_lib = env::var("BOOST_LIB_PATH")
        .unwrap_or_else(|_| "/opt/homebrew/opt/boost@1.85/lib".to_string());
    println!("cargo:rustc-link-search=native={}", boost_lib);
    
    println!("cargo:rustc-link-lib=boost_system");
    println!("cargo:rustc-link-lib=boost_chrono");
    println!("cargo:rustc-link-lib=pthread");

    println!("cargo:rustc-link-search=native={}", project_root.join("pulsevm/build/libraries/chain").to_str().unwrap());
    println!("cargo:rustc-link-lib=chain");

    // C++ standard library
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}