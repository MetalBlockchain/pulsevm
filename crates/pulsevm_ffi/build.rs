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

    // Try and find Boost headers
    let boost_headers = match env::var("BOOST_HEADERS") {
        Ok(val) => PathBuf::from(val),
        Err(_) => {
            let default_path = if target.contains("apple") {
                "/usr/local/include"
            } else {
                "/usr/include"
            };
            PathBuf::from(default_path)
        }
    };
    let boost_lib = match env::var("BOOST_LIB") {
        Ok(val) => PathBuf::from(val),
        Err(_) => {
            let mut default_path = if target.contains("apple") {
                "/usr/local/lib"
            } else {
                "/usr/lib"
            };

            // On some Linux systems, Boost libraries are in a different directory
            if Path::new("/usr/lib/x86_64-linux-gnu").exists() {
                default_path = "/usr/lib/x86_64-linux-gnu";
            } else if Path::new("/usr/lib/aarch64-linux-gnu").exists() {
                default_path = "/usr/lib/aarch64-linux-gnu";
            }

            PathBuf::from(default_path)
        }
    };
    let zlib_root = match env::var("ZLIB_ROOT") {
        Ok(val) => PathBuf::from(val),
        Err(_) => {
            let mut default_path = if target.contains("apple") {
                "/usr/local/lib"
            } else {
                "/usr/lib"
            };

            // On some Linux systems, Boost libraries are in a different directory
            if Path::new("/usr/lib/x86_64-linux-gnu").exists() {
                default_path = "/usr/lib/x86_64-linux-gnu";
            } else if Path::new("/usr/lib/aarch64-linux-gnu").exists() {
                default_path = "/usr/lib/aarch64-linux-gnu";
            }

            PathBuf::from(default_path)
        }
    };

    let cxx_standard = if target.contains("apple") {
        "c++20"
    } else {
        "gnu++20"
    };

    cxx_build::bridges(["src/bridge.rs"])
        .file("database.cpp")
        .file("utils.cpp")
        .file("name.cpp")
        .file("iterator_cache.cpp")
        .file("api.cpp")
        // Include directories
        .include(boost_headers) // Standard system headers
        .include(libraries_root.join("chainbase/include")) // Add chainbase source headers
        .include(libraries_root.join("chain/include")) // Add fc built headers
        .include(libraries_root.join("libfc/include")) // Add fc source headers
        .include(libraries_root.join("libfc/libraries/boringssl/bssl/include")) // Add boring ssl headers
        .include(&project_dir)
        // Compiler flags
        .std(cxx_standard)
        .cpp(true)
        .flag("-pthread")
        .flag("-Wall")
        .flag_if_supported("-Wno-missing-template-arg-list-after-template-kw")
        .flag_if_supported("-Wno-deprecated-declarations")
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-Wno-unused-parameter")
        // Compile everything into one library
        .compile("pulsevm_ffi");

    // Link to the built static libraries
    println!(
        "cargo:rustc-link-search=native={}",
        libraries_dest.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=fc");
    println!("cargo:rustc-link-lib=static=chainbase");
    println!("cargo:rustc-link-lib=static=bls12-381");
    println!("cargo:rustc-link-lib=static=decrepit");
    println!("cargo:rustc-link-lib=static=bscrypto");
    println!("cargo:rustc-link-lib=static=secp256k1");
    println!("cargo:rustc-link-lib=static=pulsevm_chain");

    // Statically link to Boost and zlib
    println!("cargo:rustc-link-search=native={}", boost_lib.display());
    println!("cargo:rustc-link-lib=static=boost_system");
    println!("cargo:rustc-link-lib=static=boost_iostreams");
    println!("cargo:rustc-link-lib=static=boost_chrono");
    println!("cargo:rustc-link-search=native={}", zlib_root.display());
    println!("cargo:rustc-link-lib=static=z");

    // C++ standard library
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
