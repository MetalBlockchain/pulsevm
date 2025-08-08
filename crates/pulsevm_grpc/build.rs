fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["proto/vm/runtime/runtime.proto"], &["proto"])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(&["proto/vm/vm.proto"], &["proto"])?;
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["proto/appsender/appsender.proto"], &["proto"])?;
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["proto/messenger/messenger.proto"], &["proto"])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(&["proto/http/http.proto"], &["proto"])?;
    Ok(())
}
