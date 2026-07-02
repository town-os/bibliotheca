use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("proto");
    let proto_file = proto_root
        .join("bibliotheca")
        .join("v1")
        .join("control.proto");

    // Use the vendored protoc plus its bundled well-known types rather than
    // relying on a system install. Fedora's `protobuf-compiler` package (at
    // least on aarch64) ships the `protoc` binary but not the well-known type
    // .proto files (google/protobuf/timestamp.proto, empty.proto, …), so a
    // system-only build fails with "File not found". Vendoring both keeps the
    // build reproducible across platforms and architectures.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let wkt_include = protoc_bin_vendored::include_path()?;
    std::env::set_var("PROTOC", &protoc);

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto_file], &[proto_root, wkt_include])?;

    println!("cargo:rerun-if-changed=../../proto/bibliotheca/v1/control.proto");
    Ok(())
}
