use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("proto");
    let proto_file = proto_root.join("bibliotheca").join("v1").join("control.proto");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto_file], &[proto_root])?;

    println!("cargo:rerun-if-changed=../../proto/bibliotheca/v1/control.proto");
    Ok(())
}
