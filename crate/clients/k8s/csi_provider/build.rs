fn main() {
    // Regenerate bindings when the proto changes by running:
    //   cargo run --manifest-path crate/clients/k8s/csi_provider/gen/Cargo.toml
    // and committing the updated src/provider.rs.
    println!("cargo:rerun-if-changed=src/provider.proto");
    println!("cargo:rerun-if-changed=src/provider.rs");
}
