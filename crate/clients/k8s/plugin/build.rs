fn main() {
    // Regenerate bindings when the proto changes by running:
    //   cargo run --manifest-path crate/clients/k8s/plugin/gen/Cargo.toml
    // and committing the updated src/v2.rs.
    println!("cargo:rerun-if-changed=src/kmsv2.proto");
    println!("cargo:rerun-if-changed=src/v2.rs");
}
