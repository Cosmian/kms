fn main() {
    // Regenerate bindings when the proto changes with tonic-build and commit src/v2.rs.
    println!("cargo:rerun-if-changed=src/kmsv2.proto");
    println!("cargo:rerun-if-changed=src/v2.rs");
}
