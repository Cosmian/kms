fn main() {
    // Regenerate bindings when the proto changes with tonic-build and commit src/provider.rs.
    println!("cargo:rerun-if-changed=src/provider.proto");
    println!("cargo:rerun-if-changed=src/provider.rs");
}
