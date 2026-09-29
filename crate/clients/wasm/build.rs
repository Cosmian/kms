fn main() {
    // Declare custom cfg used in tests to silence unexpected_cfgs warnings
    println!("cargo::rustc-check-cfg=cfg(wasm_test_browser)");
}
