pub(crate) fn check_certificate(pkcs12: &[u8], password: &str) {
    // Alternatively, the certificate can be check with:
    // `openssl pkcs12 -legacy -in final.p12 -nodes -passin pass:"secret"`
    let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(pkcs12).unwrap();
    pkcs12_parser.parse2(password).unwrap();
}
