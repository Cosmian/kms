pub const EXTENSION_CONFIG: &[u8] = br"
[ v3_ca ]
keyUsage=critical,nonRepudiation,digitalSignature,dataEncipherment,keyEncipherment
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
crlDistributionPoints=URI:http://crl3.digicert.com/CloudflareIncECCCA-3.crl
subjectAltName=email:black@cosmian.com
";
