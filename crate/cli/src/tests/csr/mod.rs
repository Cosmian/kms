use std::str::FromStr;

use cloudproof::reexport::crypto_core::reexport::x509_cert::{name::Name, request::CertReq};
use const_oid::{db::DB, ObjectIdentifier};
use der::{DecodePem, Tagged};

#[test]
fn parsing_test() {
    // This CSR is from Wikipedia and prints as follows:
    // $ openssl req -text -noout -in request.pem
    //Certificate Request:
    //  Data:
    //      Version: 0 (0x0)
    //      Subject: C=US, ST=California, L=San Francisco, O=Wikimedia Foundation, Inc., CN=*.wikipedia.org
    //      Subject Public Key Info:
    //          Public Key Algorithm: rsaEncryption
    //          RSA Public Key: (512 bit)
    //              Modulus (512 bit):
    //                  00:be:a2:0c:4c:e9:3f:47:c2:1c:c1:b9:f0:53:c4:
    //                  41:4a:60:b8:5a:88:d4:54:c3:ef:3e:28:ff:15:e0:
    //                  54:ce:f6:6c:bb:e4:99:25:af:04:a9:6b:8c:a6:a4:
    //                  03:0c:a5:3c:8a:f5:c6:38:1c:86:89:39:76:76:d6:
    //                  89:bc:e5:cd:2f
    //              Exponent: 65537 (0x10001)
    //      Attributes:
    //          a0:00
    //  Signature Algorithm: sha1WithRSAEncryption
    //      07:f8:b7:40:37:49:08:c4:13:82:cb:1f:57:e9:00:db:fc:b4:
    //      a5:7e:53:3f:e2:f3:9e:99:1f:52:91:31:96:59:e1:8f:e1:99:
    //      3b:b4:88:78:14:f5:73:27:5d:02:34:bb:05:20:2b:fe:ba:32:
    //s    fe:20:38:cd:8d:2e:dc:31:ea:43
    let pem = include_str!("./csr_wikipedia.pem");
    let csr = CertReq::from_pem(pem.as_bytes()).unwrap();

    // Subject
    assert_eq!(
        Name::from_str(
            "CN=*.wikipedia.org,O=Wikimedia Foundation\\, Inc.,L=San Francisco,ST=California,C=US"
        )
        .unwrap(),
        Name::from_str(format!("{}", csr.info.subject).as_str()).unwrap()
    );

    let algorithm = csr.info.public_key.algorithm.oid;
    assert_eq!("rsaEncryption", DB.by_oid(&algorithm).unwrap());

    // This shows how to recover the RSA key using the RSA crate
    //
    // let rsa_public_key = rsa::RsaPublicKey::from_pkcs1_der(
    //     csr.info.public_key.subject_public_key.as_bytes().unwrap(),
    // )
    // .unwrap();
    // let modulus = rsa_public_key.n().to_bytes_be();
    // assert_eq!(
    //     "bea20c4ce93f47c21cc1b9f053c4414a60b85a88d454c3ef3e28ff15e054cef66cbb\
    //     e49925af04a96b8ca6a4030ca53c8af5c6381c8689397676d689bce5cd2f",
    //     hex::encode(modulus)
    // );
    // let exponent = rsa_public_key.e().to_bytes_be();
    // assert_eq!("010001", hex::encode(exponent));

    let signature_algorithm = csr.algorithm.oid;
    assert_eq!(
        "sha1WithRSAEncryption",
        DB.by_oid(&signature_algorithm).unwrap()
    );

    let signatured = csr.signature.as_bytes().unwrap();
    assert_eq!(
        "07f8b740374908c41382cb1f57e900dbfcb4a57e533fe2f39e991f5291319659e18fe1993bb4887814f573275d0234bb05202bfeba32fe2038cd8d2edc31ea43",
        hex::encode(signatured)
    );
}

#[test]
fn rsa_csr_parsing_test() {
    /*
    Certificate Request:
        Data:
            Version: 1 (0x0)
            Subject: C = FR, ST = IdF, L = Paris, O = Cosmian, CN = blue@cosmian.com, emailAddress = blue@cosmian.com
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    Public-Key: (4096 bit)
                    Modulus:
                        00:c8:dd:36:9c:df:ab:36:c7:e9:46:2c:f4:53:9d:
                        96:a7:a5:ee:75:dc:85:08:90:de:c2:d2:6b:1c:e3:
                        10:91:a7:2c:86:1e:74:a2:16:8e:0e:13:e2:23:03:
                        c7:c4:c3:b2:45:93:2a:51:e3:3b:8c:a4:aa:40:84:
                        68:ed:31:5b:e3:d5:c6:68:da:46:bf:95:ae:bc:31:
                        89:67:fa:85:e9:64:f6:9b:51:27:0e:4b:eb:ff:b0:
                        7c:29:31:20:dd:4a:88:c2:f7:d7:9a:12:3d:a5:3b:
                        59:c8:3b:78:f9:2f:cc:78:f0:16:15:da:0d:e2:f8:
                        6b:df:6f:3a:d1:40:2f:d0:75:ea:93:07:69:ce:e4:
                        9f:f5:00:e5:67:19:de:d3:bd:bd:c8:4e:47:c0:6f:
                        2c:17:58:a2:68:12:f4:c1:07:e1:b6:75:47:2f:d3:
                        21:a0:aa:dc:36:0c:b7:78:8a:33:f1:c2:2e:d1:42:
                        98:c0:86:84:32:37:fe:dd:db:08:cc:9d:82:f4:58:
                        02:3d:c4:9c:c4:96:92:9e:49:14:74:f9:12:d1:9b:
                        dd:bf:b8:70:31:0e:8e:7a:03:5d:5b:03:2e:7f:fe:
                        d8:fc:3a:77:a3:5e:2e:91:91:1f:f3:98:d1:0b:fb:
                        f9:92:aa:bd:cd:8c:b3:c9:b6:df:58:8b:31:10:09:
                        fc:2c:39:04:36:b5:e9:12:c4:84:c3:8e:8a:5e:36:
                        a5:b4:70:43:37:fd:88:5b:ef:e2:58:4b:6a:cd:2a:
                        50:9c:b3:a1:1f:43:2c:d1:e2:f8:8b:e2:d6:b4:c6:
                        2e:ee:db:60:b8:df:b5:97:d4:fe:df:22:eb:ab:c4:
                        98:19:db:19:f8:3c:cc:5c:2d:5c:90:2e:cc:c3:70:
                        4c:67:4d:eb:bd:88:cc:07:d6:8a:31:00:62:99:ef:
                        c2:e0:39:f5:d1:af:93:12:d0:a9:f9:9e:db:33:32:
                        5f:a5:e3:b4:e2:f7:35:01:2b:05:ff:90:36:3d:b9:
                        ac:e1:27:00:ca:5c:d6:47:f5:30:8c:8c:b6:6f:d1:
                        08:4e:6a:c1:c2:24:78:1e:54:df:54:f8:12:43:ac:
                        69:c4:cb:aa:c3:ca:e1:d0:0f:b1:29:e1:c2:30:a1:
                        aa:d1:8f:db:a2:23:63:47:20:58:a1:6c:55:ef:ba:
                        4c:a5:2e:38:39:37:41:9b:43:e1:fc:ff:63:73:10:
                        1d:5c:e8:6f:6d:dd:75:06:2e:00:6f:3e:98:5c:75:
                        99:80:90:cb:b9:12:27:44:99:45:f9:47:db:24:7b:
                        d7:01:ad:3c:97:8f:68:2a:5b:bc:db:a3:44:03:45:
                        03:5a:35:5e:fc:1d:13:d5:5f:cf:6b:18:cc:69:6b:
                        f9:0c:cd
                    Exponent: 65537 (0x10001)
            Attributes:
                (none)
                Requested Extensions:
        Signature Algorithm: sha256WithRSAEncryption
        Signature Value:
            a2:e3:3c:27:fe:3b:24:0e:61:c0:be:66:f3:f2:f7:e9:66:3f:
            5d:69:24:52:fb:f2:6d:ee:44:9e:c5:04:a3:21:e4:07:34:b2:
            80:18:6a:51:96:d1:e5:1b:b8:e5:16:c8:9a:52:ef:f8:be:e5:
            6c:e4:8f:09:18:2c:f2:ba:44:54:02:f8:db:0b:d5:a6:9f:a7:
            ae:e2:96:7d:0f:cd:15:2e:53:5b:a6:00:ec:82:07:f7:0d:3e:
            b4:b7:c5:5f:96:f7:ed:5b:7e:45:c3:36:7a:b3:74:16:be:b4:
            bf:cb:5d:aa:11:e4:f0:c3:8c:60:2c:0c:ab:b0:e3:7f:a5:4b:
            d8:27:03:d8:23:05:39:5b:0c:b0:2a:f8:5e:69:ca:03:77:30:
            b7:d4:de:99:2e:9e:1c:25:98:39:b3:0f:96:a2:4c:8c:7a:58:
            bf:1e:40:fd:57:a4:11:7a:c5:e5:7e:ed:dc:ae:2f:25:0b:fa:
            aa:a1:4c:aa:d3:f0:d0:4a:8c:89:fc:c8:d3:f6:50:5a:54:29:
            19:49:05:f2:65:cb:da:42:b3:36:e6:33:b3:33:62:18:71:df:
            d9:97:d3:a1:89:86:a8:0f:9a:d1:7a:e7:e6:d0:ef:7b:54:d9:
            33:ae:89:67:6e:a7:45:c6:4c:ae:00:d9:24:33:61:2a:39:82:
            c1:92:92:a5:e5:fa:05:68:3f:cd:24:34:b5:09:3a:1d:46:a3:
            95:bf:1e:05:6d:aa:46:72:68:94:ad:75:32:89:18:d3:f1:5b:
            fc:7b:ac:a2:5d:31:fe:ec:4b:53:7a:61:0a:6e:0b:6a:83:2b:
            32:5c:78:e4:62:0e:76:89:38:bf:f7:50:82:51:73:0a:8b:41:
            8c:b4:cc:a7:2e:62:dc:63:51:ac:61:00:ed:1c:88:ce:2d:ca:
            82:40:1a:aa:cf:a2:04:62:46:28:a6:bd:c2:ad:71:dd:a7:5e:
            a1:fe:ac:93:d8:70:5b:43:99:09:7d:8b:4a:b6:96:f7:95:bb:
            b7:9b:d8:f7:49:50:9d:73:d4:f5:a5:7e:fc:32:bb:b7:bd:b1:
            1a:d6:2e:41:c4:f4:62:aa:6c:f8:75:44:0b:ac:57:de:b8:80:
            a1:a9:2a:f8:a8:b3:96:bc:0a:7d:b1:82:8e:aa:c7:1f:91:10:
            dd:05:7f:a2:5d:14:0b:d5:1d:a3:40:3b:16:7d:e2:f1:32:37:
            79:19:23:63:99:67:13:51:37:f6:7c:b5:4f:4f:49:a2:5e:fb:
            a1:9f:3b:75:59:67:49:32:27:6a:5b:a5:e6:bf:2b:02:37:f9:
            14:38:2b:8d:4d:27:88:7c:dd:8a:75:75:79:bc:16:ff:df:b0:
            c8:69:69:36:44:1c:53:f4
    */
    let pem = include_str!("./rsa_csr.pem");
    let csr = CertReq::from_pem(pem.as_bytes()).unwrap();

    // Subject
    println!("subject: {}", csr.info.subject);
    assert_eq!(
        Name::from_str("EMAIL=blue@cosmian.com,CN=blue@cosmian.com,O=Cosmian,L=Paris,ST=IdF,C=FR")
            .unwrap(),
        Name::from_str(format!("{}", csr.info.subject).as_str()).unwrap()
    );

    let signature_algorithm = csr.algorithm.oid;
    assert_eq!(
        "sha256WithRSAEncryption",
        DB.by_oid(&signature_algorithm).unwrap()
    );
}

#[test]
fn ra_tls_csr_parsing_test() {
    /*
        Certificate Request:
        Data:
            Version: 1 (0x0)
            Subject: ST = Ile-de-France, L = Paris, C = FR, O = Cosmian Tech, CN = test.dev.cosmian.io
            Subject Public Key Info:
                Public Key Algorithm: id-ecPublicKey
                    Public-Key: (256 bit)
                    pub:
                        04:ee:42:37:2e:55:3d:b6:4e:b1:48:0d:08:8c:c4:
                        1b:67:53:16:6e:cf:39:74:5b:cb:e6:74:d5:03:32:
                        7e:46:6f:93:c1:83:19:24:c8:f8:0b:89:4c:71:a0:
                        f9:30:a9:f8:f6:f8:81:41:95:2a:ac:11:21:62:66:
                        70:48:6b:81:25
                    ASN1 OID: prime256v1
                    NIST CURVE: P-256
            Attributes:
                Requested Extensions:
                    X509v3 Subject Alternative Name:
                        DNS:test.dev.cosmian.io
                    1.2.840.113741.1337.6:
                        ..............r3..L..
    .....Bn....7B)..|o|.........................................................................e..ls%bt..d...k.f..h.......9.................................._.uS...P'.%.....-.ES..[.*EV.Z....................................................................................................
    ...............................................................=;........h_........I).))....../2eH.\j....N*..U...'..(./V.#"{f....4.1s).P........P....Z.h^.w.....%@@...........m.iW.G.(O.....k.4k1.......Bd...B..i..T.m@...=u....,...I.m..n1.....s.M.~...k...\.1 .......yx.....wM.p..T...................................OWu..P>...w.....V...p.....D..{.....................................................................................................................................................................C.VR......y..$:......X.......................................?...y...S~Kr3[.{{z..yR.p..e..D....,.h.#*#...a|C..9...$$.[.<.o.. ...........
....................b...-----BEGIN CERTIFICATE-----
MIIE8jCCBJigAwIBAgIUcy75l5AoAQv0d9MS53fhghPaDWAwCgYIKoZIzj0EAwIw
cDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR
SW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI
DAJDQTELMAkGA1UEBhMCVVMwHhcNMjMwMTE5MDkyNjQyWhcNMzAwMTE5MDkyNjQy
WjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK
DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
BAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHVa
uORu/+Z9pQd6NFsJBDkleRYABGRgEfvgkvkI9WxRN1zsX8+Ihpxd98essX+OUFbt
bLwtqeIglN7mLE1ytoujggMOMIIDCjAfBgNVHSMEGDAWgBSVb13NvRvh6UBJydT0
M84BVwveVDBrBgNVHR8EZDBiMGCgXqBchlpodHRwczovL2FwaS50cnVzdGVkc2Vy
dmljZXMuaW50ZWwuY29tL3NneC9jZXJ0aWZpY2F0aW9uL3Y0L3Bja2NybD9jYT1w
bGF0Zm9ybSZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFJVSrg4NrAk8s4jWEag1WESc
qCZMMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIICOwYJKoZIhvhNAQ0B
BIICLDCCAigwHgYKKoZIhvhNAQ0BAQQQ0jgEwWtijZFZgx0vN8BzZzCCAWUGCiqG
SIb4TQENAQIwggFVMBAGCyqGSIb4TQENAQIBAgEEMBAGCyqGSIb4TQENAQICAgEE
MBAGCyqGSIb4TQENAQIDAgEDMBAGCyqGSIb4TQENAQIEAgEDMBEGCyqGSIb4TQEN
AQIFAgIA/zARBgsqhkiG+E0BDQECBgICAP8wEAYLKoZIhvhNAQ0BAgcCAQAwEAYL
KoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0BAgoC
AQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZIhvhN
AQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAwEAYL
KoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQswHwYLKoZIhvhNAQ0BAhIE
EAQEAwP//wAAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhNAQ0B
BAQGMGBqAAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQTn8+G0wX
SsI2mGnRAY2BcTBEBgoqhkiG+E0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8wEAYL
KoZIhvhNAQ0BBwIBAQAwEAYLKoZIhvhNAQ0BBwMBAf8wCgYIKoZIzj0EAwIDSAAw
RQIhAP++EdrQfFlD3Av9U7VheOpB6Soh3YH1OwfTTGB1yhkPAiADCRu+zVn8Mu3F
yc2ogH3TNzwf8zdHdlsePNyID+FHDw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICljCCAj2gAwIBAgIVAJVvXc29G+HpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC
MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg
BgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs
IENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex
CzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB/7t21lXSO
2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z+UiRZCnqR7psOvgqFeSxlmTlJl
eTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS
BgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy
dmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d
zb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w+i6VYGW3UF/22uaXe0YJDj1Ue
nA+TjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN+
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
.
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:6a:b6:58:73:8f:21:7e:d6:b5:2b:f0:af:41:38:
        3f:ce:e2:35:9d:cd:1a:67:41:10:48:f1:13:c6:91:c6:61:bf:
        02:21:00:b9:ac:fe:f6:33:4c:7b:9b:8f:05:4f:44:ae:56:78:
        03:26:bb:6f:42:e1:50:b7:12:b7:a0:7a:07:96:88:89:ae
     */
    let pem = include_str!("./csr_ra_tls.pem");

    let csr = CertReq::from_pem(pem.as_bytes()).unwrap();

    let algorithm = &csr.info.public_key.algorithm;
    assert_eq!("id-ecPublicKey", DB.by_oid(&algorithm.oid).unwrap());
    println!("algorithm: {:?}", algorithm);
    let params = algorithm.parameters.as_ref().unwrap();
    assert_eq!(der::Tag::ObjectIdentifier, params.tag());
    assert_eq!(
        "secp256r1",
        DB.by_oid(&ObjectIdentifier::from_bytes(&params.value()).unwrap())
            .unwrap()
    );

    let bit_string = &csr.info.public_key.subject_public_key;
    println!("bit_string: {:?}", bit_string);
    println!("bit_string: {:?}", bit_string.as_bytes().unwrap());

    // Ths shows how to recover the public key using the p256 crate
    //
    // let pk = p256::PublicKey::from_public_key_der(csr.info.public_key.to_der().unwrap().as_slice())
    //     .unwrap();
    // println!("pk: {:?}", pk);
}
