//! Characterization tests pinning the BASE behavior of `key.rs`.

use std::sync::Arc;

use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::{
    KmsClient, KmsClientConfig,
};
use cosmian_logger::reexport::{tracing, tracing_subscriber};

use super::*;
use crate::error::KspError;

const VENDOR: &str = "cosmian";

const PEM_LINES: [&str; 28] = [
    "-----BEGIN PRIVATE KEY-----",
    "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDcI+9N4WCQ5eWq",
    "OTXHAv2oizBuStee5mMJYNlnaiB4lTd5TxRvJefLzE57k4YtKSKGYrwaZ7PBTv+N",
    "b7L22ZFmjpexmxdXbq8Hb7g7awjQd058M11AuhkpEgzH2dc7T44Furq7yL+xRdah",
    "TuVpnWURRrTwKLBQbs6EpzWxLb6D6YD8uBpbRzICOWwvOz/IlIHY/3R24GjxuxoJ",
    "sUUUYeJ45NZh2T4lmQY4OWWsi7HlaOlgOWWn1j6b4SsUkMFIcpfII7yqo9ozLUl6",
    "MYlRzqFzu2ryGq1af7W64ZoOno4LhF0Z5zoo9nhQKCUc2sTYxb1hxgObd6PQ726f",
    "JLNetm/hAgMBAAECggEAQr9GjMecPvLl6vIDwz696H+jhJ1+uThDqRFLedas18Lu",
    "mgKHQJguqxVcao21bjX9uN9xB1SQJTmttJW8nqojMwRjLD/JGQJ/YXLXWnS+rG6w",
    "RmpQiRKkFFbbtzDu2JXriwMuIUfiD38Mb8Z7OsW1YkKdFABSTWD7jy8f0YP8MwRm",
    "f3iGWpEF2OlQB+ZqpVMWcJ09pkPi/Y93FwywgEHHreXZeP49N2EQTW3VL534c9K4",
    "ygeNnc7vwn3zbc0Kt4kiSfp6Fn8aQjFi2ZbqC7kVXduB/IsF0jiB5FHRMKdSAxq7",
    "CfSxN4ihXQbH7GjJB4NU6slYAvKJ2nI8hBgKFX3A7QKBgQD+ixvKvoB+5YFumHTH",
    "6flgSd1p16tXgwwSyWV6yLFNusiNwmy3XRv0iLwzr9KtaOUWRL/CA0HPdchQHKxP",
    "hk7NEHfymhhFSvWIyxqHVoLV4nZEMMuumGWyjwAd2Fkia83j6b2q9V67YdgCXBZU",
    "f9tP0EomeKomOxXrcePaSAZFYwKBgQDdZm2CSxetbnxUZ8jsAEkr/44TY4agr8av",
    "qk0O/TB/g/MKRUWQuI+6WDrnYBnVRcJxBMVOZAqQmcc0C5WlCdynVssORKEPmhYd",
    "RmryIJCxXS91UMmZUEZ1Jn/ZvLm4bWulgpDrEWcoPRdfnDwQzW0BacZX9aqHRgz0",
    "gU7wl+uq6wKBgQDe4pxBWbJWa0x8tQ59BwmQIN26Elk8Vcm6oZM0gouOjqGST862",
    "eNdDtn9lmu2VXqZKa4SltAhqSq5OR+0x7V8O/P6q9feOpWZ+k6n1G/GQq633Y+rW",
    "RSe3xLPLbmgOVeuBSGkGS7jZx4FH/66l6xb0umRTb5E9zLsS4TUtK6giFQKBgQDL",
    "nfUe/FLlVRSRR/X4XnbtORYAbOsXAzH2wugl3eNpkv/FtVm6NJMy7QwXWUHI7GRc",
    "LugLJWS2Ake7bOAOrdg6Kk+LasC5qZunBuk6j4qjJDGOcmNGVhbGjUbOCIzBuhhj",
    "WoZPOm0mC7FgZD61sUgMIayhnrVbvagSgo4IJaA/SwKBgQD008yrE7OwQdWsyCyq",
    "N4F4BUxTKi2zKPPXDQArHYXHihDaoI4zmiZmLT94IneR1gvxUFCS0dz3QascaiYv",
    "uf90ygAY8udGIuA4a/NPvei8GMUW4ZD5C3xTOe1ijVe9J6kebCHrDky2Mp5+wKlC",
    "O57B5Cp/560aemCI7t1FS+BfHQ==",
    "-----END PRIVATE KEY-----",
];

const RSA_DER_HEX: &str = "308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100dc23ef4de16090e5e5aa3935c702fda88b306e4ad79ee6630960d9676a20789537794f146f25e7cbcc4e7b93862d29228662bc1a67b3c14eff8d6fb2f6d991668e97b19b17576eaf076fb83b6b08d0774e7c335d40ba1929120cc7d9d73b4f8e05bababbc8bfb145d6a14ee5699d651146b4f028b0506ece84a735b12dbe83e980fcb81a5b473202396c2f3b3fc89481d8ff7476e068f1bb1a09b1451461e278e4d661d93e259906383965ac8bb1e568e9603965a7d63e9be12b1490c1487297c823bcaaa3da332d497a318951cea173bb6af21aad5a7fb5bae19a0e9e8e0b845d19e73a28f6785028251cdac4d8c5bd61c6039b77a3d0ef6e9f24b35eb66fe102030100010282010042bf468cc79c3ef2e5eaf203c33ebde87fa3849d7eb93843a9114b79d6acd7c2ee9a028740982eab155c6a8db56e35fdb8df710754902539adb495bc9eaa233304632c3fc919027f6172d75a74beac6eb0466a508912a41456dbb730eed895eb8b032e2147e20f7f0c6fc67b3ac5b562429d1400524d60fb8f2f1fd183fc3304667f78865a9105d8e95007e66aa55316709d3da643e2fd8f77170cb08041c7ade5d978fe3d3761104d6dd52f9df873d2b8ca078d9dceefc27df36dcd0ab7892249fa7a167f1a423162d996ea0bb9155ddb81fc8b05d23881e451d130a752031abb09f4b13788a15d06c7ec68c9078354eac95802f289da723c84180a157dc0ed02818100fe8b1bcabe807ee5816e9874c7e9f96049dd69d7ab57830c12c9657ac8b14dbac88dc26cb75d1bf488bc33afd2ad68e51644bfc20341cf75c8501cac4f864ecd1077f29a18454af588cb1a875682d5e2764430cbae9865b28f001dd859226bcde3e9bdaaf55ebb61d8025c16547fdb4fd04a2678aa263b15eb71e3da4806456302818100dd666d824b17ad6e7c5467c8ec00492bff8e136386a0afc6afaa4d0efd307f83f30a454590b88fba583ae76019d545c27104c54e640a9099c7340b95a509dca756cb0e44a10f9a161d466af22090b15d2f7550c999504675267fd9bcb9b86d6ba58290eb1167283d175f9c3c10cd6d0169c657f5aa87460cf4814ef097ebaaeb02818100dee29c4159b2566b4c7cb50e7d07099020ddba12593c55c9baa19334828b8e8ea1924fceb678d743b67f659aed955ea64a6b84a5b4086a4aae4e47ed31ed5f0efcfeaaf5f78ea5667e93a9f51bf190abadf763ead64527b7c4b3cb6e680e55eb814869064bb8d9c78147ffaea5eb16f4ba64536f913dccbb12e1352d2ba8221502818100cb9df51efc52e555149147f5f85e76ed3916006ceb170331f6c2e825dde36992ffc5b559ba349332ed0c175941c8ec645c2ee80b2564b60247bb6ce00eadd83a2a4f8b6ac0b9a99ba706e93a8f8aa324318e7263465616c68d46ce088cc1ba18635a864f3a6d260bb160643eb5b1480c21aca19eb55bbda812828e0825a03f4b02818100f4d3ccab13b3b041d5acc82caa378178054c532a2db328f3d70d002b1d85c78a10daa08e339a26662d3f78227791d60bf1505092d1dcf741ab1c6a262fb9ff74ca0018f2e74622e0386bf34fbde8bc18c516e190f90b7c5339ed628d57bd27a91e6c21eb0e4cb6329e7ec0a9423b9ec1e42a7fe7ad1a7a6088eedd454be05f1d";
const RSA3_BLOB_HEX: &str = "525341330008000003000000000100008000000080000000010001dc23ef4de16090e5e5aa3935c702fda88b306e4ad79ee6630960d9676a20789537794f146f25e7cbcc4e7b93862d29228662bc1a67b3c14eff8d6fb2f6d991668e97b19b17576eaf076fb83b6b08d0774e7c335d40ba1929120cc7d9d73b4f8e05bababbc8bfb145d6a14ee5699d651146b4f028b0506ece84a735b12dbe83e980fcb81a5b473202396c2f3b3fc89481d8ff7476e068f1bb1a09b1451461e278e4d661d93e259906383965ac8bb1e568e9603965a7d63e9be12b1490c1487297c823bcaaa3da332d497a318951cea173bb6af21aad5a7fb5bae19a0e9e8e0b845d19e73a28f6785028251cdac4d8c5bd61c6039b77a3d0ef6e9f24b35eb66fe1fe8b1bcabe807ee5816e9874c7e9f96049dd69d7ab57830c12c9657ac8b14dbac88dc26cb75d1bf488bc33afd2ad68e51644bfc20341cf75c8501cac4f864ecd1077f29a18454af588cb1a875682d5e2764430cbae9865b28f001dd859226bcde3e9bdaaf55ebb61d8025c16547fdb4fd04a2678aa263b15eb71e3da48064563dd666d824b17ad6e7c5467c8ec00492bff8e136386a0afc6afaa4d0efd307f83f30a454590b88fba583ae76019d545c27104c54e640a9099c7340b95a509dca756cb0e44a10f9a161d466af22090b15d2f7550c999504675267fd9bcb9b86d6ba58290eb1167283d175f9c3c10cd6d0169c657f5aa87460cf4814ef097ebaaebdee29c4159b2566b4c7cb50e7d07099020ddba12593c55c9baa19334828b8e8ea1924fceb678d743b67f659aed955ea64a6b84a5b4086a4aae4e47ed31ed5f0efcfeaaf5f78ea5667e93a9f51bf190abadf763ead64527b7c4b3cb6e680e55eb814869064bb8d9c78147ffaea5eb16f4ba64536f913dccbb12e1352d2ba82215cb9df51efc52e555149147f5f85e76ed3916006ceb170331f6c2e825dde36992ffc5b559ba349332ed0c175941c8ec645c2ee80b2564b60247bb6ce00eadd83a2a4f8b6ac0b9a99ba706e93a8f8aa324318e7263465616c68d46ce088cc1ba18635a864f3a6d260bb160643eb5b1480c21aca19eb55bbda812828e0825a03f4bf4d3ccab13b3b041d5acc82caa378178054c532a2db328f3d70d002b1d85c78a10daa08e339a26662d3f78227791d60bf1505092d1dcf741ab1c6a262fb9ff74ca0018f2e74622e0386bf34fbde8bc18c516e190f90b7c5339ed628d57bd27a91e6c21eb0e4cb6329e7ec0a9423b9ec1e42a7fe7ad1a7a6088eedd454be05f1d42bf468cc79c3ef2e5eaf203c33ebde87fa3849d7eb93843a9114b79d6acd7c2ee9a028740982eab155c6a8db56e35fdb8df710754902539adb495bc9eaa233304632c3fc919027f6172d75a74beac6eb0466a508912a41456dbb730eed895eb8b032e2147e20f7f0c6fc67b3ac5b562429d1400524d60fb8f2f1fd183fc3304667f78865a9105d8e95007e66aa55316709d3da643e2fd8f77170cb08041c7ade5d978fe3d3761104d6dd52f9df873d2b8ca078d9dceefc27df36dcd0ab7892249fa7a167f1a423162d996ea0bb9155ddb81fc8b05d23881e451d130a752031abb09f4b13788a15d06c7ec68c9078354eac95802f289da723c84180a157dc0ed";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap(), 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Client that never reaches a server (port 1 is closed).
fn offline_client() -> Arc<KmsClient> {
    let mut config = KmsClientConfig::default();
    config.http_config.server_url = "http://127.0.0.1:1".to_owned();
    Arc::new(KmsClient::new_with_config(config).unwrap())
}

/// Run `f` with a DEBUG-level subscriber so `debug!` arguments are evaluated.
fn with_debug<T>(f: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_writer(std::io::sink)
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .finish();
    tracing::subscriber::with_default(subscriber, f)
}

#[derive(Clone)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` under a DEBUG subscriber and return its result with the captured log text.
fn with_captured_debug<T>(f: impl FnOnce() -> T) -> (T, String) {
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&buf));
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    (result, text)
}

fn pending(import_blob: Option<Vec<u8>>, algorithm: KeyAlgorithm) -> PendingCreation {
    PendingCreation {
        algorithm,
        key_name: "pending-key".to_owned(),
        usage: KeyUsage::SIGN | KeyUsage::DECRYPT,
        export_policy: ExportPolicy {
            allow_export: true,
            allow_plaintext_export: false,
        },
        import_blob,
    }
}

fn pending_ctx(import_blob: Option<Vec<u8>>, algorithm: KeyAlgorithm) -> CngKeyCtx {
    CngKeyCtx {
        magic: KEY_CTX_MAGIC,
        client: offline_client(),
        vendor_id: VENDOR.to_owned(),
        state: KeyState::Pending(pending(import_blob, algorithm)),
    }
}

#[test]
fn characterization_key_algorithm_cng_alg_id() {
    assert_eq!(KeyAlgorithm::Rsa { bits: 1 }.cng_alg_id(), "RSA");
    assert_eq!(KeyAlgorithm::Rsa { bits: 4096 }.cng_alg_id(), "RSA");
    assert_eq!(
        KeyAlgorithm::Ec {
            curve: EcCurve::P256
        }
        .cng_alg_id(),
        "ECDSA_P256"
    );
    assert_eq!(
        KeyAlgorithm::Ec {
            curve: EcCurve::P384
        }
        .cng_alg_id(),
        "ECDSA_P384"
    );
    assert_eq!(
        KeyAlgorithm::Ec {
            curve: EcCurve::P521
        }
        .cng_alg_id(),
        "ECDSA_P521"
    );
}

#[test]
fn characterization_key_algorithm_from_cng_name() {
    assert_eq!(
        KeyAlgorithm::from_cng_name("RSA", 0).unwrap(),
        KeyAlgorithm::Rsa { bits: 2048 }
    );
    assert_eq!(
        KeyAlgorithm::from_cng_name("rsa", 3072).unwrap(),
        KeyAlgorithm::Rsa { bits: 3072 }
    );
    for (name, curve) in [
        ("ECDSA_P256", EcCurve::P256),
        ("ecdh_p256", EcCurve::P256),
        ("ECDSA_P384", EcCurve::P384),
        ("ECDH_P384", EcCurve::P384),
        ("ecdsa_p521", EcCurve::P521),
        ("ECDH_P521", EcCurve::P521),
    ] {
        assert_eq!(
            KeyAlgorithm::from_cng_name(name, 12345).unwrap(),
            KeyAlgorithm::Ec { curve }
        );
    }
    assert_eq!(
        KeyAlgorithm::from_cng_name("dsa", 0)
            .unwrap_err()
            .to_string(),
        "algorithm not supported: DSA"
    );
    assert_eq!(
        KeyAlgorithm::from_cng_name("", 0).unwrap_err().to_string(),
        "algorithm not supported: "
    );
}

#[test]
fn characterization_key_usage_bits() {
    assert_eq!(KeyUsage::DECRYPT.bits(), 1);
    assert_eq!(KeyUsage::SIGN.bits(), 2);
    assert_eq!(KeyUsage::KEY_AGREEMENT.bits(), 4);
    assert_eq!(KeyUsage::default().bits(), 0);
    assert_eq!(KEY_CTX_MAGIC, 0x0C05_1AAC);
}

#[test]
fn characterization_ctx_persisted_accessors() {
    let ctx = CngKeyCtx::new_persisted(
        offline_client(),
        VENDOR.to_owned(),
        "priv-uid".to_owned(),
        Some("pub-uid".to_owned()),
        KeyAlgorithm::Rsa { bits: 3072 },
        "my-key".to_owned(),
        KeyUsage::SIGN,
        ExportPolicy {
            allow_export: false,
            allow_plaintext_export: true,
        },
    );
    assert_eq!(ctx.magic, KEY_CTX_MAGIC);
    assert_eq!(ctx.vendor_id, VENDOR);
    assert_eq!(ctx.priv_uid().unwrap(), "priv-uid");
    assert_eq!(ctx.pub_uid().unwrap(), "pub-uid");
    assert_eq!(ctx.key_name(), "my-key");
    assert_eq!(ctx.algorithm(), &KeyAlgorithm::Rsa { bits: 3072 });
    assert_eq!(ctx.usage().bits(), 2);
    assert!(!ctx.export_policy().allow_export);
    assert!(ctx.export_policy().allow_plaintext_export);
}

#[test]
fn characterization_ctx_persisted_without_pub_uid_falls_back() {
    let ctx = CngKeyCtx::new_persisted(
        offline_client(),
        VENDOR.to_owned(),
        "priv-only".to_owned(),
        None,
        KeyAlgorithm::Ec {
            curve: EcCurve::P384,
        },
        "ec-key".to_owned(),
        KeyUsage::KEY_AGREEMENT,
        ExportPolicy::default(),
    );
    assert_eq!(ctx.pub_uid().unwrap(), "priv-only");
    assert_eq!(ctx.priv_uid().unwrap(), "priv-only");
    assert_eq!(ctx.usage().bits(), 4);
    assert!(!ctx.export_policy().allow_export);
    // already finalized: idempotent no-op
    let mut ctx = ctx;
    ctx.finalize().unwrap();
    assert_eq!(ctx.priv_uid().unwrap(), "priv-only");
}

#[test]
fn characterization_ctx_pending_accessors_and_errors() {
    let ctx = CngKeyCtx::new_pending(
        offline_client(),
        VENDOR.to_owned(),
        pending(
            None,
            KeyAlgorithm::Ec {
                curve: EcCurve::P521,
            },
        ),
    );
    assert_eq!(ctx.magic, KEY_CTX_MAGIC);
    assert_eq!(ctx.key_name(), "pending-key");
    assert_eq!(
        ctx.algorithm(),
        &KeyAlgorithm::Ec {
            curve: EcCurve::P521
        }
    );
    assert_eq!(ctx.usage().bits(), 3);
    assert!(ctx.export_policy().allow_export);
    assert!(!ctx.export_policy().allow_plaintext_export);
    let msg = "invalid parameter: Key not yet finalized";
    assert_eq!(ctx.priv_uid().unwrap_err().to_string(), msg);
    assert_eq!(ctx.pub_uid().unwrap_err().to_string(), msg);
    assert_eq!(ctx.export_public_blob().unwrap_err().to_string(), msg);
    assert_eq!(ctx.export_private_pkcs8().unwrap_err().to_string(), msg);
}

#[test]
fn characterization_ctx_handle_roundtrip() {
    // SAFETY-relevant: the production API takes raw handles, so `unsafe` is forced here.
    assert!(matches!(
        unsafe { CngKeyCtx::from_handle(0) },
        Err(KspError::InvalidHandle)
    ));
    assert_eq!(
        unsafe { CngKeyCtx::from_handle(0) }
            .map(|_| ())
            .unwrap_err()
            .to_string(),
        "invalid handle"
    );
    unsafe { CngKeyCtx::free(0) };

    let ctx = Box::new(pending_ctx(None, KeyAlgorithm::Rsa { bits: 2048 }));
    let handle = Box::into_raw(ctx).expose_provenance();
    let got = unsafe { CngKeyCtx::from_handle(handle) }.unwrap();
    assert_eq!(got.key_name(), "pending-key");
    assert_eq!(got.magic, KEY_CTX_MAGIC);
    got.magic = 0x1234;
    assert_eq!(
        unsafe { CngKeyCtx::from_handle(handle) }
            .map(|_| ())
            .unwrap_err()
            .to_string(),
        "invalid handle"
    );
    unsafe { CngKeyCtx::free(handle) };
}

fn assert_finalize_fails_pending(blob: Option<Vec<u8>>, algorithm: KeyAlgorithm) -> String {
    let mut ctx = pending_ctx(blob, algorithm);
    let err = with_debug(|| ctx.finalize()).unwrap_err().to_string();
    // a failed finalize leaves the key pending
    assert!(matches!(ctx.state, KeyState::Pending(_)));
    err
}

#[test]
fn characterization_finalize_pem_invalid_utf8() {
    let err = assert_finalize_fails_pending(
        Some(b"-----\xff\xfe".to_vec()),
        KeyAlgorithm::Rsa { bits: 2048 },
    );
    assert_eq!(err, "invalid parameter: PEM is not valid UTF-8");
}

#[test]
fn characterization_finalize_pem_bad_base64() {
    let err = assert_finalize_fails_pending(
        Some(b"-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n".to_vec()),
        KeyAlgorithm::Rsa { bits: 2048 },
    );
    assert_eq!(
        err,
        "invalid parameter: PEM base64 decode failed: Invalid symbol 33, offset 0."
    );
}

#[test]
fn characterization_finalize_rsa3_blob_short_header() {
    let err =
        assert_finalize_fails_pending(Some(b"RSA3abc".to_vec()), KeyAlgorithm::Rsa { bits: 2048 });
    assert_eq!(
        err,
        "invalid parameter: RSA full private blob too short for header"
    );
}

#[test]
fn characterization_finalize_rsa3_blob_reaches_backend() {
    let mut blob = b"RSA3".to_vec();
    blob.extend_from_slice(&[0_u8; 20]);
    let err = assert_finalize_fails_pending(Some(blob), KeyAlgorithm::Rsa { bits: 2048 });
    assert_eq!(
        err,
        "KMS backend error: HTTP Client: HTTP request failed: client error (Connect)"
    );
}

#[test]
fn characterization_finalize_raw_der_and_pem_reach_backend() {
    // exactly 4 bytes starting with "RSA3" is NOT treated as an RSA3 blob (len > 4 needed)
    let err =
        assert_finalize_fails_pending(Some(b"RSA3".to_vec()), KeyAlgorithm::Rsa { bits: 2048 });
    assert_eq!(
        err,
        "KMS backend error: HTTP Client: HTTP request failed: client error (Connect)"
    );
    let mut pem = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
    for line in PEM_LINES.iter().skip(1).take(PEM_LINES.len() - 2) {
        pem.extend_from_slice(line.as_bytes());
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    let err = assert_finalize_fails_pending(Some(pem), KeyAlgorithm::Rsa { bits: 2048 });
    assert_eq!(
        err,
        "KMS backend error: HTTP Client: HTTP request failed: client error (Connect)"
    );
}

#[test]
fn characterization_finalize_generate_reaches_backend() {
    let err = assert_finalize_fails_pending(None, KeyAlgorithm::Rsa { bits: 2048 });
    assert_eq!(
        err,
        "KMS backend error: HTTP Client: HTTP request failed: client error (Connect)"
    );
    for curve in [EcCurve::P256, EcCurve::P384, EcCurve::P521] {
        let err = assert_finalize_fails_pending(None, KeyAlgorithm::Ec { curve });
        assert_eq!(
            err,
            "KMS backend error: HTTP Client: HTTP request failed: client error (Connect)"
        );
    }
}

#[test]
fn characterization_export_persisted_reaches_backend() {
    for algorithm in [
        KeyAlgorithm::Rsa { bits: 2048 },
        KeyAlgorithm::Ec {
            curve: EcCurve::P256,
        },
    ] {
        for pub_uid in [Some("pub".to_owned()), None] {
            let ctx = CngKeyCtx::new_persisted(
                offline_client(),
                VENDOR.to_owned(),
                "priv".to_owned(),
                pub_uid,
                algorithm.clone(),
                "k".to_owned(),
                KeyUsage::SIGN,
                ExportPolicy::default(),
            );
            assert_eq!(
                ctx.export_public_blob().unwrap_err().to_string(),
                "KMS backend error: Get: HTTP Client: HTTP request failed: client error (Connect)"
            );
            assert_eq!(
                ctx.export_private_pkcs8().unwrap_err().to_string(),
                "KMS backend error: Get: HTTP Client: HTTP request failed: client error (Connect)"
            );
        }
    }
}

#[test]
fn characterization_decode_pem_to_der() {
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        PEM_LINES.get(1..PEM_LINES.len() - 1).unwrap().join("\n")
    );
    let der = decode_pem_to_der(pem.as_bytes()).unwrap();
    assert_eq!(to_hex(&der), RSA_DER_HEX);
    assert_eq!(
        decode_pem_to_der(b"-----BEGIN-----\nAQID\n-----END-----").unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(decode_pem_to_der(b"").unwrap(), Vec::<u8>::new());
    assert_eq!(
        decode_pem_to_der(&[0xFF]).unwrap_err().to_string(),
        "invalid parameter: PEM is not valid UTF-8"
    );
    assert_eq!(
        decode_pem_to_der(b"A").unwrap_err().to_string(),
        "invalid parameter: PEM base64 decode failed: Invalid input length: 1"
    );
}

#[test]
fn characterization_rsa3_fixture_converts_to_fixture_der_structure() {
    let der = crate::blob::pkcs8_from_rsa_full_private_blob(&unhex(RSA3_BLOB_HEX)).unwrap();
    assert_eq!(der.len(), 1219);
    assert_eq!(
        to_hex(der.get(..32).unwrap()),
        "308204bf020100300d06092a864886f70d0101010500048204a9308204a50201"
    );
}

#[cfg(feature = "non-fips")]
mod with_server {
    use serial_test::serial;
    use test_kms_server::start_default_test_kms_server;

    use super::*;
    use crate::backend;

    fn test_client() -> Arc<KmsClient> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ctx = rt.block_on(async { start_default_test_kms_server().await });
        drop(rt);
        Arc::new(ctx.get_owner_client())
    }

    fn cleanup(client: &KmsClient, ctx: &CngKeyCtx) {
        if let Ok(priv_uid) = ctx.priv_uid() {
            drop(backend::revoke_key(client, priv_uid));
            drop(backend::destroy_key(client, priv_uid));
        }
        if let Ok(pub_uid) = ctx.pub_uid() {
            drop(backend::revoke_key(client, pub_uid));
            drop(backend::destroy_key(client, pub_uid));
        }
    }

    fn finalize_ctx(
        client: &Arc<KmsClient>,
        name: &str,
        blob: Option<Vec<u8>>,
        algorithm: KeyAlgorithm,
    ) -> CngKeyCtx {
        let mut ctx = CngKeyCtx {
            magic: KEY_CTX_MAGIC,
            client: Arc::clone(client),
            vendor_id: backend::query_vendor_id(client),
            state: KeyState::Pending(PendingCreation {
                key_name: name.to_owned(),
                ..pending(blob, algorithm)
            }),
        };
        with_debug(|| ctx.finalize()).unwrap();
        ctx
    }

    #[test]
    #[serial]
    fn characterization_finalize_generate_rsa_and_export() {
        let client = test_client();
        let ctx = finalize_ctx(
            &client,
            "char-gen-rsa",
            None,
            KeyAlgorithm::Rsa { bits: 2048 },
        );
        assert_ne!(ctx.priv_uid().unwrap(), ctx.pub_uid().unwrap());
        assert_eq!(ctx.key_name(), "char-gen-rsa");
        assert_eq!(ctx.usage().bits(), 3);
        let blob = ctx.export_public_blob().unwrap();
        assert_eq!(blob.len(), 24 + 3 + 256);
        assert_eq!(
            to_hex(blob.get(..24).unwrap()),
            "52534131000800000300000000010000".to_owned() + "0000000000000000"
        );
        assert!(!ctx.export_private_pkcs8().unwrap().is_empty());
        cleanup(&client, &ctx);
    }

    #[test]
    #[serial]
    fn characterization_finalize_generate_ec_and_export() {
        let client = test_client();
        for (curve, coord, head) in [
            (EcCurve::P256, 32_usize, "45435331"),
            (EcCurve::P384, 48, "45435333"),
            (EcCurve::P521, 66, "45435335"),
        ] {
            let ctx = finalize_ctx(
                &client,
                &format!("char-gen-ec-{coord}"),
                None,
                KeyAlgorithm::Ec { curve },
            );
            let blob = ctx.export_public_blob().unwrap();
            assert_eq!(blob.len(), 8 + 2 * coord);
            assert_eq!(to_hex(blob.get(..4).unwrap()), head);
            assert_eq!(
                blob.get(4..8).unwrap(),
                u32::try_from(coord).unwrap().to_le_bytes()
            );
            cleanup(&client, &ctx);
        }
    }

    fn assert_imported(client: &Arc<KmsClient>, name: &str, blob: Vec<u8>) {
        let ctx = finalize_ctx(client, name, Some(blob), KeyAlgorithm::Rsa { bits: 2048 });
        // BASE: the public export of an imported private key fails to parse.
        assert_eq!(
            ctx.export_public_blob().unwrap_err().to_string(),
            "invalid parameter: Expected INTEGER (exponent)"
        );
        let exported = ctx.export_private_pkcs8().unwrap();
        assert_eq!(exported.len(), 1219);
        assert_eq!(
            to_hex(exported.get(..24).unwrap()),
            "308204bf020100300d06092a864886f70d01010105000482"
        );
        cleanup(client, &ctx);
    }

    #[test]
    #[serial]
    fn characterization_finalize_import_pem_der_and_rsa3() {
        let client = test_client();
        let mut pem = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
        for line in PEM_LINES.iter().skip(1).take(PEM_LINES.len() - 2) {
            pem.extend_from_slice(line.as_bytes());
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        assert_imported(&client, "char-imp-pem", pem);
        assert_imported(&client, "char-imp-der", unhex(RSA_DER_HEX));
        assert_imported(&client, "char-imp-rsa3", unhex(RSA3_BLOB_HEX));
    }
}

#[test]
fn characterization_finalize_logs_import_blob_prefix() {
    let mut short = pending_ctx(Some(b"RSA3abc".to_vec()), KeyAlgorithm::Rsa { bits: 2048 });
    let (result, log) = with_captured_debug(|| short.finalize());
    assert!(result.is_err());
    assert!(log.contains(
        "DEBUG cosmian_cng::key: CNG KSP: finalize import blob len=7, first_bytes=[82, 83, 65, 51, 97, 98, 99] "
    ));

    let blob: Vec<u8> = (0_u8..30).collect();
    let mut long = pending_ctx(Some(blob), KeyAlgorithm::Rsa { bits: 2048 });
    let (result, log) = with_captured_debug(|| long.finalize());
    assert!(result.is_err());
    assert!(log.contains(
        "DEBUG cosmian_cng::key: CNG KSP: finalize import blob len=30, first_bytes=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19] "
    ));
}
