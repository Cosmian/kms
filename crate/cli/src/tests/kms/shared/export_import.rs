use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::Engine;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    export_utils::{ExportKeyFormat, WrappingAlgorithm},
    import_utils::{ImportKeyFormat, KeyUsage},
};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use cosmian_logger::warn;
use cosmian_logger::{debug, info, log_init};
use openssl::pkey::PKey;
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::error::result::KmsCliResultHelper;
use crate::{
    actions::kms::{
        shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    cli_bail,
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_wrap_on_export_unwrap_on_import() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Generate a symmetric wrapping key
    let kek_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Generate a symmetric key to wrap
    let dek_path = tmp_path.join("dek.key");
    let dek_file = dek_path.to_str().unwrap().to_owned();
    let dek_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // Export and import the key with different block cipher modes
    for wrapping_algorithm in [WrappingAlgorithm::AesGCM, WrappingAlgorithm::NistKeyWrap] {
        debug!("wrapping algorithm: {wrapping_algorithm:?}",);
        ExportSecretDataOrKeyAction {
            key_id: Some(dek_id.clone()),
            key_file: dek_path.clone(),
            wrap_key_id: Some(kek_id.clone()),
            wrapping_algorithm: Some(wrapping_algorithm),
            ..Default::default()
        }
        .run(ctx.get_user_client())
        .await?;

        let imported_key_id = ImportSecretDataOrKeyAction {
            key_file: PathBuf::from(&dek_file),
            key_id: Some(dek_id.clone()),
            unwrap: true,
            replace_existing: true,
            key_usage: None,
            ..Default::default()
        }
        .run(ctx.get_user_client())
        .await?
        .to_string();
        debug!("imported key id: {imported_key_id}",);
    }

    Ok(())
}

const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzdXCsuC+YqBvc
gGTe9oF4L3Ni0pj2pk6yTfGqt1Az/08IvueZsetFnrIew9ZSaACobSlwIs2moc3s
ukkYTQpDxNEeRg1lPQArDlhz+twBbLx0q31RWwT0kW8R/+UW5GO4uehUhduAgi6s
isxSpqXkv3/00v9rIAtdpfhAdEs8Rz8EAza236EDHC6SiXVbTKn2vLAe/0JX4egP
5/LUo7okTHOyQHhw6cc8B1HnGen5fcMwpEO4I1gQZSDRio2718njTIegUs1yV87W
lxhudkP8SfMKEHWJUy1wlYbkIsKdE/B822XeVKz22MGokJjdyiZsuhYhzgaouzK3
yE2erWwVAgMBAAECggEAHztuaWThxbXmKW1AAOzSUgYiFP4VaIG/mvkFOOKP5wjF
Kr68xGsqSNLKaZ/IJk3a5XUgG9e2xkwNMGioTX4k7e/sPBJRhP/Fjni/7KlpTics
MjrhQ74tQdooxC9uoZoMf+r88+7a6YXelSFP14eQwhuQ650oHi70w27d4mvK5zms
sqd2aM1ousSfTGikSQxyszdsFkJgVKBoSdh/YIp83bcL1bKz8iairaNCFaBSQe+Q
3JI2evfPCZ0bijG+CzA80/86pFMJKOT9sksp0KdCf2Azu+Q8wFv3dZwgayk2KBVQ
TyPaI3YJ12rV9OI2OngNg2PM+pTyyZQjnquAOeaJQQKBgQD2/HO54v4OZtwSSr3d
J43DH5re1ZBFPik2pAQRPBdillwAq+4MbNimupjtFYevoGhDxzMB4TFa+qvDSYlB
RAOktBsYjsdVBRLB4Kfqfwd00dxg+4opGJOVupNTijf4fKhWyM3vF4gIy104Y9TK
J88BAN4AyTLpjl2EPrZdJBVrVQKBgQC6AhdyF9TP5ccCCUEPjcWyaUMQDinInmpe
PxnId9Iyry0n5ArR2e+nhCpRvj4iqbWw4I+eRkmbgfvA8Z5Sq4YmLYlY27IZKr7Z
29E5cT8TsqzAD5dkidNaju+TjIQdPSIuIcgdTIKq53+z2kS5VW8XRWp4fM4wlxC9
6eRRJqN9wQKBgDbFEtCk4pvE+YZg5quVKt2bM5e4mi6Qs0j3pCNCRRlKqIpJlhdR
R9XpSSJCBP3QP27QTKJdErnPHqnGs9YyQ/CRM/UFLHTRFDDEJdhdZQTlyM4E2cV1
Or0YS7VZ0EGdOyNLkkcz26m/lyN7F+PgYgoh7BkWhOC//kLmOUB8UPelAoGAU9C7
ddrNNzzn1sAKxBJzIfiSknp/U3omnf87A/0SB2quI0p7oaHdfpNsalcaMo5cY65c
qMotQthoc8GsQL4vfaaJPDQK5ZJAW3TUq1ifPqYFd6nO4yvDxAuiYs8vfOleLIFm
ZeVi/9W+0nEpBIY9v7O0zUQXuQdpMNpi2jpZ80ECgYADEWWxeNCtz9049INp92Fs
63eTetFy6wG41v/ngrxDvgb13zDDX0dFM5kVNev3j98QKiQ+x/46j7fFyhgl1Dup
qeDmXs6dH40L2I0TLPF0Ax2V7DgXwgeCPnlwLrf96xpV+2UXt1zvqzU8BdK8qT4b
yLT7mm6+hAwMp3y0u6oBTA==
-----END PRIVATE KEY-----";

const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3VwrLgvmKgb3IBk3vaB
eC9zYtKY9qZOsk3xqrdQM/9PCL7nmbHrRZ6yHsPWUmgAqG0pcCLNpqHN7LpJGE0K
Q8TRHkYNZT0AKw5Yc/rcAWy8dKt9UVsE9JFvEf/lFuRjuLnoVIXbgIIurIrMUqal
5L9/9NL/ayALXaX4QHRLPEc/BAM2tt+hAxwukol1W0yp9rywHv9CV+HoD+fy1KO6
JExzskB4cOnHPAdR5xnp+X3DMKRDuCNYEGUg0YqNu9fJ40yHoFLNclfO1pcYbnZD
/EnzChB1iVMtcJWG5CLCnRPwfNtl3lSs9tjBqJCY3combLoWIc4GqLsyt8hNnq1s
FQIDAQAB
-----END PUBLIC KEY-----";

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn test_openssl_cli_compat() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info"));

    if let Ok(output) = tokio::process::Command::new("openssl")
        .arg("version")
        .output()
        .await
    {
        if !output.status.success() {
            warn!("test_openssl_cli_compat: openssl CLI call failed, skipping test: {output:#?}");
            return Ok(());
        }
        let res = String::from_utf8(output.stdout)
            .context("test_openssl_cli_compat: openssl CLI output is not valid UTF-8)")?;
        if !res.to_lowercase().contains("openssl 3") {
            warn!(
                "test_openssl_cli_compat: openssl version is not OpenSSL 3: {res}, skipping test"
            );
            return Ok(());
        }
    } else {
        warn!("test_openssl_cli_compat: openssl CLI not found, skipping test");
        return Ok(());
    }

    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let dek = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";

    // write RSA private key to file
    let priv_key_file = tmp_path.join("rsa_private_key.pem");
    fs::write(&priv_key_file, RSA_PRIVATE_KEY)?;
    // write RSA public key to file
    let pub_key_file = tmp_path.join("rsa_public_key.pem");
    fs::write(&pub_key_file, RSA_PUBLIC_KEY)?;
    // write dek to file
    let dek_file = tmp_path.join("dek.bin");
    fs::write(&dek_file, hex::decode(dek)?)?;

    let priv_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&priv_key_file),
        key_format: ImportKeyFormat::Pem,
        key_usage: Some(vec![KeyUsage::UnwrapKey, KeyUsage::Decrypt]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?
    .to_string();
    info!("priv_key_id: {priv_key_id}");

    let pub_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&pub_key_file),
        key_format: ImportKeyFormat::Pem,
        key_usage: Some(vec![KeyUsage::WrapKey, KeyUsage::Encrypt]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?
    .to_string();
    info!("pub_key_id: {pub_key_id}");

    let dek_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&dek_file),
        key_format: ImportKeyFormat::Aes,
        key_usage: Some(vec![KeyUsage::Decrypt, KeyUsage::Encrypt]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?
    .to_string();
    info!("dek_id: {dek_id}");

    // SHA256
    let rec_dek =
        test_openssl_cli_compat_inner(ctx, tmp_path, &dek_id, &pub_key_id, &priv_key_file, false)
            .await?;
    assert_eq!(rec_dek, hex::decode(dek)?);

    // SHA1
    let rec_dek =
        test_openssl_cli_compat_inner(ctx, tmp_path, &dek_id, &pub_key_id, &priv_key_file, true)
            .await?;
    assert_eq!(rec_dek, hex::decode(dek)?);

    Ok(())
}

async fn test_openssl_cli_compat_inner(
    ctx: &TestsContext,
    tmp_path: &Path,
    dek_id: &str,
    pub_key_id: &str,
    priv_key_file: &PathBuf,
    use_sha1: bool,
) -> KmsCliResult<Vec<u8>> {
    let wrapped_key_file = tmp_path.join("wrapped_key.bin");
    ExportSecretDataOrKeyAction {
        key_id: Some(dek_id.to_owned()),
        key_file: wrapped_key_file.clone(),
        wrap_key_id: Some(pub_key_id.to_owned()),
        wrapping_algorithm: Some(if use_sha1 {
            WrappingAlgorithm::RsaAesKeyWrapSha1
        } else {
            WrappingAlgorithm::RsaAesKeyWrap
        }),
        export_format: ExportKeyFormat::Raw,
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    // read wrapped key from file
    let wrapped_key = fs::read(&wrapped_key_file)?;

    // the last 40 bytes are the AES_KEY_WRAP_PAD (RFC 5649)
    assert_eq!(wrapped_key.len(), 2048 / 8 + 40);

    // write wrapped key to file
    let oaep_encapsulation = &wrapped_key[..wrapped_key.len() - 40];
    let rsa_oaep_encapsulation_file = tmp_path.join("rsa_oaep_encapsulation.bin");
    fs::write(&rsa_oaep_encapsulation_file, oaep_encapsulation)?;

    let rfc5649_encapsulation = &wrapped_key[wrapped_key.len() - 40..];
    let rfc5649_encapsulation_file = tmp_path.join("rfc5649_encapsulation.bin");
    fs::write(&rfc5649_encapsulation_file, rfc5649_encapsulation)?;

    // Execute OpenSSL command to decrypt the RSA OAEP encapsulation
    let aes_kek_file = tmp_path.join("aes_kek.bin");
    let output = tokio::process::Command::new("openssl")
        .arg("pkeyutl")
        .arg("-decrypt")
        .arg("-inkey")
        .arg(priv_key_file)
        .arg("-in")
        .arg(&rsa_oaep_encapsulation_file)
        .arg("-out")
        .arg(&aes_kek_file)
        .arg("-pkeyopt")
        .arg("rsa_padding_mode:oaep")
        .arg("-pkeyopt")
        .arg(if use_sha1 {
            "rsa_oaep_md:sha1"
        } else {
            "rsa_oaep_md:sha256"
        })
        .arg("-pkeyopt")
        .arg(if use_sha1 {
            "rsa_mgf1_md:sha1"
        } else {
            "rsa_mgf1_md:sha256"
        })
        .output()
        .await?;

    if !output.status.success() {
        cli_bail!("test_openssl_cli_compat: RSA OAEP openssl pkeyutl failed: {output:?}");
    }
    // recover the AES_KEK from the decrypted key
    let aes_kek = fs::read(&aes_kek_file)?;
    assert_eq!(aes_kek.len(), 32);

    // Execute OpenSSL command to decrypt the RFC 5649 encapsulation
    let rec_dek_file = tmp_path.join("rec_dek.bin");
    let output = tokio::process::Command::new("openssl")
        .arg("enc")
        .arg("-d")
        .arg("-id-aes256-wrap-pad")
        .arg("-iv")
        .arg("A65959A6")
        .arg("-K")
        .arg(hex::encode(&aes_kek))
        .arg("-in")
        .arg(&rfc5649_encapsulation_file)
        .arg("-out")
        .arg(&rec_dek_file)
        .output()
        .await?;

    if !output.status.success() {
        cli_bail!("test_openssl_cli_compat: RFC5649 pkeyutl failed: {output:?}");
    }

    // read recovered dek from file
    let rec_dek = std::fs::read(&rec_dek_file)?;
    assert_eq!(rec_dek.len(), 32);

    Ok(rec_dek)
}

const GOOGLE_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApg4Oo7ygEBmAlzhUZFm2
75K999TqNjvgiAi/pSzAJS6XO3sa346zZYjZpj4l4OP5T2xlmPXoF/igbCO9jAeW
+Y8N1VZ6LRvPQ+ndP22ZyL/kiJFc1jUVrBm9ItzTGSO44Z4A77uDga1eAWkIg/9i
mp+tY0qmlmhnRHwoQkZDU1c08SLA4p6IV3NssgwKaN8KwM53KDxw6kDo0INfS+Ym
MNZ8oHg8FJ5Q3ExR54fD1/WFngOSexpzNtGvZGMaoCnISMumEo8nfENtMXxnLquu
BvYAOQEQs7vl0ES/DD0dNzVonZTo9/c8yr0SlcWg8Uy7XkD5FQSE5A87pOZUDEcD
FQIDAQAB
-----END PUBLIC KEY-----";

const GOOGLE_RSA_3072_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA4IC9RHuBZN0JiDhmTahs
CReA/T9sClL1Y4W52let67FLli50pdltx6LktI722DhKQTkNIwLZvnih27cOp+Vq
Ryp3yVWDWcr5f/MgRwDbcUXfNDobyWd5f2N/8XMYQV3GVTpP3Lyx4QcdzOG0FTwM
RuiukTMowISGVGvRTGQofqqJFiFuzxRdjfkhJcW7LyWhjNRn//YDf09ziOfwvEAQ
QmUQNdmoiziJXXBvUQ6mE/V4Dd1c/8FzCKxZVMSPzfUcB1L3xs4Uw1rAOdunC7tb
KKAtHuhzL1Vn8liT2Mb2xP7319+WeP0C3mF0dKv8xXKxi96N11fXpPizMypf35aW
gMEuwal4Cn+nkQnM6OAHz2oPsKmgZ7TF0HUmtabiC29q7mjXlHAx97OxfsDd1bnb
FrCApNcbq921jx1pOqsgeA1xJF5s/9nNEh60xsTL1gckKtPOlM6wYQJFWGWOp9Uw
Po4I434ukwwHfwHuXTOrWxXEtFJkiGcjqxDeaDyVuR2ZAgMBAAE=
-----END PUBLIC KEY-----";

#[tokio::test]
#[ignore = "Requires Google OAuth credentials and Google CSE setup"]
async fn test_google_cse_export_import() -> KmsCliResult<()> {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("info"));

    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap();
    let pub_key = PKey::public_key_from_pem(GOOGLE_RSA_3072_PUBLIC_KEY.as_bytes()).unwrap();
    info!("pub_key: {}", pub_key.rsa().unwrap().size());
    let dek = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";

    // write RSA public key to file
    let pub_key_file = tmp_path.join("rsa_public_key.pem");
    fs::write(&pub_key_file, GOOGLE_RSA_3072_PUBLIC_KEY)?;
    // write dek to file
    let dek_file = tmp_path.join("dek.bin");
    fs::write(&dek_file, hex::decode(dek)?)?;

    let pub_key_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&pub_key_file),
        key_format: ImportKeyFormat::Pem,
        key_usage: Some(vec![KeyUsage::WrapKey, KeyUsage::Encrypt]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?
    .to_string();
    info!("pub_key_id: {pub_key_id}");

    let dek_id = ImportSecretDataOrKeyAction {
        key_file: PathBuf::from(&dek_file),
        key_format: ImportKeyFormat::Aes,
        key_usage: Some(vec![KeyUsage::Decrypt, KeyUsage::Encrypt]),
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?
    .to_string();
    info!("dek_id: {dek_id}");

    let wrapped_key_file = tmp_path.join("wrapped_key.bin");
    // Export the key wrapped
    ExportSecretDataOrKeyAction {
        key_id: Some(dek_id.clone()),
        key_file: wrapped_key_file.clone(),
        wrap_key_id: Some(pub_key_id.clone()),
        wrapping_algorithm: Some(WrappingAlgorithm::RsaAesKeyWrapSha1),
        export_format: ExportKeyFormat::Raw,
        ..Default::default()
    }
    .run(ctx.get_user_client())
    .await?;
    // read wrapped key from file
    let wrapped_key = fs::read(&wrapped_key_file)?;

    // encode in BASE 64
    let wrapped_key_base64 = base64::engine::general_purpose::STANDARD.encode(&wrapped_key);
    let dek_base64 = base64::engine::general_purpose::STANDARD.encode(hex::decode(dek)?);

    info!("dek_base64: {}", dek_base64);
    info!("wrapped_key_base64: {}", wrapped_key_base64);

    Ok(())
}
