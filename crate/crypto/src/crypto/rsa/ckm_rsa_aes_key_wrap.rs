use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
#[cfg(not(feature = "non-fips"))]
use cosmian_kmip::kmip_2_1::extra::fips::FIPS_MIN_RSA_MODULUS_LENGTH;
use openssl::{
    pkey::{PKey, Private, Public},
    rand::rand_bytes,
};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        rsa::ckm_rsa_pkcs_oaep::{ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap},
        symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    },
    crypto_bail,
    error::CryptoError,
};

/// AES KEY WRAP with padding key length in bytes.
pub const AES_KWP_KEY_LENGTH: usize = 0x20;

/// Asymmetrically wrap keys referring to PKCS#11 `CKM_RSA_AES_KEY_WRAP` available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226908
///
/// This document describes how to wrap keys of any size using asymmetric
/// encryption and the RSA algorithm. Since old similar wrapping methods based
/// on RSA used naive RSA encryption and could present some flaws, this RFC aims
/// at a generally more secure method to wrap keys.
///
/// Let `m` be the key/message to wrap, first generate a temporary random AES
/// key `kek`. Encrypt it using RSA-OAEP; `c` is the encrypted key.
///
/// Encrypt the key/message `m` such as`wk = enc(kek, m)` using the key `kek`
/// with AES-KWP as specified in RFC5649.
///
/// Send `c|wk` where `|` is the concatenation operator.
pub fn ckm_rsa_aes_key_wrap(
    pubkey: &PKey<Public>,
    hash_fn: HashingAlgorithm,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Generate temporary AES key.
    let mut kek = Zeroizing::from(vec![0_u8; AES_KWP_KEY_LENGTH]);
    rand_bytes(&mut kek)?;

    // Encapsulate it using RSA-OAEP.
    let encapsulation = ckm_rsa_pkcs_oaep_key_wrap(pubkey, hash_fn, hash_fn, None, &kek)?;

    // Wrap key according to RFC 5649 (CKM_AES_KEY_WRAP_PAD) as recommended.
    let wk = rfc5649_wrap(plaintext, &kek)?;

    Ok([encapsulation, wk].concat())
}

/// Asymmetrically unwrap keys referring to PKCS#11 `CKM_RSA_AES_KEY_WRAP` available at
/// <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226908
///
/// This document describes how to unwrap keys of any size using asymmetric
/// encryption and the RSA algorithm. Since old similar wrapping methods based
/// on RSA used naive RSA encryption and could present some flaws, this RFC aims
/// at a generally more secure method to wrap keys.
///
/// Receive data of the form `c|wk` where `|` is the concatenation operator.
/// Distinguish `c` and `wk`, respectively the encrypted `kek` and the wrapped
/// key.
///
/// First decrypt the key-encryption-key `kek` using RSA-OAEP. Then proceed to
/// unwrap the key by decrypting `m = dec(wk, kek)` using AES-KWP as specified in
/// RFC5649.
pub fn ckm_rsa_aes_key_unwrap(
    p_key: &PKey<Private>,
    hash_fn: HashingAlgorithm,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let rsa_privkey = p_key.rsa()?;

    #[cfg(not(feature = "non-fips"))]
    if p_key.bits() < FIPS_MIN_RSA_MODULUS_LENGTH {
        crypto_bail!(
            "CKM_RSA_AES: CKM_RSA_OAEP decryption error: RSA key has insufficient size: expected \
             >= {} bytes and got {} bytes",
            FIPS_MIN_RSA_MODULUS_LENGTH,
            rsa_privkey.size()
        )
    }

    let encapsulation_bytes_len = usize::try_from(rsa_privkey.size())?;
    if ciphertext.len() <= encapsulation_bytes_len {
        crypto_bail!(
            "CKM_RSA_AES: CKM_RSA_OAEP decryption error: encapsulated data of insufficient \
             length: got {}, expected: {}",
            ciphertext.len(),
            encapsulation_bytes_len
        );
    }

    // Split ciphertext into encapsulation and wrapped key.
    let encapsulation = ciphertext.get(..encapsulation_bytes_len).ok_or_else(|| {
        CryptoError::IndexingSlicing(
            "ckm_rsa_aes_key_unwrap: encapsulation from ciphertext".to_owned(),
        )
    })?;
    let wk = ciphertext
        .get(encapsulation_bytes_len..)
        .ok_or_else(|| CryptoError::IndexingSlicing("ckm_rsa_aes_key_unwrap: wk".to_owned()))?;

    // Unwrap key-encryption-key using RSA-OAEP.
    let kek = ckm_rsa_pkcs_oaep_key_unwrap(p_key, hash_fn, hash_fn, None, encapsulation)?;

    // Unwrap key according to RFC 5649 as recommended.
    let plaintext = rfc5649_unwrap(wk, &kek)?;

    Ok(plaintext)
}

#[allow(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::expect_used
)]
#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use std::{fs, path::Path};

    use base64::Engine;
    use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    use cosmian_logger::log_init;
    #[cfg(not(target_os = "windows"))]
    use cosmian_logger::warn;
    use openssl::pkey::PKey;
    use serde_json::json;
    #[cfg(not(target_os = "windows"))]
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    #[cfg(not(target_os = "windows"))]
    use crate::{crypto::symmetric::rfc5649::rfc5649_unwrap, crypto_bail};
    use crate::{
        crypto::{
            rsa::{
                ckm_rsa_aes_key_wrap::{ckm_rsa_aes_key_unwrap, ckm_rsa_aes_key_wrap},
                ckm_rsa_pkcs_oaep::{ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap},
            },
            symmetric::rfc5649::rfc5649_wrap,
        },
        error::{CryptoError, result::CryptoResult},
    };

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

    #[test]
    fn test_rsa_kem_wrap_unwrap() -> Result<(), CryptoError> {
        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips")
            .map_err(|e| CryptoError::Default(format!("Failed to load FIPS provider: {e}")))?;

        let priv_key = PKey::from_rsa(openssl::rsa::Rsa::generate(2048)?)?;
        let pub_key = PKey::public_key_from_pem(&priv_key.public_key_to_pem()?)?;

        let priv_key_to_wrap =
            Zeroizing::from(openssl::rsa::Rsa::generate(2048)?.private_key_to_pem()?);

        let wrapped_key = ckm_rsa_aes_key_wrap(
            &pub_key,
            HashingAlgorithm::SHA256,
            priv_key_to_wrap.as_ref(),
        )?;

        let unwrapped_key =
            ckm_rsa_aes_key_unwrap(&priv_key, HashingAlgorithm::SHA256, &wrapped_key)?;

        assert_eq!(unwrapped_key, priv_key_to_wrap);

        Ok(())
    }

    #[test]
    fn test_openssl_cli_compat() {
        // This is inspired by a Google Documentation example:
        // https://cloud.google.com/kms/docs/wrapping-a-key

        let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap();
        let pub_key = PKey::public_key_from_pem(RSA_PUBLIC_KEY.as_bytes()).unwrap();
        let dek = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";
        let aes_kek = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a85840df6e29b02af1";

        // For openssl CLI tests, uncomment this code to recover the keys as files.
        // // write RSA public key to file
        // std::fs::write("/tmp/rsa_public_key.pem", RSA_PUBLIC_KEY).unwrap();
        // // write aes_kek to file
        // std::fs::write("/tmp/aes_kek.bin", hex::decode(aes_kek).unwrap()).unwrap();
        // // write dek to file
        // std::fs::write("/tmp/dek.bin", hex::decode(dek).unwrap()).unwrap();

        // openssl pkeyutl \
        //   -encrypt \
        //   -pubin \
        //   -inkey /tmp/rsa_public_key.pem \
        //   -in /tmp/aes_kek.bin \
        //   -out /tmp/rsa_oaep_encapsulation.bin \
        //   -pkeyopt rsa_padding_mode:oaep \
        //   -pkeyopt rsa_oaep_md:sha256 \
        //   -pkeyopt rsa_mgf1_md:sha256
        let openssl_rsa_oaep_encapsulation = "2b39270a021b314ba08da7c5568892658767d21961ba19075bdb6df7257f8b176f2fd54f850a334e0b86cf906c05ec8f965c5f8b76a51f30c0e039e0652703f2df2052e9b9f3fce8d407ed4fba78f47820d728bbf580062d749a2e98aaa1e3b736de01ba761782ca6d5e37c455dad9c4da00546b79ecdaf1938090bfb0367d2c2119fc3d774b8dbd7e249c8a2c97573ac5b244491e1696acd0cc602cfba247106ae6b7a22655c904d1d01ad5dc728a9677ef173dc187c287d3eea2935e5b9e5c76971b72283f5834e61d6ef441e2844d9b340313f2854cc772d40aed8bf87fce0fa9ef79e2b05224f50ff2aa298a49cd6dcd2304719743fa422738846a7896f2";

        // Check that our implementation of CKM_RSA_OAEP_UNWRAP is compatible with OpenSSL CLI.
        let rec_aes_kek = hex::encode(
            ckm_rsa_pkcs_oaep_key_unwrap(
                &priv_key,
                HashingAlgorithm::SHA256,
                HashingAlgorithm::SHA256,
                None,
                &hex::decode(openssl_rsa_oaep_encapsulation).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(aes_kek, rec_aes_kek);

        // Check that we can decrypt the key-encryption-key using our implementation.
        // Encapsulate it using RSA-OAEP.
        let rsa_oaep_encapsulation = ckm_rsa_pkcs_oaep_key_wrap(
            &pub_key,
            HashingAlgorithm::SHA256,
            HashingAlgorithm::SHA256,
            None,
            &hex::decode(aes_kek).unwrap(),
        )
        .unwrap();
        let rec_aes_kek = hex::encode(
            ckm_rsa_pkcs_oaep_key_unwrap(
                &priv_key,
                HashingAlgorithm::SHA256,
                HashingAlgorithm::SHA256,
                None,
                &rsa_oaep_encapsulation,
            )
            .unwrap(),
        );
        assert_eq!(aes_kek, rec_aes_kek);

        // To encrypt using AES_KEY_WRAP_PAD using openssl, use the following command
        //  openssl enc \
        //   -id-aes256-wrap-pad \
        //   -iv A65959A6 \
        //   -K $( hexdump -v -e '/1 "%02x"' < /tmp/aes_kek.bin )\
        //   -in /tmp/dek.bin > /tmp/aes_key_wrapping.bin
        //
        //  hexdump -v -e '/1 "%02x"' < /tmp/aes_key_wrapping.bin
        let openssl_aes_key_wrapping =
            "340068e5236ceb5aaca068695fe28266a2dd7b75bdfc46a53f3e4f8c8052f41bd905f3571d04e0f7";

        // Wrap key according to RFC 5649 (CKM_AES_KEY_WRAP_PAD) as recommended.
        let aes_key_wrapping =
            rfc5649_wrap(&hex::decode(dek).unwrap(), &hex::decode(aes_kek).unwrap()).unwrap();
        // this is deterministic, everything should be equal
        assert_eq!(hex::encode(&aes_key_wrapping), openssl_aes_key_wrapping);

        let wrapped_key = [rsa_oaep_encapsulation, aes_key_wrapping].concat();

        // we should be able to unwrap the key using our implementation
        let rec_dek = hex::encode(
            ckm_rsa_aes_key_unwrap(&priv_key, HashingAlgorithm::SHA256, &wrapped_key).unwrap(),
        );
        assert_eq!(rec_dek, dek);

        // we should also be able to unwrap the key generated by the openssl CLI
        let rec_dek = hex::encode(
            ckm_rsa_aes_key_unwrap(
                &priv_key,
                HashingAlgorithm::SHA256,
                &hex::decode(openssl_rsa_oaep_encapsulation.to_owned() + openssl_aes_key_wrapping)
                    .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(rec_dek, dek);
    }

    #[cfg(not(target_os = "windows"))]
    async fn assert_openssl3_cli() -> bool {
        if let Ok(output) = tokio::process::Command::new("openssl")
            .arg("version")
            .output()
            .await
        {
            if !output.status.success() {
                warn!(
                    "test_openssl_cli_compat: openssl CLI call failed, skipping test: {output:#?}"
                );
                return false;
            }
            let Ok(res) = String::from_utf8(output.stdout) else {
                warn!("test_openssl_cli_compat: openssl CLI output is not valid UTF-8");
                return false;
            };
            if res.to_lowercase().contains("openssl 3") {
                true
            } else {
                warn!(
                    "test_openssl_cli_compat: openssl version is not OpenSSL 3: {res}, skipping \
                     test"
                );
                false
            }
        } else {
            warn!("test_openssl_cli_compat: openssl CLI not found, skipping test");
            false
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[allow(clippy::unwrap_in_result)]
    async fn test_wrap_against_openssl_cli() -> CryptoResult<()> {
        log_init(Some("info"));
        if !assert_openssl3_cli().await {
            return Ok(());
        }

        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();

        // PKCS#8 RSA key
        let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes())?;
        let secret_bytes = priv_key
            .rsa()
            .map_err(|e| CryptoError::Default(format!("Failed to get RSA: {e}")))?
            .private_key_to_der()?;
        test_wrap_against_openssl_cli_inner(tmp_path, &secret_bytes).await?;

        // AES KEY
        let dek = "deadbeef7dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";
        let dek_bytes = hex::decode(dek)
            .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?;
        test_wrap_against_openssl_cli_inner(tmp_path, &dek_bytes).await?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    async fn test_wrap_against_openssl_cli_inner(
        tmp_path: &Path,
        secret_bytes: &[u8],
    ) -> CryptoResult<()> {
        let secrets_file = tmp_path.join("secrets.bin");
        fs::write(&secrets_file, secret_bytes)?;

        let ephemeral = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";
        let ephemeral_file = tmp_path.join("ephemeral.bin");
        fs::write(
            &ephemeral_file,
            hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?,
        )?;

        let priv_key_file = tmp_path.join("rsa_private_key.pem");
        fs::write(&priv_key_file, RSA_PRIVATE_KEY)?;

        let oaep_encapsulation_file = tmp_path.join("oaep_encapsulation.bin");

        let pub_key = PKey::public_key_from_pem(RSA_PUBLIC_KEY.as_bytes())?;
        let oaep_encapsulation = ckm_rsa_pkcs_oaep_key_wrap(
            &pub_key,
            HashingAlgorithm::SHA1,
            HashingAlgorithm::SHA1,
            None,
            &hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?,
        )?;
        fs::write(&oaep_encapsulation_file, oaep_encapsulation)?;

        // decrypt the ephemeral using OpenSSL CLI
        let rec_ephemeral_file = tmp_path.join("rec_ephemeral.bin");
        let output = tokio::process::Command::new("openssl")
            .arg("pkeyutl")
            .arg("-decrypt")
            .arg("-inkey")
            .arg(priv_key_file)
            .arg("-in")
            .arg(&oaep_encapsulation_file)
            .arg("-out")
            .arg(&rec_ephemeral_file)
            .arg("-pkeyopt")
            .arg("rsa_padding_mode:oaep")
            .arg("-pkeyopt")
            .arg("rsa_oaep_md:sha1")
            .arg("-pkeyopt")
            .arg("rsa_mgf1_md:sha1")
            .output()
            .await?;

        if !output.status.success() {
            crypto_bail!(
                "test_wrap_against_openssl_cli_inner: RSA OAEP openssl pkeyutl failed: {output:?}"
            );
        }
        let rec_ephemeral = fs::read(&rec_ephemeral_file)?;
        assert_eq!(
            rec_ephemeral,
            hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?
        );

        // RFC 5649 of DEK using the ephemeral key
        let rfc5649_encapsulation = rfc5649_wrap(
            secret_bytes,
            &hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?,
        )?;

        let rfc5649_encapsulation_file = tmp_path.join("rfc5649_encapsulation.bin");
        fs::write(&rfc5649_encapsulation_file, rfc5649_encapsulation)?;
        // Check
        let rec_secret_file = tmp_path.join("rec_secret.bin");
        let output = tokio::process::Command::new("openssl")
            .arg("enc")
            .arg("-d")
            .arg("-id-aes256-wrap-pad")
            .arg("-iv")
            .arg("A65959A6")
            .arg("-K")
            .arg(ephemeral)
            .arg("-in")
            .arg(&rfc5649_encapsulation_file)
            .arg("-out")
            .arg(&rec_secret_file)
            .output()
            .await?;

        if !output.status.success() {
            crypto_bail!("test_wrap_against_openssl_cli_inner: RFC5649 pkeyutl failed: {output:?}");
        }
        let rec_secret_bytes = fs::read(&rec_secret_file)?;
        assert_eq!(rec_secret_bytes.as_slice(), secret_bytes);

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    #[allow(clippy::unwrap_in_result)]
    async fn test_unwrap_against_openssl_cli() -> CryptoResult<()> {
        log_init(Some("info"));
        if !assert_openssl3_cli().await {
            return Ok(());
        }

        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();

        // PKCS#8 RSA key
        let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes())?;
        let secret_bytes = priv_key
            .rsa()
            .map_err(|e| CryptoError::Default(format!("Failed to get RSA: {e}")))?
            .private_key_to_der()?;
        test_unwrap_against_openssl_cli_inner(tmp_path, &secret_bytes).await?;

        // AES KEY
        let dek = "deadbeef7dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";
        let dek_bytes = hex::decode(dek)
            .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?;
        test_unwrap_against_openssl_cli_inner(tmp_path, &dek_bytes).await?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    async fn test_unwrap_against_openssl_cli_inner(
        tmp_path: &Path,
        secret_bytes: &[u8],
    ) -> CryptoResult<()> {
        let secrets_file = tmp_path.join("secrets.bin");
        fs::write(&secrets_file, secret_bytes)?;

        let ephemeral = "afbeb0f07dfbf5419200f2ccb50bb24aafbeb0f07dfbf5419200f2ccb50bb24a";
        let ephemeral_file = tmp_path.join("ephemeral.bin");
        fs::write(
            &ephemeral_file,
            hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?,
        )?;

        let pub_key_file = tmp_path.join("rsa_public_key.pem");
        fs::write(&pub_key_file, RSA_PUBLIC_KEY)?;

        let oaep_encapsulation_file = tmp_path.join("oaep_encapsulation.bin");

        // wrap the ephemeral using KEK_FOR_BYOK
        let output = tokio::process::Command::new("openssl")
            .arg("pkeyutl")
            .arg("-encrypt")
            .arg("-inkey")
            .arg(pub_key_file)
            .arg("-pubin")
            .arg("-in")
            .arg(&ephemeral_file)
            .arg("-out")
            .arg(&oaep_encapsulation_file)
            .arg("-pkeyopt")
            .arg("rsa_padding_mode:oaep")
            .arg("-pkeyopt")
            .arg("rsa_oaep_md:sha1")
            .arg("-pkeyopt")
            .arg("rsa_mgf1_md:sha1")
            .output()
            .await?;
        if !output.status.success() {
            crypto_bail!("test_for_byok: RSA OAEP pkeyutl failed: {output:?}");
        }
        let oaep_encapsulation = fs::read(&oaep_encapsulation_file)?;

        // check that we can decrypt the ephemeral using KEK_FOR_BYOK and our implementation
        let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes())?;
        let rec_ephemeral = ckm_rsa_pkcs_oaep_key_unwrap(
            &priv_key,
            HashingAlgorithm::SHA1,
            HashingAlgorithm::SHA1,
            None,
            &oaep_encapsulation,
        )?;
        assert_eq!(
            rec_ephemeral.as_slice(),
            hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?
                .as_slice()
        );

        // RFC 5649 of DEK using the ephemeral key
        let rfc5649_encapsulation_file = tmp_path.join("rfc5649_encapsulation.bin");
        let output = tokio::process::Command::new("openssl")
            .arg("enc")
            .arg("-id-aes256-wrap-pad")
            .arg("-iv")
            .arg("A65959A6")
            .arg("-K")
            .arg(ephemeral)
            .arg("-in")
            .arg(&secrets_file)
            .arg("-out")
            .arg(&rfc5649_encapsulation_file)
            .output()
            .await?;

        if !output.status.success() {
            crypto_bail!("test_for_byok: RFC5649 pkeyutl failed: {output:?}");
        }
        let rfc5649_encapsulation = fs::read(&rfc5649_encapsulation_file)?;
        // Check against our implementation of AESKeyWrapPadding
        let rec_secret_bytes = rfc5649_unwrap(
            &rfc5649_encapsulation,
            &hex::decode(ephemeral)
                .map_err(|e| CryptoError::Default(format!("Failed to decode hex: {e}")))?,
        )?;
        assert_eq!(rec_secret_bytes.as_slice(), secret_bytes);

        // Build the complete ciphertext
        let wrapped_key = [oaep_encapsulation, rfc5649_encapsulation].concat();

        // Check that we can unwrap the key using our implementation
        let rec_secret_bytes =
            ckm_rsa_aes_key_unwrap(&priv_key, HashingAlgorithm::SHA1, &wrapped_key)?;
        assert_eq!(rec_secret_bytes.as_slice(), secret_bytes);

        Ok(())
    }

    const KEK_FOR_BYOK: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk0HniT34p3O8bD3pyy7p7YASh2Tk7oYag4fbFKVxMX23KX8n68Jx7LWBKgbv6JF6ndZMmUsiBRWoaRC1SUxmtMTZ551CnqeAN47e9FXL1QakHlje4+wK9/tCfllZ2jYNLhvRy1NjTi1ounhkOQC1gdNasvNIRsfzgNVJ8nwgK+1ZJSqkNaoBbQHlJhvUXD3ba0fVH66gat+ns1KPk0HR1WlepZ4cMBmwFlZtPStAqM0dNnflcUzpTeeLLqbuBSzcT0Qb1Q0a/qakmy5SM47nR6RzTZ8A+bOLXP9G+fiK2UPSaAxGMTh8+LfrJqZTEW/lG5GraIbqsJwEQd9ibTlPIDMz8DPUcASUNqU9wQWcVqcjesZXJTb+xurcUPxDvWH/TnIQa0CKt3xcBXw2GZYkn8ROhk/woPJi9IC+rg1TnA4LruNB2OD2Ltg+wt90JYHW6DIxWjVe8/dbEZFof9iE/dYcZqNcipy79C6kJw9Cq2Eq4nP9KX0lk0tAo1B+EI+adQNJv/Hho1fStabk1zSGGsjR2p0izi76AEeNwIn3NkQMewQlKZWHfKz9T2MT8kjsAqvGwDW7g/p7uBhVn2s05kIW8En2JBpitLpqqRTiErS6UsyL1EYwc35BjfMySCt89YZU/wOi/2O1kaHvfi4NjCxclQXM1Y74WjVr1LFgG2MCAwEAAQ==
-----END PUBLIC KEY-----";

    const KV_KEY_IDENTIFIER: &str = "https://hsmbackedkeyvault.vault.azure.net/keys/KEKForBYOK/5e617a4d39c74f47b0b7d345f6a49d1b";

    #[expect(dead_code)]
    const EC_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg22cFLXwIE4yi+G2/
xQWVI5BTNNbJn4HpvZ5BOmddMvmhRANCAATkiSFiMaIvIFBB1FiBzij+2PQyQNj6
vKJMiWk/TowEqm5zcvCeTsPlceZdxidTBNB/EPCSxIHpycyzT3pQ4ehI
-----END PRIVATE KEY-----";

    #[test]
    fn test_for_azure_byok() -> CryptoResult<()> {
        log_init(Some("debug"));
        let priv_key = PKey::private_key_from_pem(RSA_PRIVATE_KEY.as_bytes())?;
        // let priv_key = PKey::private_key_from_pem(EC_PRIVATE_KEY.as_bytes())?;
        let secret_bytes = priv_key.private_key_to_pkcs8()?;

        let pub_key = PKey::public_key_from_pem(KEK_FOR_BYOK.as_bytes())?;
        let wrapped_key = ckm_rsa_aes_key_wrap(&pub_key, HashingAlgorithm::SHA1, &secret_bytes)?;

        // Generate .byok file
        let _byok_value = json!({
            "schema_version": "1.0.0",
            "header":
            {
                "kid": KV_KEY_IDENTIFIER,
                "alg": "dir",
                "enc": "CKM_RSA_AES_KEY_WRAP"
            },
            "ciphertext": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrapped_key),
            "generator": "Cosmian_KMS;v5"
        });

        Ok(())
    }
}
