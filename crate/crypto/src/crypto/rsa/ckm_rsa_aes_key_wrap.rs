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
    let encapsulation = ckm_rsa_pkcs_oaep_key_wrap(pubkey, hash_fn, &kek)?;

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
    let kek = ckm_rsa_pkcs_oaep_key_unwrap(p_key, hash_fn, encapsulation)?;

    // Unwrap key according to RFC 5649 as recommended.
    let plaintext = rfc5649_unwrap(wk, &kek)?;

    Ok(plaintext)
}

#[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    use openssl::pkey::PKey;
    use zeroize::Zeroizing;

    use crate::{
        crypto::{
            rsa::{
                ckm_rsa_aes_key_wrap::{ckm_rsa_aes_key_unwrap, ckm_rsa_aes_key_wrap},
                ckm_rsa_pkcs_oaep::{ckm_rsa_pkcs_oaep_key_unwrap, ckm_rsa_pkcs_oaep_key_wrap},
            },
            symmetric::rfc5649::rfc5649_wrap,
        },
        error::CryptoError,
    };

    const RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----"#;

    const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs3VwrLgvmKgb3IBk3vaB
eC9zYtKY9qZOsk3xqrdQM/9PCL7nmbHrRZ6yHsPWUmgAqG0pcCLNpqHN7LpJGE0K
Q8TRHkYNZT0AKw5Yc/rcAWy8dKt9UVsE9JFvEf/lFuRjuLnoVIXbgIIurIrMUqal
5L9/9NL/ayALXaX4QHRLPEc/BAM2tt+hAxwukol1W0yp9rywHv9CV+HoD+fy1KO6
JExzskB4cOnHPAdR5xnp+X3DMKRDuCNYEGUg0YqNu9fJ40yHoFLNclfO1pcYbnZD
/EnzChB1iVMtcJWG5CLCnRPwfNtl3lSs9tjBqJCY3combLoWIc4GqLsyt8hNnq1s
FQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn test_rsa_kem_wrap_unwrap() -> Result<(), CryptoError> {
        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

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
            &hex::decode(aes_kek).unwrap(),
        )
        .unwrap();
        let rec_aes_kek = hex::encode(
            ckm_rsa_pkcs_oaep_key_unwrap(
                &priv_key,
                HashingAlgorithm::SHA256,
                &rsa_oaep_encapsulation,
            )
            .unwrap(),
        );
        assert_eq!(aes_kek, rec_aes_kek);

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
}
