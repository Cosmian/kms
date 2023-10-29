use openssl::{
    bn::BigNum,
    ec::EcKey,
    pkey::{PKey, Private},
    rsa::Rsa,
};

use crate::{
    error::KmipError,
    kmip::{kmip_data_structures::KeyMaterial, kmip_objects::Object, kmip_types::KeyFormatType},
    kmip_bail,
    result::KmipResultHelper,
};

/// Convert a KMIP Private key to openssl `PKey<Private>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * ECPrivateKey (SEC1)
/// * PKCS8: actually a SPKI DER (RFC 5480)
/// * TransparentRSAPrivateKey
///
/// Note: TransparentECPrivateKey is not supported: the current openssl implementation
/// does not allow constructing a private key without the public component.  
///
/// # Arguments
///
/// * `private_key` - The KMIP Private key to convert
///
/// # Returns
///
/// * `PKey<Private>` - The openssl Private key
///
pub fn kmip_private_key_to_openssl(private_key: &Object) -> Result<PKey<Private>, KmipError> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {:?}. KMIP Private Key expected", x),
    };
    // Convert the key to the default storage format: SPKI DER (RFC 5480)
    let key_bytes = key_block.key_bytes()?;
    let pk: PKey<Private> = match key_block.key_format_type {
        KeyFormatType::PKCS1 => {
            // parse the RSA private key to make sure it is correct
            let rsa_private_key = Rsa::private_key_from_der(&key_bytes)?;
            PKey::from_rsa(rsa_private_key)?
        }
        // This really is a SPKI as specified by RFC 5480
        KeyFormatType::PKCS8 => {
            // This key may be an RSA or EC key
            PKey::private_key_from_der(&key_bytes)?
        }
        KeyFormatType::ECPrivateKey => {
            // this is the (not so appropriate) value for SEC1
            let ec_key = EcKey::private_key_from_der(&key_bytes)?;
            ec_key.check_key()?;
            PKey::from_ec_key(ec_key)?
        }
        KeyFormatType::TransparentRSAPrivateKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => {
                let rsa_private_key = Rsa::from_private_components(
                    BigNum::from_slice(&modulus.to_bytes_be())?,
                    BigNum::from_slice(
                        &public_exponent
                            .to_owned()
                            .context(
                                "the public exponent is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &private_exponent
                            .to_owned()
                            .context(
                                "the private exponent is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &p.to_owned()
                            .context("'p' is required for Transparent RSA Private Keys")?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &q.to_owned()
                            .context("'q' is required for Transparent RSA Private Keys")?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &prime_exponent_p
                            .to_owned()
                            .context(
                                "the prime exponent p is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &prime_exponent_q
                            .to_owned()
                            .context(
                                "the prime exponent q is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &crt_coefficient
                            .to_owned()
                            .context(
                                "the CRT coefficient is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                )?;
                PKey::from_rsa(rsa_private_key)?
            }
            _ => kmip_bail!(
                "Invalid Transparent RSA private key material: TransparentRSAPrivateKey expected"
            ),
        },
        KeyFormatType::TransparentECPrivateKey => kmip_bail!(
            "TransparentECPrivateKey is not supported: the current openssl implementation does \
             not allow constructing a private key without the public component."
        ),
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC private key",
            f
        ),
    };
    Ok(pk)
}
