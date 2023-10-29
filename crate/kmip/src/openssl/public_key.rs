use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::Rsa,
};

use crate::{
    error::KmipError,
    kmip::{
        kmip_data_structures::KeyMaterial,
        kmip_objects::Object,
        kmip_types::{KeyFormatType, RecommendedCurve},
    },
    kmip_bail,
};

/// Convert a KMIP Public key to openssl `PKey<Public>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * PKCS8: actually a SPKI DER (RFC 5480)
/// * TransparentRSAPublicKey
/// * TransparentECPublicKey: only the following curves are supported:
///    * P192
///    * P224
///    * P256
///    * P384
///    * P521
///    * CURVE25519
///    * CURVE448
///    * CURVEED25519
///
/// For the NIST P-curves the `q_string` is expected to be the octet form (as defined in RFC5480 and used in certificates and TLS records):
/// only the content octets are present, the OCTET STRING tag and length are not included.
///
/// For the last 3 curves the `q_string` is expected to be the raw bytes of the public key.
///
/// # Arguments
///
/// * `public_key` - The KMIP Public key to convert
///
/// # Returns
///
/// * `PKey<Public>` - The openssl Public key
///
pub fn kmip_public_key_to_openssl(public_key: &Object) -> Result<PKey<Public>, KmipError> {
    let key_block = match public_key {
        Object::PublicKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {:?}. KMIP Public Key expected", x),
    };
    // Convert the key to the default storage format: SPKI DER (RFC 5480)
    let key_bytes = key_block.key_bytes()?;
    let pk: PKey<Public> = match key_block.key_format_type {
        KeyFormatType::PKCS1 => {
            // parse the RSA public key to make sure it is correct
            let rsa_public_key = Rsa::public_key_from_der_pkcs1(&key_bytes)?;
            PKey::from_rsa(rsa_public_key)?
        }
        // This really is a SPKI as specified by RFC 5480
        KeyFormatType::PKCS8 => {
            // This key may be an RSA or EC key
            PKey::public_key_from_der(&key_bytes)?
        }
        // KeyFormatType::ECPrivateKey => {
        //     // this is the (not so appropriate) placeholder for SEC1
        //     // parse the SEC1 public key
        //     let ec_key = EcKey::public_key_from_der(&key_bytes)?;
        //     ec_key.check_key()?;
        //     PKey::from_ec_key(ec_key)?
        // }
        KeyFormatType::TransparentRSAPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let rsa_public_key = Rsa::from_public_components(
                    BigNum::from_slice(&modulus.to_bytes_be())?,
                    BigNum::from_slice(&public_exponent.to_bytes_be())?,
                )?;
                PKey::from_rsa(rsa_public_key)?
            }
            _ => kmip_bail!(
                "Invalid Transparent RSA public key material: TransparentRSAPublicKey expected"
            ),
        },
        KeyFormatType::TransparentECPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => match recommended_curve {
                RecommendedCurve::P192 => {
                    ec_public_key_from_point_encoding(&q_string, Nid::X9_62_PRIME192V1)?
                }
                RecommendedCurve::P224 => {
                    ec_public_key_from_point_encoding(&q_string, Nid::SECP224R1)?
                }
                RecommendedCurve::P256 => {
                    ec_public_key_from_point_encoding(&q_string, Nid::X9_62_PRIME256V1)?
                }
                RecommendedCurve::P384 => {
                    ec_public_key_from_point_encoding(&q_string, Nid::SECP384R1)?
                }
                RecommendedCurve::P521 => {
                    ec_public_key_from_point_encoding(&q_string, Nid::SECP521R1)?
                }
                RecommendedCurve::CURVE25519 => {
                    PKey::public_key_from_raw_bytes(&q_string, Id::X25519)?
                }
                RecommendedCurve::CURVE448 => PKey::public_key_from_raw_bytes(&q_string, Id::X448)?,
                RecommendedCurve::CURVEED25519 => {
                    PKey::public_key_from_raw_bytes(&q_string, Id::ED25519)?
                }
                unsupported_curve => {
                    kmip_bail!(
                        "Unsupported curve: {:?} for a Transparent EC Public Key",
                        unsupported_curve
                    )
                }
            },
            _ => kmip_bail!(
                "Invalid key material for a Transparent EC public key format: \
                 TransparentECPublicKey expected"
            ),
        },
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC public key",
            f
        ),
    };
    Ok(pk)
}

/// Instantiate an openssl Public Key from the point (EC_POINT) encoding on a standardized curve
///
/// The encoding of the ECPoint structure is expected to be in the octet form  
/// (as defined in RFC5480 and used in certificates and TLS records):
/// only the content octets are present, the OCTET STRING tag and length are not included.
/// The encoding/decoding conforms with Sec. 2.3.3/2.3.4 of the SECG SEC 1 (“Elliptic Curve Cryptography”) standard.
fn ec_public_key_from_point_encoding(
    point_encoding: &[u8],
    curve_nid: Nid,
) -> Result<PKey<Public>, KmipError> {
    let group = EcGroup::from_curve_name(curve_nid)?;
    let mut ctx = BigNumContext::new()?;
    //# EcKey::generate(&group)?.public_key().to_bytes(&group,
    //# PointConversionForm::COMPRESSED, &mut ctx)?;
    let ec_point = EcPoint::from_bytes(&group, point_encoding, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &ec_point)?;
    key.check_key()?;
    Ok(PKey::from_ec_key(key)?)
}

#[cfg(test)]
mod tests {
    // use openssl::{
    //     bn::BigNumContext,
    //     ec::{EcGroup, EcKey, EcPoint},
    //     nid::Nid,
    // };

    // // test creating a X25519 key pair with openssl
    // #[test]
    // fn test_create_x25519_key_pair() {
    // use openssl::{pkey::PKey, sign::Signer, symm::Cipher};

    // let key = PKey::generate_x25519().unwrap();
    // let bytes = key.private_key_to_pem_pkcs8().unwrap();
    // println!("bytes: {:?}", String::from_utf8(bytes.clone()).unwrap());
    // let key = PKey::private_key_from_pem(&bytes).unwrap();

    // let public_key = PKey::public_key_from_raw_bytes(public, Id::X448)?;

    // let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    // let mut ctx = BigNumContext::new()?;

    // /*
    // In addition EC_POINT can be converted to and from various external representations. The octet form is the binary encoding of the ECPoint structure (as defined in RFC5480 and used in certificates and TLS records): only the content octets are present, the OCTET STRING tag and length are not included. BIGNUM form is the octet form interpreted as a big endian integer converted to a BIGNUM structure. Hexadecimal form is the octet form converted to a NULL terminated character string where each character is one of the printable values 0-9 or A-F (or a-f).

    // The functions EC_POINT_point2oct(), EC_POINT_oct2point(), EC_POINT_point2bn(), EC_POINT_bn2point(), EC_POINT_point2hex() and EC_POINT_hex2point() convert from and to EC_POINTs for the formats: octet, BIGNUM and hexadecimal respectively.

    // The function EC_POINT_point2oct() encodes the given curve point p as an octet string into the buffer buf of size len, using the specified conversion form form. The encoding conforms with Sec. 2.3.3 of the SECG SEC 1 (“Elliptic Curve Cryptography”) standard. Similarly the function EC_POINT_oct2point() decodes a curve point into p from the octet string contained in the given buffer buf of size len, conforming to Sec. 2.3.4 of the SECG SEC 1 (“Elliptic Curve Cryptography”) standard.
    //          */
    // //get bytes from somewhere
    // //let public_key = /...
    // //# EcKey::generate(&group)?.public_key().to_bytes(&group,
    // //# PointConversionForm::COMPRESSED, &mut ctx)?;

    // let ec_point = EcPoint::from_bytes(&group, buf, &mut ctx)?;
    // let key = EcKey::from_public_key(&group, &ec_point)?;
    // /// key.check_key()?;
    // let ec_key = EcKey::from_public_key_affine_coordinates(
    //     Nid::from_raw(elliptic_curve_type),
    //     &BigNum::from_slice(&public_point.x_coordinate.to_bytes_be())?,
    //     &BigNum::from_slice(&public_point.y_coordinate.to_bytes_be())?,
    // )?;
    // }
}
