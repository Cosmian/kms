use actix_web::web;
use cosmian_kms::kmip_server::ciphers::fpe::{AlphabetCharacters, FpeText};
use paperclip::actix::{api_v2_operation, web::Json, Apiv2Schema};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct EncryptRequest {
    symmetric_key: String,
    tweak: String,
    alphabet: AlphabetCharacters,
    plaintext: String,
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct EncryptResponse {
    ciphertext: String,
}

pub fn _encrypt(req: EncryptRequest) -> anyhow::Result<EncryptResponse> {
    debug!(
        "POST /fpe/stateless/encrypt. Request: {:?}",
        serde_json::to_string(&req)?
    );

    let symmetric_key =
        hex::decode(req.symmetric_key).context("failed hex-decoding symmetric key")?;
    let tweak = hex::decode(req.tweak).context("failed hex-decoding tweak")?;

    let text = FpeText {
        alphabet_characters: req.alphabet,
        input: req.plaintext,
    };
    let ciphertext = text.encrypt(&symmetric_key, &tweak)?;

    let response = EncryptResponse { ciphertext };
    debug!(
        "POST /fpe/stateless/encrypt. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /fpe/stateless/encrypt`
/// FPE using FF1 zcash implementation
#[api_v2_operation]
pub async fn encrypt(req: web::Json<EncryptRequest>) -> ActixResult<Json<EncryptResponse>> {
    Ok(Json(
        _encrypt(req.into_inner()).context("failed encryption")?,
    ))
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct DecryptRequest {
    symmetric_key: String,
    tweak: String,
    alphabet: AlphabetCharacters,
    ciphertext: String,
}
#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct DecryptResponse {
    cleartext: String,
}

pub fn _decrypt(req: DecryptRequest) -> anyhow::Result<DecryptResponse> {
    debug!(
        "POST /fpe/stateless/decrypt. Request: {:?}",
        serde_json::to_string(&req)?
    );
    let symmetric_key =
        hex::decode(req.symmetric_key).context("failed hex-decoding symmetric key")?;
    let tweak = hex::decode(req.tweak).context("failed hex-decoding tweak")?;

    let text = FpeText {
        alphabet_characters: req.alphabet,
        input: req.ciphertext,
    };
    let cleartext = text.decrypt(&symmetric_key, &tweak)?;

    let response = DecryptResponse { cleartext };
    debug!(
        "POST /fpe/stateless/decrypt. Response: {:?}",
        serde_json::to_string(&response)?
    );
    Ok(response)
}

/// `POST /fpe/stateless/decrypt`
/// FPE using FF1 zcash implementation
#[api_v2_operation]
pub async fn decrypt(req: web::Json<DecryptRequest>) -> ActixResult<Json<DecryptResponse>> {
    Ok(Json(
        _decrypt(req.into_inner()).context("failed decryption")?,
    ))
}

#[cfg(test)]
mod tests {
    use common::prelude::*;
    use cosmian_kms::kmip_server::ciphers::fpe::{AlphabetCharacters, NumericType};
    use test_utils::log_init;

    use super::EncryptRequest;
    use crate::rest::fpe::no_kmip::{DecryptRequest, _decrypt, _encrypt};

    fn fpe_ff1_test(alphabet: AlphabetCharacters, plaintext: &str) -> anyhow::Result<()> {
        let symmetric_key =
            "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF".to_string();
        let tweak = "00112233445566778899AABBCCDDEEFF".to_string();
        let er = EncryptRequest {
            symmetric_key: symmetric_key.clone(),
            tweak: tweak.clone(),
            alphabet: alphabet.clone(),
            plaintext: plaintext.to_string(),
        };
        let ciphertext = _encrypt(er)?;

        let dr = DecryptRequest {
            symmetric_key,
            tweak,
            alphabet,
            ciphertext: ciphertext.ciphertext,
        };
        let cleartext = _decrypt(dr)?;
        assert_eq!(plaintext, cleartext.cleartext);
        //debug!("\n\n\n");
        Ok(())
    }

    #[test]
    fn fpe_ff1_encrypt() -> anyhow::Result<()> {
        log_init("debug");

        fpe_ff1_test(AlphabetCharacters::Numeric(NumericType::U32), "0123456789")?;

        fpe_ff1_test(AlphabetCharacters::Alphabetic, "abcdefghijklmnopqrstuvwxyz")?;

        fpe_ff1_test(AlphabetCharacters::AlphaNumeric, "abcd0123456789")?;

        fpe_ff1_test(
            AlphabetCharacters::CustomAlphabet("1234567890".to_string()),
            "1234-1234-1234-1234",
        )?;

        fpe_ff1_test(
            AlphabetCharacters::CustomAlphabet("ABCD1234".to_string()),
            "EFGH0123456789",
        )?;

        Ok(())
    }
}
