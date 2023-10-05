use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use acme_lib::{
    create_p384_key, persist::FilePersist, Account, Certificate, Directory, DirectoryUrl,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Private},
    x509::X509,
};

use crate::{error::KmsError, kms_bail, result::KResult};

#[derive(Clone)]
pub struct Certbot {
    pub days_threshold_before_renew: i64,
    pub email: String,
    pub common_name: String,
    pub http_root_path: PathBuf,
    pub keys_path: PathBuf,
    pub use_tee_key: Option<Vec<u8>>,
    account: Option<Account<FilePersist>>,
    certificate: Option<Certificate>,
}

impl fmt::Debug for Certbot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certbot")
            .field(
                "days_threshold_before_renew",
                &self.days_threshold_before_renew,
            )
            .field("email", &self.email)
            .field("common name", &self.common_name)
            .field("http_root_path", &self.http_root_path)
            .field("keys_path", &self.keys_path)
            .finish()
    }
}

impl Default for Certbot {
    fn default() -> Self {
        Self::new(
            String::new(),
            String::new(),
            PathBuf::from(""),
            PathBuf::from(""),
            None,
        )
    }
}

impl Certbot {
    pub fn new(
        email: String,
        common_name: String,
        http_root_path: PathBuf,
        keys_path: PathBuf,
        use_tee_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            days_threshold_before_renew: 15,
            email,
            common_name,
            http_root_path,
            keys_path,
            use_tee_key,
            account: None,
            certificate: None,
        }
    }

    pub fn init(&mut self) -> KResult<()> {
        #[cfg(feature = "insecure")]
        let url = DirectoryUrl::LetsEncryptStaging;

        #[cfg(not(feature = "insecure"))]
        let url = DirectoryUrl::LetsEncrypt;

        // Save/load keys and certificates to current dir.
        let persist = FilePersist::new(&self.keys_path);

        // Create a directory entrypoint.
        let dir = Directory::from_url(persist, url)?;

        let acc = dir.account(&self.email)?;

        self.certificate = acc.certificate(&self.common_name)?;

        self.account = Some(acc);

        Ok(())
    }

    // Check if the certificate exists and is valid
    pub fn check(&self) -> bool {
        match &self.certificate {
            Some(certificate) => certificate.valid_days_left() > self.days_threshold_before_renew,
            _ => false,
        }
    }

    // Return the number of days before the certificate expired
    pub fn get_days_before_expiration(&self) -> KResult<i64> {
        match &self.certificate {
            Some(certificate) => Ok(certificate.valid_days_left()),
            _ => Ok(0),
        }
    }

    // Return the number of days before the certificate has to be renewed
    pub fn get_days_before_renew(&self) -> KResult<i64> {
        Ok(self.get_days_before_expiration()? - self.days_threshold_before_renew)
    }

    // Get the certificate as standard OpenSSL objects
    pub fn get_cert(&self) -> KResult<(PKey<Private>, Vec<X509>)> {
        if let Some(certificate) = &self.certificate {
            return Ok((
                PKey::private_key_from_pem(certificate.private_key().as_bytes())?,
                X509::stack_from_pem(certificate.certificate().as_bytes())?,
            ))
        }
        kms_bail!("Certificate can't be found...");
    }

    // Get the certificate as ACME objects
    pub fn get_raw_cert(&self) -> KResult<(&str, &str)> {
        if let Some(certificate) = &self.certificate {
            return Ok((certificate.private_key(), certificate.certificate()))
        }
        kms_bail!("Certificate can't be found...");
    }

    pub fn generate_private_key(&self) -> KResult<PKey<Private>> {
        if let Some(salt) = &self.use_tee_key {
            let key = tee_attestation::get_key(Some(salt))?;
            let private_number = BigNum::from_slice(&key)?;
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

            let mut public_point = EcPoint::new(&group)?;
            let ctx = BigNumContext::new()?;
            public_point.mul_generator(&group, &private_number, &ctx)?;

            let pri_key_ec =
                EcKey::from_private_components(&group, &private_number, &public_point)?;
            Ok(PKey::from_ec_key(pri_key_ec)?)
        } else {
            Ok(create_p384_key())
        }
    }

    pub fn request_cert(&mut self) -> KResult<()> {
        let pkey_pri = self.generate_private_key()?;

        let acc = self
            .account
            .as_ref()
            .ok_or_else(|| KmsError::ServerError("Account shouldn't be None".to_string()))?;

        // Order a new TLS certificate for a domain.
        let mut ord_new = acc.new_order(&self.common_name, &[])?;

        let target = Path::new(&self.http_root_path).join(".well-known/acme-challenge/");
        let target_parent = Path::new(&self.http_root_path).join(".well-known");

        // If the ownership of the domain(s) has already been
        // authorized in a previous order, you might be able to
        // skip validation. The ACME API provider decides.
        let ord_csr = loop {
            // are we done?
            if let Some(ord_csr) = ord_new.confirm_validations() {
                break ord_csr
            }

            // Get the possible authorizations (for a single domain
            // this will only be one element).
            let auths = ord_new.authorizations()?;

            // For HTTP, the challenge is a text file that needs to
            // be placed in your web server's root:
            //
            // /var/www/.well-known/acme-challenge/<token>
            //
            // The important thing is that it's accessible over the
            // web for the domain(s) you are trying to get a
            // certificate for:
            //
            // http://mydomain.io/.well-known/acme-challenge/<token>
            let chall = auths[0].http_challenge();

            // The token is the filename.
            let token = chall.http_token();

            // The proof is the contents of the file
            let proof = chall.http_proof();

            // Update my web server
            fs::create_dir_all(&target)?;
            fs::write(target.join(token), proof).expect("Unable to write the token file");

            // After the file is accessible from the web,
            // this tells the ACME API to start checking the
            // existence of the proof.
            //
            // The order at ACME will change status to either
            // confirm ownership of the domain, or fail due to the
            // not finding the proof. To see the change, we poll
            // the API with 5000 milliseconds wait between.
            chall.validate(5000)?;

            // Update the state against the ACME API.
            ord_new.refresh()?;

            // Clean the .well-known
            #[allow(clippy::needless_borrow)]
            fs::remove_dir_all(&target_parent)?;
        };

        // Submit the CSR. This causes the ACME provider to enter a
        // state of "processing" that must be polled until the
        // certificate is either issued or rejected. Again we poll
        // for the status change.
        let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

        // Now download the certificate. Also stores the cert in
        // the persistence.
        self.certificate = Some(ord_cert.download_and_save_cert()?);

        Ok(())
    }
}
