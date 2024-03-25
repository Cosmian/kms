// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

use pkcs11_sys::{
    CKO_CERTIFICATE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKP_BASELINE_PROVIDER,
    CK_OBJECT_HANDLE,
};
use tracing::{debug, instrument, warn};

use crate::{
    core::{
        attribute::{Attribute, AttributeType, Attributes},
        compoundid, Result,
    },
    object::Object,
    traits::{backend, SearchOptions},
    Error,
};

#[derive(Debug)]
pub struct ObjectStore {
    objects: HashMap<CK_OBJECT_HANDLE, Object>,
    handles_by_object: HashMap<Object, CK_OBJECT_HANDLE>,
    next_object_handle: CK_OBJECT_HANDLE,
    last_loaded_certs: Option<std::time::Instant>,
}

impl ObjectStore {
    #[instrument(skip(self))]
    pub fn insert(&mut self, object: Object) -> CK_OBJECT_HANDLE {
        if let Some(existing_handle) = self.handles_by_object.get(&object) {
            return *existing_handle;
        }
        let handle = self.next_object_handle + 1;
        self.next_object_handle += 1;
        self.objects.insert(handle, object.clone());
        self.handles_by_object.insert(object, handle);
        handle
    }

    #[instrument(skip(self))]
    pub fn get(&self, handle: &CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.get(handle)
    }

    /// Refresh the cache of certificates.
    /// Firefox + NSS query certificates for every TLS connection in order to
    ///  evaluate server trust.
    /// The cache is refreshed if it has been more than 3 seconds since the last
    /// refresh.
    fn refresh_cache(&mut self) -> Result<()> {
        let should_reload = match self.last_loaded_certs {
            Some(last) => last.elapsed() >= std::time::Duration::from_secs(3),
            None => true,
        };
        if !should_reload {
            return Ok(());
        }
        for cert in backend().find_all_certificates()? {
            let private_key = backend().find_private_key(SearchOptions::Hash(
                cert.public_key().public_key_hash().as_slice().try_into()?,
            ))?;
            //  Check if certificate has an associated PrivateKey.
            match private_key {
                Some(key) => key,
                None => continue,
            };
            self.insert(Object::Certificate(cert.into()));
        }
        //  Add all keys, regardless of label.
        for private_key in backend().find_all_private_keys()? {
            // Add the associated PublicKey if it exists.
            if let Some(public_key) = private_key.find_public_key(backend())? {
                self.insert(Object::PublicKey(public_key));
            };
            self.insert(Object::PrivateKey(private_key));
        }
        for public_key in backend().find_all_public_keys()? {
            self.insert(Object::PublicKey(public_key));
        }
        self.last_loaded_certs = Some(std::time::Instant::now());
        Ok(())
    }

    #[instrument(skip(self))]
    pub fn find(&mut self, template: Attributes) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let class = match template.get(AttributeType::Class) {
            Some(Attribute::Class(class)) => class,
            None => {
                return Err(Error::Todo("find: no class attribute".to_string()));
            }
            other => {
                return Err(Error::Todo(format!(
                    "find: unexpected attribute value: {:?}, on class attribute type",
                    other
                )));
            }
        };

        let search_options = search_options_from_attributes(&template)?;
        debug!(
            "find: searching with class: {:?} and options: {:?}",
            class, search_options
        );

        let mut output = vec![];
        let search_options = match search_options {
            // find all objects
            None => {
                return match *class {
                    CKO_CERTIFICATE => match template.get(AttributeType::CertificateType) {
                        Some(Attribute::CertificateType(cert_type)) => match *cert_type {
                            pkcs11_sys::CKC_X_509 => {
                                self.refresh_cache()?;
                                for handle in self.objects.keys() {
                                    if let Object::Certificate(_) =
                                        self.objects.get(handle).unwrap()
                                    {
                                        output.push(*handle);
                                    }
                                }
                                Ok(output)
                            }
                            _ => Err(Error::Todo(format!(
                                "find: find all objects not yet implemented for certificate type: \
                                 {}",
                                cert_type
                            ))),
                        },
                        Some(other_type) => Err(Error::Todo(format!(
                            "find: certificate search for attribute {:?}, is not implemented",
                            other_type
                        ))),
                        None => {
                            // assume it is a X509 certificate
                            self.refresh_cache()?;
                            for handle in self.objects.keys() {
                                if let Object::Certificate(_) = self.objects.get(handle).unwrap() {
                                    output.push(*handle);
                                }
                            }
                            Ok(output)
                        }
                    },
                    CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
                        self.refresh_cache()?;
                        for handle in self.objects.keys() {
                            output.push(*handle);
                        }
                        Ok(output)
                    }
                    // CKO_DATA
                    0 => {
                        for data_object in backend().find_all_data_objects()? {
                            output.push(self.insert(Object::DataObject(data_object)));
                        }
                        Ok(output)
                    }
                    class => Err(Error::Todo(format!(
                        "find: find all objects not yet implemented for class: {}",
                        class
                    ))),
                };
            }
            // find specific objects
            Some(search_options) => search_options,
        };

        // See if the object is already in the cache.
        for (handle, object) in self.objects.iter() {
            if object.matches(&template) {
                output.push(*handle);
            }
        }

        // We did not find any objects in the cache that match the template.
        // Query objects from the backend.
        if output.is_empty() {
            match *class {
                CKO_CERTIFICATE => {
                    if let Some(certificate) = backend().find_certificate(search_options)? {
                        output.push(self.insert(Object::Certificate(certificate)));
                    }
                }
                // CKO_NSS_TRUST | CKO_NETSCAPE_BUILTIN_ROOT_LIST
                3461563219 | 3461563220 => (),
                // 0 if for CKO_DATA
                0 => {
                    if let Some(data) = backend().find_data_object(search_options)? {
                        output.push(self.insert(Object::DataObject(data)));
                    }
                }
                CKO_SECRET_KEY => (),
                CKO_PRIVATE_KEY => {
                    if let Some(key) = backend().find_private_key(search_options)? {
                        output.push(self.insert(Object::PrivateKey(key)));
                    }
                }
                CKO_PUBLIC_KEY => {
                    if let Some(key) = backend().find_public_key(search_options)? {
                        output.push(self.insert(Object::PublicKey(key)));
                    }
                }
                _ => {
                    warn!("unsupported class: {}", class);
                }
            }
        }
        Ok(output)
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self {
            objects: HashMap::from([(1, Object::Profile(CKP_BASELINE_PROVIDER))]),
            handles_by_object: HashMap::from([(Object::Profile(CKP_BASELINE_PROVIDER), 1)]),
            next_object_handle: 2,
            last_loaded_certs: None,
        }
    }
}

/// Convert an Attributes object into a SearchOptions object.
// TODO(BGR) this should probable by a TryFrom implementation
fn search_options_from_attributes(template: &Attributes) -> Result<Option<SearchOptions>> {
    if template.is_empty() {
        return Ok(None);
    }
    let search_options = if let Some(Attribute::Id(id)) = template.get(AttributeType::Id) {
        let id = compoundid::decode(id)?;
        Some(SearchOptions::Hash(id.hash.as_slice().try_into()?))
    } else if let Some(Attribute::Label(label)) = template.get(AttributeType::Label) {
        Some(SearchOptions::Label(label.into()))
    } else {
        None
    };
    Ok(search_options)
}

#[cfg(test)]
mod tests {
    use std::vec;

    use pkcs11_sys::CKO_PRIVATE_KEY;
    use serial_test::serial;

    use super::*;
    use crate::{
        tests::test_init,
        traits::{backend, random_label, KeyAlgorithm},
    };

    #[test]
    #[serial]
    fn test_object_store() {
        test_init();

        let label = &format!("objectstore test {}", random_label());

        let key = backend()
            .generate_key(KeyAlgorithm::Rsa, Some(label))
            .unwrap();

        let mut store = ObjectStore::default();

        let template = Attributes::from(vec![
            Attribute::Class(CKO_PRIVATE_KEY),
            Attribute::Label(label.into()),
        ]);
        let private_key_handle = store.find(template.clone()).unwrap()[0];
        //  find again
        assert_eq!(store.find(template).unwrap()[0], private_key_handle);

        key.find_public_key(backend()).unwrap().unwrap().delete();
        key.delete();
    }

    #[test]
    #[serial]
    fn key_alg() -> Result<()> {
        test_init();
        let ec = backend().generate_key(KeyAlgorithm::Ecc, Some(&random_label()))?;
        let rsa = backend().generate_key(KeyAlgorithm::Rsa, Some(&random_label()))?;

        assert_eq!(ec.algorithm(), KeyAlgorithm::Ecc);
        assert_eq!(rsa.algorithm(), KeyAlgorithm::Rsa);

        for key in [ec, rsa] {
            key.find_public_key(backend()).unwrap().unwrap().delete();
            key.delete();
        }

        Ok(())
    }
}
