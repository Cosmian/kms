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

#[cfg(feature = "bindgen")]
mod generate {

    use bindgen::callbacks;

    const LICENSE_HEADER: &str = r#"// Copyright 2022 Google LLC
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
// limitations under the License."#;

    #[derive(Debug)]
    pub(crate) struct CargoCallbacks;

    impl callbacks::ParseCallbacks for CargoCallbacks {
        // https://github.com/rust-lang/rust-bindgen/issues/1594
        fn int_macro(&self, name: &str, _: i64) -> Option<callbacks::IntKind> {
            if ["CK_TRUE", "CK_FALSE"].contains(&name) {
                Some(callbacks::IntKind::Custom {
                    name: "CK_BBOOL",
                    is_signed: false,
                })
            } else if name.starts_with("CK_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_ULONG",
                    is_signed: false,
                })
            } else if name.starts_with("CKA_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_ATTRIBUTE_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKC_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_CERTIFICATE_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKD_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_EC_KDF_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKF_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_FLAGS",
                    is_signed: false,
                })
            } else if name.starts_with("CKG_MGF1_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_RSA_PKCS_MGF_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKG_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_GENERATOR_FUNCTION",
                    is_signed: false,
                })
            } else if name.starts_with("CKH_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_HW_FEATURE_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKK_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_KEY_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKM_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_MECHANISM_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKN_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_NOTIFICATION",
                    is_signed: false,
                })
            } else if name.starts_with("CKO_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_OBJECT_CLASS",
                    is_signed: false,
                })
            } else if name.starts_with("CKP_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_PROFILE_ID",
                    is_signed: false,
                })
            } else if name.starts_with("CKR_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_RV",
                    is_signed: false,
                })
            } else if name.starts_with("CKS_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_STATE",
                    is_signed: false,
                })
            } else if name.starts_with("CKU_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_USER_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CKZ_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_RSA_PKCS_OAEP_SOURCE_TYPE",
                    is_signed: false,
                })
            } else if name.starts_with("CRYPTOKI_VERSION_") {
                Some(callbacks::IntKind::Custom {
                    name: "CK_BYTE",
                    is_signed: false,
                })
            } else {
                None
            }
        }

        fn include_file(&self, filename: &str) {
            println!("cargo:rerun-if-changed={filename}");
        }

        fn will_parse_macro(&self, name: &str) -> callbacks::MacroParsingBehavior {
            if name.starts_with('_') {
                callbacks::MacroParsingBehavior::Ignore
            } else {
                callbacks::MacroParsingBehavior::Default
            }
        }
    }

    #[allow(unused)]
    fn windows_modifications(builder: bindgen::Builder) -> bindgen::Builder {
        builder.blocklist_item("CK_UNAVAILABLE_INFORMATION")
    }

    fn target_specific_output_path() -> String {
        format!("src/pkcs11_{}.rs", std::env::consts::FAMILY)
    }

    pub(crate) fn generate_main() {
        println!("cargo:rerun-if-changed=pkcs11.h");

        let bindings = bindgen::Builder::default()
            .header("pkcs11.h")
            .derive_default(true)
            .parse_callbacks(Box::new(CargoCallbacks))
            .raw_line(LICENSE_HEADER);

        #[cfg(target_os = "windows")]
        let bindings = windows_modifications(bindings);

        let bindings = bindings.generate().expect("failed to generate bindings");

        bindings
            .write_to_file(target_specific_output_path())
            .expect("failed to write bindings");
    }
}

#[cfg(not(feature = "bindgen"))]
fn main() {}

#[cfg(feature = "bindgen")]
fn main() {
    generate::generate_main();
}
