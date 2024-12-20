use std::collections::HashMap;

use cosmian_cover_crypt::{AccessStructure, EncryptionHint, QualifiedAttribute};
use tracing::debug;

use crate::{error::KmsError, result::KResult};

pub(crate) fn access_structure_from_str(access_structure_str: &str) -> KResult<AccessStructure> {
    let access_structure_json: HashMap<String, Vec<String>> =
        serde_json::from_str(access_structure_str).map_err(|e| {
            KmsError::Default(format!(
                "failed parsing the access structure from the string: {e}"
            ))
        })?;

    let mut access_structure = AccessStructure::new();
    for (dimension, attributes) in &access_structure_json {
        if dimension.contains("::<") {
            let trim_key_name = dimension.trim_end_matches("::<");
            access_structure.add_hierarchy(trim_key_name.to_owned())?;
        } else {
            access_structure.add_anarchy(dimension.clone())?;
        }

        for name in attributes.iter().rev() {
            let attribute = QualifiedAttribute {
                dimension: dimension.trim_end_matches("::<").to_owned(),
                name: name.trim_end_matches("::+").to_owned(),
            };
            let encryption_hint = if name.contains("::+") {
                EncryptionHint::Hybridized
            } else {
                EncryptionHint::Classic
            };
            debug!("attribute: {attribute:?}, encryption_hint: {encryption_hint:?}");
            access_structure.add_attribute(attribute, encryption_hint, None)?;
        }
    }

    Ok(access_structure)
}
