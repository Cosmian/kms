use std::{collections::HashMap, path::Path};

use cosmian_cover_crypt::{AccessStructure, EncryptionHint, QualifiedAttribute};
use cosmian_kms_client::read_from_json_file;
use tracing::debug;

use crate::error::result::CliResult;

pub(crate) fn access_structure_from_json_file(
    specs_filename: &impl AsRef<Path>,
) -> CliResult<AccessStructure> {
    let access_structure_json: HashMap<String, Vec<String>> = read_from_json_file(&specs_filename)?;

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
            debug!("cli parsing: attribute: {attribute:?}, encryption_hint: {encryption_hint:?}");
            access_structure.add_attribute(attribute, encryption_hint, None)?;
        }
    }

    Ok(access_structure)
}
