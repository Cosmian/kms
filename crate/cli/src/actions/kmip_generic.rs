use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::Get,
    kmip_types::Attributes,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::{
    crypto::generic::kmip_requests::build_import_object_request, kmip_utils::tag_from_object,
};
use eyre::Context;

/// Export an object from the KMS, returning it in KMIP JSON TTLV format.
/// Note: the exported key is serialized in KMIP TTLV format.
/// If you want to export a key in raw format, please use `get` subcommand
#[derive(Parser, Debug)]
pub struct ExportAction {
    /// The object unique identifier stored in the KMS
    #[clap(required = true, long = "object-id", short = 'i')]
    object_id: String,

    /// The JSON file to export the object to
    #[clap(
        required = false,
        long = "object-file",
        short = 'o',
        default_value = "object.json"
    )]
    object_file: PathBuf,
}

impl ExportAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        let get_response = client_connector
            .get(Get::from(&self.object_id))
            .await
            .with_context(|| format!("failed retrieving the object {}", &self.object_id))?;
        let object = Object::post_fix(get_response.object_type, get_response.object);
        // serialize the returned object to JSON TTLV
        let mut ttlv = to_ttlv(&object)?;
        ttlv.tag = tag_from_object(&object);
        let json = serde_json::to_string(&ttlv)?;
        // create the file (or overwrite it)
        let mut file =
            File::create(&self.object_file).with_context(|| "Fail to write exported file")?;
        write!(&mut file, "{}", &json).with_context(|| {
            format!(
                "failed writing the object {} to file {:?}",
                &self.object_id, &self.object_file
            )
        })?;
        println!(
            "The object {} of type {} was exported to {:?}",
            &self.object_id, ttlv.tag, &self.object_file
        );

        Ok(())
    }
}

/// Import an object in the KMS, returning its KMS Id.
/// The object must be already serialized using KMIP TTLV.
/// Note: the key to import must be serialized in KMIP TTLV format.
/// If you want to import a key in raw format, please use `import-keys` subcommand.
#[derive(Parser, Debug)]
pub struct ImportAction {
    /// The KMIP TTLV JSON file containing the object. Defaults to `object.json`
    #[clap(
        required = false,
        long = "object-file",
        short = 'f',
        default_value = "object.json"
    )]
    object_file: PathBuf,

    /// The Unique identifier to use when inserting the object in the KMS.
    /// Will fail if the identifier already exists and the `--replace-existing` option is not set.
    ///
    /// When not specified, a unique identifier will be created
    #[clap(required = false, long = "unique-id", short = 'i', default_value = "")]
    unique_identifier: String,

    /// Replace the object if an object with the same identifier already exists.
    /// Defaults to false.
    #[clap(long = "replace-existing", short = 'r')]
    replace_existing: bool,
}

impl ImportAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        // a passed lambda to check the imported object and determine its ObjectType
        // Reverse injection minimises the code duplication and makes the ImportAction more general
        determine_object_type: impl Fn(&Object) -> eyre::Result<ObjectType>,
    ) -> eyre::Result<()> {
        let file = File::open(&self.object_file)
            .with_context(|| format!("Can't read the object file: {:?}", &self.object_file))?;

        let ttlv: TTLV = serde_json::from_reader(&file)
            .with_context(|| format!("Failed reading the object file: {:?}", &self.object_file))?;
        let object: Object = from_ttlv(&ttlv)
            .with_context(|| format!("Invalid TTLV in object file: {:?}", &self.object_file))?;

        //determine the object type using the passed lambda
        let object_type = determine_object_type(&object)?;
        let object = Object::post_fix(object_type, object);

        let attributes = if let Ok(attrs) = object
            .key_block()
            .context("object to be imported must contain a key block")?
            .key_value
            .attributes()
        {
            attrs.clone()
        } else {
            Attributes::new(object_type)
        };

        let import = build_import_object_request(
            object,
            object_type,
            attributes,
            &self.unique_identifier,
            Some(self.replace_existing),
        );

        let import_response = client_connector
            .import(import)
            .await
            .with_context(|| format!("failed importing the object with type {object_type}"))?;
        println!(
            "The object in {:?} of type {} was imported with id: {}",
            &self
                .object_file
                .file_name()
                .and_then(std::ffi::OsStr::to_str),
            &object_type,
            &import_response.unique_identifier
        );
        Ok(())
    }
}
