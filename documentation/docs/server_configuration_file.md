# TOML configuration file

By default, the configuration filepath is retrieved in the following order:

1. if the environment variable `COSMIAN_KMS_CONF` is set and the path behind exists, the KMS server will use it as
   configuration file path.
2. otherwise if a file is found at `/etc/cosmian_kms/kms.toml`, the KMS server will use it to configure itself.
3. finally, if none of the above is found, the KMS server will load default configuration values in combination
   additional CLI arguments.

The file should be a TOML file with the following structure:

```toml
default_username = "[default username]"
force_default_username = false
google_cse_kacls_url = "[google cse kacls url]"
ms_dke_service_url = "[ms dke service url]"
info = false

# The following fields are only neeeded if an HSM is used. Check the HSMs pages for more information.
hsm_model = "<hsm_name>"
hsm_admin = "<hsm admin username>" #for Create operation on HSM
hsm_slot = [1, 2, ...]
hsm_password = ["<password_of_1st_slot1>", "<password_of_2bd_slot2>", ...]

[db]
database_type = "[redis-findex, postgresql,...]"
database_url = "[redis urls]"
sqlite_path = "[sqlite path]"
redis_master_password = "[redis master password]"
redis_findex_label = "[redis findex label]"
clear_database = false

[http]
port = 443
hostname = "[hostname]"
https_p12_file = "[https p12 file]"
https_p12_password = "[https p12 password]"
authority_cert_file = "[authority cert file]"

[auth]
jwt_issuer_uri = ["[jwt issuer uri]"]
jwks_uri = ["[jwks uri]"]
jwt_audience = ["[jwt audience]"]

[workspace]
root_data_path = "[root data path]"
tmp_path = "[tmp path]"

[telemetry]
otlp = "[url of the OTLP collector]"
quiet = false
```
