Python Setup

# Create a virtual environment and install required modules into it

```python
python3 -m venv cli_env
source cli_env/bin/activate
pip install -r requirements.txt
```

# Invoke the tool

```python
python cse_cmd.py -h
```

# Sample steps to upload keys/certs for CSE

1. Create a directory for storing all wrapped private keys.

    Ex: `$root/wrapped_keys`

    a. The wrapped private key file for each user should have basename as email-id
    and a `.wrap` extension.

      Ex: `$root/wrapped_keys/user1@example.com.wrap`

    b. The wrapped private key file should have a json object with
      two required fields:

    ```json
      {
        'kacls_url': 'url of kacls configured in CSE Admin Console',
        'wrapped_private_key': 'wrapped private key bytes'
      }
    ```

2. Create a directory for storing all certificates in p7 pem format.

    Ex: $root/p7pem_certs

    a. The certificate file should contain the full chain to root CA and should
    have basename as email-id and a `.p7pem` extension.

      Ex: `$root/p7pem_certs/user1@example.com.p7pem`

    b. If you have p7b file, you can use the following openssl command to convert
    it to a p7 pem format:

    ```bash
    openssl pkcs7 -inform DER -in {old_name.p7b} -outform PEM -out {new_name.p7pem}
    ```

3. Note that all commands require one argument

  `--creds`: a json file contains credentials to the service account created
  in your GCP project. After creating a service account, you can download
  the credentials to that account to a json file, which you will use here.

  Ex: stored at `$root/gmail_discovery_doc.json, $root/svc_acct_creds.json`

4. Easiest is to run the `insert` command to insert key pairs and identities

  Ex:

  ```bash
  python cse_cmd.py insert
      --creds $root/svc_acct_creds.json
      --inkeydir $root/wrapped_keys
      --incertdir $root/p7pem_certs
  ```

  a. Alternatively, you could run `insert_keypair`, note down the keypair id
    and then run `insert_identity` using that keypair id. You can also get the
    keypair id by running `list_keypair` command.

5. You can check if user has a valid cse keypair or identity by running
  `list_keypair` and/or `list_identity`
