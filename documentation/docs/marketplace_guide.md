# Deploy KMS in a Confidential Virtual Machine (CVM)

A KMS-ready instance based on Cosmian VM can be deployed on virtual machines that supports AMD SEV-SNP or Intel TDX technologies.

This instance can be deployed on virtual machines that supports AMD SEV-SNP or Intel TDX technologies.

Please first read the guide about how to setup a Cosmian VM.

The following steps can help one to deploy its own instance on each available cloud provider.

Please first read the guide about [how to setup a Cosmian VM](../cosmian_vm/deployment_guide.md).

## Deploy Cosmian VM KMS on a cloud provider

Go the Cosmian marketplace webpage of the chosen cloud provider.

Select an OS and continue until the Cosmian VM KMS instance is spawned.

Here's the list of instance types by cloud provider

| Cloud provider | Azure             | GCP          | AWS           |
| -------------- | ----------------- | ------------ | ------------- |
| **AMD**        | **SNP**           | **SNP**      | **SNP**       |
|                | Standard_DCas_v5  | n2d-standard | M6a           |
|                | Standard_DCads_v5 |              | C6a           |
|                |                   |              | R6a           |
| **Intel**      | **TDX**           | **TDX**      | **TDX**       |
|                | DCes_v5-series    | c3-standard  | Not available |
|                | ECesv5-series     |              |               |
|                | (preview)         |              |               |

The Cosmian VM KMS contains:

- a ready-to-go Nginx setup (listening on port `443` and locally on port `8080`)
- a ready-to-go KMS service
- the Cosmian VM software stack. As reminder, Cosmian VM Agent is listening on port `5555`.

The Cosmian KMS configuration can potentially contain secrets, that is why the configuration file is save in a LUKS container. To override the default configuration, a new configuration MUST be sent remotely and securely via the Cosmian VM CLI following [see app init](#deploy-the-configuration-and-starts-the-cosmian-kms).

### Service

`Systemd` is used to supervise and run the KMS server and the Cosmian VM agent. As an administrator, you can see the running services with the following commands:

```sh
systemctl status cosmian_kms
systemctl status cosmian_vm_agent
```

You can read as well full logs using:

```sh
journalctl -u cosmian_kms
journalctl -u cosmian_vm_agent
```

## Configure the KMS 📜

As explained previously, it is safe to provide secrets (such as passwords) in the configuration file because this file is going to be stored in the encrypted folder (LUKS) of the Cosmian VM KMS.

=== "KMS minimal config"

    By default a local SQLite database is used as storage engine.

    ```toml title="kms.toml on local machine"
    default_username = "admin"

    [http]
    port = 8080
    hostname = "0.0.0.0"
    ```

    This port is set accordingly with the one set in Nginx conf.

=== "KMS config with Redis"

    A database can be specified, for example an external managed Redis with a password

    ```toml title="kms.toml on local machine"
    default_username = "admin"

    [http]
    port = 8080
    hostname = "0.0.0.0"

    [db]
    database_type = "redis-findex"
    database_url = "redis://<some_managed_redis>:6379"
    redis_master_password = "master-password"
    redis_findex_label = "label"
    ```
    The DB type `redis-findex` is a Redis database with encrypted data and encrypted indexes thanks to Cosmian Findex.

    The `database_url` points to the Redis, typically an external managed Redis database.

    The `redis_master_password` is used to encrypt the Redis data and indexes.

    The `redis_findex_label` is a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key.

### Use Cosmian VM CLI to send securely the new KMS configuration

Cosmian VM CLI has to be installed on the client machine (Ubuntu, RHEL or via Docker). Please follow the [installation instructions](../cosmian_vm/deployment_guide.md#install-the-cosmian-vm-cli).

### Deploy the configuration and starts the Cosmian KMS

```console title="On the local machine"
cosmian_vm --url https://${COSMIAN_VM_IP_ADDR}:5555 \
           --allow-insecure-tls \
           app init -c kms.toml
```

This command will send via an encrypted tunnel the configuration that will be written in the remotely path `/var/lib/cosmian_vm/data/app.conf` which is contained in an encrypted container (LUKS).

### Check the connection with the KMS

```console
$ curl --insecure https://${COSMIAN_VM_IP_ADDR}/version
"4.16.0"
```

!!! info "Why `--allow-insecure-tls` and `--insecure` flags?"

    When the agent starts (see [Snapshot the VM](#snapshot-the-vm)) self-signed certificate is created to enable HTTPS out of the box.

    These certificates must be replaced by trusted ones using tools like `cosmian_certtool` or Linux tools (`certbot` with **Let's Encrypt** for instance).

    See [how to setup trusted certificates](../cosmian_vm/deployment_guide.md/#configure-https-with-your-own-domain).

## Snapshot the VM 📸

Once the VM is configured as needed, Cosmian VM Agent can do a snapshot of the VM containing fingerprint of the executables and metadata related to TEE and TPM.

The agent creates an encrypted folder (LUKS container) to store sensitive information, creates self-signed certificate for Nginx and starts a snapshot.

Wait for the agent to initialize the LUKS and generate the certificates. This is automatically at boot.

## Verify the Cosmian VM KMS integrity ✅

Verifying trustworthiness of the Cosmian VM KMS is exactly the same process as [verifying the Cosmian VM](../cosmian_vm/overview.md) itself.
