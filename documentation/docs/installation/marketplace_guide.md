A KMS-ready instance based on Cosmian Confidential VM can be deployed on virtual machines
that supports AMD SEV-SNP or Intel TDX technologies, and is available on the marketplace of the major cloud providers.

If you are interested in the confidential computing technology and the Cosmian VM,
please first read the guide about [how to setup a Cosmian VM](../../cosmian_vm/deployment_guide.md).

## Deploy Cosmian VM KMS on a cloud provider

Go the Cosmian marketplace webpage of the chosen [cloud provider](https://cosmian.com/fr/marketplaces-fr/).

Select an OS and continue until the Cosmian VM KMS instance is spawned.

!!! important "Cloud provider support"

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

The Cosmian KMS contains:

- a ready-to-go Nginx setup (listening on port `443` and locally on port `9998`)
- a ready-to-go KMS service
- the Cosmian VM software stack. As reminder, Cosmian VM Agent is listening
  on port `5555`.

## Configure the KMS 📜

### Default configuration

By default:

- the KMS server is locally listening on port 9998
- its database is a local Redis database with encrypted data
  using the scheme [Findex](../../search/findex.md).
- the KMS configuration file is located in the encrypted LUKS container
  at `/var/lib/cosmian_vm/data/app.conf` and has the following content:

```toml
default_username = "admin"

[http]
port = 9998
hostname = "0.0.0.0"

[db]
database_type = "redis-findex"
database_url = "redis://0.0.0.0:6379"
redis_master_password = "master-password"
```

For testing purposes (connectivity, features, etc.), KMS server can also use a SQLite database by modifying the
configuration file:

```toml
default_username = "admin"

[http]
port = 9998
hostname = "0.0.0.0"
```

!!! important "Protect your secrets"

    The Cosmian KMS configuration can potentially contain secrets
    (such as this `redis_master_password` field), that is why
    the configuration file is save in a LUKS container (default path: `/var/lib/cosmian_vm/data`).
    To override the default
    configuration, a new configuration SHOULD be sent remotely and securely via
    the Cosmian VM CLI following [see app init](#override-the-default-configuration).

### Override the default configuration

The default configuration can be overridden remotely by using the
[Cosmian VM CLI](../../cosmian_vm/deployment_guide.md#install-the-cosmian-vm-cli)
without any SSH connection.

It is safe to provide secrets (such as passwords) in
the configuration file because this file is going to be stored in the encrypted
folder (LUKS) of the Cosmian VM KMS (which is mounted by default on `/var/lib/cosmian_vm/data`).

Cosmian VM CLI has to be installed on the client machine (Ubuntu, RHEL or via Docker).
Please follow the [installation instructions](../../cosmian_vm/deployment_guide.md#install-the-cosmian-vm-cli).

Then proceed as follows:

```shell title="On the local machine"
cosmian_vm --url https://${COSMIAN_KMS_IP_ADDR}:5555 \
           --allow-insecure-tls \
           app init -c kms.toml

Processing the init of the deployed app...
The app has been configured and started
```

This command will send via an encrypted tunnel the configuration that will be
written in the remotely path `/var/lib/cosmian_vm/data/app.conf` which is
contained in an encrypted container (LUKS).

where `kms.toml` can be:

```toml
default_username = "admin"

[http]
port = 9998
hostname = "0.0.0.0"

[db]
database_type = "redis-findex"
database_url = "redis://<EXTERNAL_HOSTNAME_OR_IP>:6379"
redis_master_password = "master-password"
```

- The database type `redis-findex` is a Redis database with encrypted data and
  encrypted indexes thanks to Cosmian Findex.
- The `database_url` points to the Redis, typically an external managed Redis database.
- The `redis_master_password` is used to encrypt the Redis data and indexes.

### Service

`Systemd` is used to supervise and run the KMS server and the Cosmian VM agent.
As an administrator, you can see the running services with the following commands:

```sh
systemctl status cosmian_kms
systemctl status cosmian_vm_agent
```

You can read as well full logs using:

```sh
journalctl -u cosmian_kms
journalctl -u cosmian_vm_agent
```

### Check the connection with the KMS

```console
$ curl --insecure https://${COSMIAN_VM_IP_ADDR}/version
"5.16.2"
```

!!! info "Why `--allow-insecure-tls` and `--insecure` flags?"

    When the agent starts (see [Snapshot the VM](#snapshot-the-vm)) self-signed
    certificate is created to enable HTTPS out of the box.

    These certificates must be replaced by trusted ones using tools like
    `cosmian_certtool` or Linux tools (`certbot` with **Let's Encrypt** for instance).

    See [how to setup trusted certificates](../cosmian_vm/deployment_guide.md#configure-https-with-your-own-domain).

## Snapshot the VM 📸

Once the VM is configured as needed, Cosmian VM Agent can do a snapshot of the
VM containing fingerprint of the executables and metadata related to TEE and TPM.

The agent creates an encrypted folder (LUKS container) to store sensitive
information, creates self-signed certificate for Nginx and starts a snapshot.

Wait for the agent to initialize the LUKS and generate the certificates.
This is automatically at boot.

In short, to generate a snapshot, please [follow](../../cosmian_vm/deployment_guide.md#snapshot-the-vm-remotely).

The associated command is:

```console title="On the local machine"
cosmian_vm --url https://${COSMIAN_VM_IP_ADDR}:5555 --allow-insecure-tls snapshot
```

## Verify the Cosmian VM KMS integrity ✅

Verifying trustworthiness of the Cosmian VM KMS is exactly the same process
as [verifying the Cosmian VM](../../cosmian_vm/overview.md) itself.

In short, to verify a snapshot, please [follow](../cosmian_vm/deployment_guide.md#verify-the-vm-snapshot).

The associated command is:

```console title="On the local machine"
cosmian_vm --url https://${COSMIAN_VM_IP_ADDR}:5555 --allow-insecure-tls verify \
--snapshot cosmian_vm.snapshot
```
