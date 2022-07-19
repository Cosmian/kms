

### EdgelessDB as database

[EdgelessDB](https://docs.edgeless.systems/edgelessdb/#/) is based on MariaDB, so the MySQL connector will be used for that.

Currently, the `sqlx` crate is not able to authentify using a key-file, as requested with EdgelessDB.

That's why two implementations are available in the KMS Server.

Follow this guide to use EdgelessDB in simulation mode (without SGX): https://docs.edgeless.systems/edgelessdb/#/getting-started/quickstart-simulation

Use `KMS_USER_CERT_PATH` to give the client certificate to the KMS server. 

**TL;DR**

Data has been generated and is available in `data-ssl` and `data_ssl3` folder such
as:

- `data-ssl` is to use if you have a libssl<=2
- `data-ssl3` is to use if you have a libssl=3

To re-create key material, perform the following:

```console
openssl req -x509 -newkey rsa -nodes -days 3650 -subj '/CN=My CA' -keyout ca-key.pem -out ca-cert.pem
openssl req -newkey rsa -nodes -subj '/CN=rootuser' -keyout key.pem -out csr.pem
openssl x509 -req -days 3650 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -in csr.pem -out cert.pem

awk 1 ORS='\\n' ca-cert.pem
```

Then create a `manifest.json` file as requested in the guide.

An additional step is required to use properly the `mysql` crate that will connect using key-file.

```console
openssl pkcs12 -export -out cert.p12 -in cert.pem -inkey key.pem
```

If it prompts for export password, just hit `Enter`.

For simplified example, see: http://gitlab.cosmian.com/thibaud.genty/mysql_test

**EdgelessDB for Gitlab CI**

An EdgelessDB is running on `gitlab-runner-1` so that CI can test MySQL connector against it.

The database is using key material located on the home folder of the `gitlab-runner` user.

<u>Start Docker container</u>

```console
sudo docker run --restart unless-stopped -d --name my-edb -p3306:3306 -p8080:8080 -e OE_SIMULATION=1 -t ghcr.io/edgelesssys/edgelessdb-sgx-1gb
```

Note: the EdgelessDB is currently running in simulation mode (not using SGX enclave).

<u>Upload manifest to setup key material</u>

```console
cd /home/gitlab-runner/data
curl -k --data-binary @manifest.json http://gitlab-runner-1.cosmian.com:8080/manifest
```

<u>Test it works</u>

```console
cd /home/gitlab-runner/
mysql -h127.0.0.1  -uroot -e "SHOW DATABASES"  --ssl-cert $(pwd)/data/cert.pem --ssl-key $(pwd)/data/key.pem
+--------------------+
| Database           |
+--------------------+
| $edgeless          |
| information_schema |
| kms                |
| mysql              |
+--------------------+
```

