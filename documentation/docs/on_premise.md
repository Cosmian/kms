
If you don't use the SaaS offering on the Cosmian public platform, and want to run your own KMS, follow the instructions below.

The KMS server is packaged in a single Docker image based on Ubuntu 21.10.

## Installing

The KMS server has been published in [Cosmian public docker hub](https://hub.docker.com/r/cosmian/kms) and can be run in 2 modes:

 - in light mode, mostly for testing, using an embedded SQLite database
 - in production mode, using an external PostgreSQL or MariaDB Database

### Light mode

The light mode is for single server run and persists data _inside_ the container (in `/tmp/kms.db`) by default.

To run in light mode, using the defaults, simply run the container as follows:

```yaml
version: "3.4"
services:
  kms:
    container_name: kms
    image: cosmian/kms
    environment:
      - KMS_HOSTNAME=0.0.0.0
      - KMS_PUBLIC_PATH=/data
      - KMS_PRIVATE_PATH=/data
      - KMS_SHARED_PATH=/data
    ports:
      - "9998:9998"
```

And run:

```bash
docker-compose up
```

The KMS server port will be available on 9998.

### Production mode

In DB mode, the server is using PostgreSQL or Maria database to store its objects.

An URL must be provided to allow the KMS server to connect to the database (see below).

For example, KMS server can use a PostgreSQL database as follows:

```yaml
version: "3.4"
services:
  db:
    container_name: db
    image: postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=kms
      - POSTGRES_DB=kms
      - POSTGRES_PASSWORD=kms
      - PGDATA=/opt/postgres
  kms:
    container_name: kms
    image: cosmian/kms
    environment:
      - KMS_POSTGRES_URL=postgres://kms:kms@db/kms
      - KMS_HOSTNAME=0.0.0.0
      - KMS_PUBLIC_PATH=/data
      - KMS_PRIVATE_PATH=/data
      - KMS_SHARED_PATH=/data
    ports:
      - "9998:9998"
    depends_on:
      - db
```

And run:

```bash
docker-compose up
```

#### PostgreSQL survival kit

Find below the instructions for PostgreSQL.

Before running the server a dedicated database with a dedicated user should be created on the PostgreSQL instance. Here are example instructions to create a database called `kms` owned by a user `kms_user` with password `kms_password`:


1. Connect to psql under user `postgres`

```
sudo -u postgres psql
```

2. Create user `kms_user` with password `kms_password`

```
create user kms_user with encrypted password 'kms_password';
```

The user and password should obviously be set to any other appropriate values.

3. Create database `kms` under owner `kms_user`

```
create database kms owner=kms_user;
```

Likewise, the database can be set to another name.

#### Note

On linux, if PostgreSQL is running on the docker host, the network should be mapped to the `host`.


## KMS CLI
The `cosmian/kms` docker image also contains the KMS client `cosmian_kms_cli`. This client simplifies the communications with the server as described in the CLI documentation.

The KMS CLI can be used as follows:

```bash
docker run --network=host -it --entrypoint /bin/cosmian_kms_cli -v $PWD/conf:/conf -e KMS_CLI_CONF=/conf/kms.json cosmian/kms:latest cc init --policy /conf/policy.json
```

where $PWD/conf is a folder containing the files:
- kms.json
- policy.json: The JSON file refers to [CoverCrypt](https://github.com/Cosmian/cover_crypt) which is a Cosmian encryption scheme which allows creating ciphertexts for a set of attributes and issuing user keys with access policies over these attributes.

As example:

kms.json:
```yaml
{
  "kms_server_url": "http://127.0.0.1:9998",
  "kms_access_token": ""
}
```

policy.json:
```yaml
{
    "policy": {
        "level": {
            "hierarchical": true,
            "attributes": ["confidential", "secret", "top-secret"]
        },
        "department": {
            "hierarchical": false,
            "attributes": ["finance", "marketing", "operations"]
        }
    },
    "max-rotations": 100
}
```
