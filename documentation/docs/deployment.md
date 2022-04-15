
The KMS server is packaged in a single Docker image based on Ubuntu 21.10.

### Installing

Install the Docker image:

```console
sudo docker load < cosmian_kms_server_1_2_1.tar.gz
```
### Running

The KMS server can be run in 2 modes:

 - in light mode, mostly for testing, using an embedded SQLite database
 - in db mode, using an external PostgreSQL Database

#### Light mode

The light mode is for single server run and persists data _inside_ the container (in `/tmp/kms.db`) by default. The root directory for the DB inside the container can be changed by setting the environment variable `KMS_ROOT_DIR` i.e.
```
-e KMS_ROOT_DIR=/root
```

To run in light mode, using the defaults, simply run the container as

```
sudo docker run -p 9998:9998 cosmian/kms_server:1.2.1
```

The server REST port will be available on 9998.

#### DB mode


In DB mode, the server is using Postgre SQL database to store its objects. 
An URL must be provided to allow the KMS server to connect to the database (see below).


Before running the server a dedicated database with a dedicated user should be created on the PostgreSQL instance. Here are example instructions to create a database called `kms` owned by a user `kms_user` with password `kms_password`:


1. Connect to psql under user `postgres`

```
sudo -u postgres psql
```

2. Create user `kms_user` with password `kms_password`

```
create user kms_user with encrypted password 'kms_password';
```

The user and password can obviously be set to any other appropriate values.

3. Create database `kms` under owner `kms_user`

```
create database kms owner=kms_user;
```

Likewise, the database can be set to another name.

4. Connection `POSTGRES_URL`

Assuming a server running on 1.2.3.4, the environment variable to pass with the connection URL will be

```
KMS_POSTGRES_URL=CONNECTION=postgresql://kms_user:kms_password@1.2.3.4:5432:kms
```

5. Launch the KMS server on port 9998

```sh
sudo docker run \
-p 9998:9998 \
-e KMS_POSTGRES_URL=CONNECTION=postgresql://kms_user:kms_password@1.2.3.4:5432:kms \
-e KMS_DELEGATED_AUTHORITY_DOMAIN=my_auth_domain.com \
cosmian/kms_server:1.2.1
```

###### Note

On linux, if PostgreSQL is running on the docker host, the network should be mapped to the `host` and launched using


```sh
sudo docker run \
-e KMS_POSTGRES_URL=postgresql://kms_user:kms_password@localhost:5432/kms \
--network host \
cosmian/kms_server:1.2.1
```
The port wil be `9998`; this can be changed by setting the environment variable `KMS_PORT=[port]`

### Versions correspondence

#### Versions

This table shows the minimum versions correspondances between the various components

KMS Server | Java Lib | abe_gpsw lib
-----------|----------|--------------
1.2.0      | 0.5.0    | 0.3.0
1.2.1      | 0.5.1    | 0.4.0
1.2.1      | 0.6.1    | 0.6.1

#### Repositories

Main librairies repositories

[Cosmian Java Lib](https://github.com/Cosmian/cosmian_java_lib)

[abe_gpsw lib](https://github.com/Cosmian/abe_gpsw)
