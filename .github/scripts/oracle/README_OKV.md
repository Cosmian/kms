# Oracle Key Vault integration notes

Links:

- OKV + HSM overview: <https://docs.oracle.com/en/database/oracle/key-vault/18.5/okvhm/getting-started-hsm.html#GUID-A3CAE519-F583-4639-BD77-93289D64DF5C>
- `okvutil`: <https://docs.oracle.com/en/database/oracle/key-vault/18.1/okvag/okvutil_endpoint_utility_reference.html#GUID-E3D8731E-F905-4259-96F3-4B5D68754467>
- Administration of TDE for Oracle Database: <https://docs.oracle.com/en/database/oracle/oracle-database/23/dbtde/configuring-united-mode2.html#GUID-D3045557-FA85-4EA5-A85A-75EAE9D67E13>
- Pull official docker Oracle database: <https://container-registry.oracle.com/ords/f?p=113:4:106545702571334:::4:P4_REPOSITORY,AI_REPOSITORY,AI_REPOSITORY_NAME,P4_REPOSITORY_NAME,P4_EULA_ID,P4_BUSINESS_AREA_ID:1863,1863,Oracle%20Database%20Free,Oracle%20Database%20Free,1,0&cs=3Ti6PWKfgzS30ZJfMaoHY1WKna0Ss_mxMjkSQqTBI7AfugrE1tN9BilNn74Z9ynq_5THQFpwXGPfVnPbkILvCiw>
- Configure Oracle Database with OKV: <https://docs.oracle.com/en/database/oracle/oracle-database/23/dbtde/configuring-united-mode2.html#GUID-CD6E4741-4916-4F24-9427-4DA25DF40587>
    - <https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/WALLET_ROOT.html#REFRN-GUID-37347728-3D24-444A-A9ED-5B981C4EA2D3>
    - <https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/TDE_CONFIGURATION.html#REFRN-GUID-285A9BCE-22AE-4DE4-A76E-1319B7BB91BC>
- Set the encryption on DB: <https://bryangrenn.blogspot.com/2021/04/migrating-your-tde-wallet-to-oracle-key.html>
- Example of encryption on DB: <https://blog.capdata.fr/index.php/le-chiffrement-oracle-transparent-data-encryption-sur-oracle-19c/>

Install OVK 21.10
  Warning:
    Storage must be at least 256Gb
  Network
    IP 192.168.1.211 (arbitrary)
    Gateway 192.168.1.254
    DNS1 192.168.1.17
    -> This file /etc/sysconfig/network-scripts/ifcfg-enp0s3 will be overwritten.
Build libcosmian_pkcs11.so on debian-buster where glibc 2.28 is equal to OVK RHEL system.

Create `cosmian` user in `support` group.
  sudo useradd -m -g support cosmian
  sudo passwd cosmian # Password: Toto123Toto123,
Add `cosmian` user to sudo's users. (visudo + `cosmian ALL=(ALL) NOPASSWD: ALL`)
Relax SSH:
  On SSH server:
    vi /etc/ssh/sshd_config
      ClientAliveInterval 0
    systemctl restart sshd
  On SSH client:
    ssh-copy-id -i ~/.ssh/id_rsa.pub cosmian@192.168.1.211
    # SSH config:
    # Host okv
    #     HostName 192.168.1.211
    #     User cosmian
    #     IdentityFile ~/.ssh/id_rsa
Open SSH server port 22
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -L -v -n --line-numbers # identify REJECT rule
  iptables -D INPUT 15
  iptables-save > /etc/sysconfig/iptables
  service iptables save
  OR delete REJECT-line manually in file /etc/sysconfig/iptables.save

Installation configuration:
  Admin user:
    login: KEY
    password: e.SdGe4c+ebFPCu.
    recovery_password: e.SdGe4c+ebFPCu

```sh
scp libcosmian_pkcs11.so /usr/local/okv/hsm/generic/
Edit /usr/local/okv/hsm/generic/okv_hsm.conf

```sh
[root@okv080027c5c0eb hsm]# cat /usr/local/okv/hsm/generic/okv_hsm.conf
# Oracle Key Vault HSM vendor configuration file
# Lines must be shorter than 4096 characters.

# The vendor name, to be displayed on the HSM page on the management console.
VENDOR_NAME="Cosmian"

# The location of the PKCS#11 library. This file must be preserved on upgrade.
PKCS11_LIB_LOC="/usr/local/okv/hsm/generic/libcosmian_pkcs11.so"

# A colon-separated list of the full paths of files and directories that must
# be preserved on upgrade. All of these files and directories should have been
# created by the HSM client software setup; none should have existed on Oracle
# Key Vault by default. These will be necessary when upgrading to a version
# of Oracle Key Vault that is running on a higher major OS version.
# Do not use wildcards.
PRESERVED_FILES=""
````

Edit /usr/local/okv/hsm/generic/okv_hsm_env

```sh
[root@okv080027c5c0eb hsm]# cat /usr/local/okv/hsm/generic/okv_hsm_env
# Oracle Key Vault HSM vendor environment file
# Use this file to set any necessary environment variables needed when using
# a vendor's PKCS#11 library. Parameter names must not contain '='.
# Parameter values must be enclosed in double quotes. Names and values must
# be shorter than 4096 characters.

# Below is an example. Remove the '#' character to uncomment the line.
#EXAMPLE_ENV_VAR_NAME="EXAMPLE_ENV_VAR_VALUE"
COSMIAN_PKCS11_LOGGING_LEVEL="trace"
COSMIAN_CLI_CONF="/home/oracle/.cosmian/config.toml"
```

Read the logs on /var/okv/log/hsm/...

`oracle` user needs to be able to write to /var/log/cosmian-pkcs11.log

```sh
chown oracle:oracle /var/log/cosmian-pkcs11.log
chmod 664 /var/log/cosmian-pkcs11.log
```

Configure the KMS CLI configuration for oracle user (/home/oracle/.cosmian/config.toml):

```sh
[kms_config.http_config]
server_url = "http://192.168.1.17:9998"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
```

Initialize the HSM in Oracle Key Vault:
    Go to UI->System->Settings->HSM
    Click on Initialize button

You should have:

```text
[root@okv080027c5c0eb ~]# cat /var/okv/log/hsm/*
2025-03-26 14:55:02.122: Beginning trace for hsmclient pre_restore
2025-03-26 14:55:02.122: Loading /usr/local/okv/hsm/generic/okv_hsm_env
2025-03-26 14:55:02.122: Setting COSMIAN_PKCS11_LOGGING_LEVEL to trace
2025-03-26 14:55:02.122: Setting COSMIAN_CLI_CONF to /home/oracle/.cosmian/cosmian.toml
2025-03-26 14:55:02.123: WARNING: skipping line 11 with invalid formatting
2025-03-26 14:55:02.123: Setting path
2025-03-26 14:55:02.123: No token label provided
2025-03-26 14:55:02.123: Loading PKCS11 library: /usr/local/okv/hsm/generic/libcosmian_pkcs11.so
2025-03-26 14:55:02.147: Writing HSM credential from user input
2025-03-26 14:55:02.147: Creating the HSM credential wallet...
Oracle PKI Tool Release 19.0.0.0.0 - Production
Version 19.4.0.0.0
Copyright (c) 2004, 2024, Oracle and/or its affiliates. All rights reserved.

Operation is successfully completed.
2025-03-26 14:55:04.046: Created the HSM credential wallet
2025-03-26 14:55:04.047: Proceeding with FIPS enabled for HSM
2025-03-26 14:55:04.148: Finished writing HSM credential
2025-03-26 14:55:04.148: Checking for HSM credential...
2025-03-26 14:55:04.148: Retrieving the HSM credential...
2025-03-26 14:55:04.148: Proceeding with FIPS enabled for HSM
2025-03-26 14:55:04.216: Retrieved the HSM credential
2025-03-26 14:55:04.216: HSM credential found
2025-03-26 14:55:04.216: Connecting to HSM...
2025-03-26 14:55:04.216: Connecting to the HSM...
2025-03-26 14:55:04.216: Not using token label to choose slot, defaulting to first in slot list
2025-03-26 14:55:04.216: Connected to the HSM
2025-03-26 14:55:04.216: Connection to HSM succeeded
2025-03-26 14:55:04.216: Checking HSM setting in configuration file
2025-03-26 14:55:04.216: HSM enabled in configuration file
2025-03-26 14:55:04.216: Getting encryption key metadata...
2025-03-26 14:55:04.216: Verifying header...
2025-03-26 14:55:04.216: Header version: 0x18010000
2025-03-26 14:55:04.216: HSM Root of Trust key number: 281109417
2025-03-26 14:55:04.216: Header verified
2025-03-26 14:55:04.216: Retrieved encryption key metadata
2025-03-26 14:55:04.216: Searching for root of trust in HSM...
2025-03-26 14:55:04.216: Getting the Root of Trust key...
2025-03-26 14:55:04.245: Retrieved 1 keys
2025-03-26 14:55:04.245: Retrieved Root of Trust key handle: 0
2025-03-26 14:55:04.245: Found root of trust in HSM
2025-03-26 14:55:04.245: Checking that we can decrypt the encrypted TDE password...
2025-03-26 14:55:04.245: Decrypting data...
2025-03-26 14:55:04.280: Finished decrypting data
2025-03-26 14:55:04.280: Able to decrypt the TDE password.
2025-03-26 14:55:04.280: Checking that the TDE password is correct...
2025-03-26 14:55:04.280: Checking the wallet password...
2025-03-26 14:55:05.853: Checked the wallet password
2025-03-26 14:55:05.853: TDE password is correct.
2025-03-26 14:55:05.853: Checking password for the restore wallet...
2025-03-26 14:55:05.853: Checking the wallet password...
2025-03-26 14:55:07.506: Checked the wallet password
2025-03-26 14:55:07.506: Restore wallet password is correct.
2025-03-26 14:55:07.506: Checking wallet links
2025-03-26 14:55:07.506: Verified wallet links
2025-03-26 14:55:07.506: HSM configuration verified
2025-03-26 14:55:07.506: Disconnecting from the HSM...
2025-03-26 14:55:07.506: Disconnected from the HSM
2025-03-26 14:55:07.561: Unloading PKCS11 library
2025-03-26 14:55:07.561: Finished successfully
Cosmian PKCS#11 provider: C_GetFunctionList called
cosmian-pkcs11 module logging at TRACE level to file /var/log/cosmian-pkcs11.log
Enter HSM credential:
Reenter HSM credential:
```

## Install Oracle Database 23.1 using docker container

Example using docker-compose.yml:

```yaml

  oracle:
    container_name: oracle
    image: container-registry.oracle.com/database/free:latest
    ports:
      - 1521:1521
    environment:
      ORACLE_PWD: 1234
      ENABLE_ARCHIVELOG: true
      ENABLE_FORCE_LOGGING: true
    volumes:
      - ./oradata:/opt/oracle/oradata
      - ./keystore:/opt/oracle/keystore
```

Prepare docker volumes permissions:

```sh
sudo chown -R oracle:oinstall /opt/oracle/oradata
sudo chown -R oracle:oinstall /opt/oracle/keystore
```

To connect to the database at the CDB$ROOT level as sysdba:

```sh
sqlplus sys/<your password>@//localhost:<port mapped to 1521>/FREE as sysdba
docker exec -it oracle sqlplus sys/1234@FREE as sysdba
ALTER SYSTEM SET WALLET_ROOT='/etc/ORACLE/KEYSTORES/${ORACLE_SID}' SCOPE = SPFILE;
SHUTDOWN IMMEDIATE
STARTUP
ALTER SYSTEM SET TDE_CONFIGURATION="KEYSTORE_CONFIGURATION=OKV" SCOPE=SPFILE SID='*';
```

Install okvclient.jar and extract okvclient.
ENDPOINT_1: enrollment token: 9VG8zmrqbgugUhlX

```sh
cd /opt/oracle/keystore
export JAVA_HOME=/opt/oracle/product/23ai/dbhomeFree/jdk/
export PATH=$PATH:$JAVA_HOME/bin/
java -jar okvclient.jar
# as root
./bin/root.sh
```

Open the keystore:

First create the folder containing the keystore:

```sh
mkdir -p /etc/ORACLE/KEYSTORES/FREE
chown -R oracle:oinstall /etc/ORACLE/KEYSTORES/FREE
```

```sql
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE IDENTIFIED BY "9VG8zmrqbgugUhlX";
```

Open the keystore: make sure okvclient is in the correct path given by WALLET_ROOT

```sh
mkdir /etc/ORACLE/KEYSTORES/FREE/okv
cp -r /opt/oracle/keystore/* /etc/ORACLE/KEYSTORES/FREE/okv/
```

```sql
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY 9VG8zmrqbgugUhlX;
# Verify a keystore is open
column name format a40
SELECT STATUS FROM V$ENCRYPTION_WALLET;
select WRL_TYPE,WRL_PARAMETER,STATUS,WALLET_TYPE,WALLET_ORDER,FULLY_BACKED_UP from v$encryption_wallet;
# Eventually, set auto-login when TDE_CONFIGURATION=OKV|FILE
ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE IDENTIFIED BY 9VG8zmrqbgugUhlX;
# Create the master key
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY 9VG8zmrqbgugUhlX WITH BACKUP;
# Check keystore:
select KEY_ID,KEYSTORE_TYPE,CREATOR_DBNAME,ACTIVATION_TIME,KEY_USE,ORIGIN from v$encryption_keys;
```

For information:

```sql
ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE IDENTIFIED BY 9VG8zmrqbgugUhlX;
```

```sql
administer key management use key '068EDC928F2D5C05F2F723D73045B10618' by <okv-pwd> | external store;
administer key management use key '06E8C385D1DFC54F25BF929386ADA93E59' IDENTIFIED by 9VG8zmrqbgugUhlX | external store;

```

Check the created PKCS12 wallet:

```sh
openssl pkcs12 -in /etc/ORACLE/KEYSTORES/FREE/tde/ewallet.p12 -passin pass:"9VG8zmrqbgugUhlX" -info -nodes
````

Create a database:

```sql
CONNECT SYS AS SYSDBA
CREATE DATABASE test_db
     DATAFILE 'test_system' SIZE 10M
     LOGFILE GROUP 1 ('test_log1a', 'test_log1b') SIZE 500K,
     GROUP 2 ('test_log2a', 'test_log2b') SIZE 500K;

CREATE USER C##u1 IDENTIFIED BY pwd1 DEFAULT TABLESPACE USERS TEMPORARY TABLESPACE TEMP QUOTA UNLIMITED ON USERS CONTAINER=ALL;
GRANT CREATE SESSION to C##u1;
GRANT CREATE TABLE TO C##u1;
```

Connect as normal user:

```sh
docker exec -it oracle sqlplus C##u1/pwd1@FREE
```

```sql
connect test_db
create table infos_employees (prenom varchar2(40),  nom varchar2(40),
  address varchar2(40) encrypt using 'AES256',
  postal_code number(6) encrypt using 'AES256');
insert into infos_employees values ('Emmanuel','Rami','19 rue Crebillon Nantes','44000');
```

Check the encryption on columns:

```sql
connect SYS as SYSDBA;
select * from dba_encrypted_columns;
````

Check in trace that columns are encrypted:

```sql
select rowid from infos_employees where NOM='Rami';
select DBMS_ROWID.ROWID_BLOCK_NUMBER('AAARriAAAAAAAMNAAA') "Block number" from DUAL;
select DBMS_ROWID.ROWID_BLOCK_NUMBER('AAARq2AAAAAAAMLAAA') "Block number" from DUAL;
alter system dump datafile 7 block 781;
```

```sh
# check last trace file
ls -alt /opt/oracle/diag/rdbms/free/FREE/trace/FREE_*
cat /opt/oracle/diag/rdbms/free/FREE/trace/FREE_ora_42690.trc
Dump of memory from 0x7bb9f6fcf000 to 0x7bb9f6fd1000
7BB9F6FCF000 0000A206 0000030D 003368F4 04030000  [.........h3.....]
7BB9F6FCF010 00003D97 00400301 00011AE2 003368F4  [.=....@......h3.]
7BB9F6FCF020 00008000 00320002 00000308 00170002  [......2.........]
7BB9F6FCF030 00000345 0000043D 001700CB 00000001  [E...=...........]
7BB9F6FCF040 00000000 00000000 00000000 00000000  [................]
        Repeat 1 times
7BB9F6FCF060 00000000 00010100 0014FFFF 1EF91F0D  [................]
7BB9F6FCF070 00001EF9 1F0D0001 00000000 00000000  [................]
7BB9F6FCF080 00000000 00000000 00000000 00000000  [................]
        Repeat 494 times
7BB9F6FD0F70 04012C00 6D6D4508 65756E61 6152046C  [.,...Emmanuel.Ra]
7BB9F6FD0F80 DA44696D 12C3B171 401428BB 94A00122  [miD.q....(.@"...]
7BB9F6FD0F90 4B1404B3 A9A60247 8E83EDC9 FF4B00E6  [...KG.........K.]
7BB9F6FD0FA0 EB0AEAA2 0DCD80CC 74B76A49 58BB6409  [........Ij.t.d.X]
7BB9F6FD0FB0 8AFC82EF EFCAD9E4 57F852B7 A475DD22  [.........R.W".u.]
7BB9F6FD0FC0 81C7E986 341FD58D 80147AAD A951EB8A  [.......4.z....Q.]
7BB9F6FD0FD0 85E287F8 1AA8C6BF 42893EE8 512CDF0F  [.........>.B..,Q]
7BB9F6FD0FE0 EED2CD1B C69B4F9C 24BD6BFD DFBED941  [.....O...k.$A...]
7BB9F6FD0FF0 7CC500C4 B6FE27D6 F788661E 68F40603  [...|.'...f.....h]

```

Compare with clear table:

```sql
connect C##u1
create table infos_societies (nom varchar2(40),
  reason varchar2(40),
  address varchar2(40),
  postal_code number(6) );
insert into infos_societies values ('Capdata','SA','9 rue de la porte de Buc Versailles','78000');
select rowid from infos_societes where NOM='Capdata';
select DBMS_ROWID.ROWID_BLOCK_NUMBER('AAARruAAAAAAAMWAAA') "Block number" from DUAL;
alter system dump datafile 7 block 790;
```

```sh
ls -alt /opt/oracle/diag/rdbms/free/FREE/trace/

Dump of memory from 0x76d822c0a000 to 0x76d822c0c000
76D822C0A000 0000A206 00000316 003412CE 04030000  [..........4.....]
76D822C0A010 00006614 00000001 00011AEE 003412CE  [.f............4.]
76D822C0A020 00008000 00320002 00000310 001A0001  [......2.........]
76D822C0A030 0000032F 0000084F 003100AB 00000001  [/...O.....1.....]
76D822C0A040 00000000 00000000 00000000 00000000  [................]
        Repeat 1 times
76D822C0A060 00000000 00010100 0014FFFF 1F4E1F62  [............b.N.]
76D822C0A070 00001F4E 1F620001 00000000 00000000  [N.....b.........]
76D822C0A080 00000000 00000000 00000000 00000000  [................]
        Repeat 499 times
76D822C0BFC0 00000000 012C0000 61430704 74616470  [......,...Capdat]
76D822C0BFD0 41530261 72203923 64206575 616C2065  [a.SA#9 rue de la]
76D822C0BFE0 726F7020 64206574 75422065 65562063  [ porte de Buc Ve]
76D822C0BFF0 69617372 73656C6C 5108C303 12CE0603  [rsailles...Q....]
```
