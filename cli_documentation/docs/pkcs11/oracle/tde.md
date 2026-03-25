# Oracle Database Transparent Data Encryption (TDE)

**Oracle Database** [Transparent Data Encryption (TDE)](https://docs.oracle.com/en/database/oracle/oracle-database/23/dbtde/introduction-to-transparent-data-encryption.html) enables automatic encryption of data at rest in Oracle databases. Users can execute SQL queries normally while TDE handles encryption transparently in the background. Encryption keys are stored directly in the database but can be encrypted using **Oracle Key Vault** or directly with **Hardware Security Modules (HSM)** via PKCS#11.

Cosmian provides two deployment modes for Oracle TDE integration:

1. **Oracle Key Vault + HSM Mode**: Uses Oracle Key Vault as an intermediary with HSM as Root-of-Trust
2. **Direct HSM Mode**: Direct communication between Oracle Database and HSM via PKCS#11 interface

## Mode 1: Oracle Key Vault + HSM Integration

**Oracle Key Vault** centralizes encryption key management, offering secure storage and distribution for Oracle databases and enterprise applications. It uses `wallets` to the crucial TDE `master key` which acts as the `Key-Encryption-Key (KEK)` for TDE. The `master key` is stored in a `wallet` that is protected by a password. This `wallet` provides a secure and centralized location for managing encryption keys.

For enhanced security, **Hardware Security Modules (HSM)** can be integrated with Oracle Key Vault to provide additional protection for these `wallets`. This configuration establishes a [Root-of-Trust (RoT)](https://docs.oracle.com/en/database/oracle/key-vault/18.5/okvhm/getting-started-hsm.html#GUID-DADA7E20-82E2-40C9-A63A-4A159EBD5F09): when an HSM is deployed with Oracle Key Vault, the RoT remains in the HSM. The HSM RoT protects the Transparent Data Encryption (TDE) wallet password, which protects the TDE master key, which in turn protects all the encryption keys, certificates, and other security artifacts managed by the Oracle Key Vault server. Note that the HSM in this RoT usage scenario does not store any customer encryption keys. The customer keys are stored and managed directly by the Oracle Key Vault server.

Using HSM as a RoT is intended to mitigate attempts to recover keys from an Oracle Key Vault server which has been started in an unauthorized environment.
Physical loss of an Oracle Key Vault server from a facility is one example of such a scenario.

When an **Oracle Key Vault server** is HSM-enabled, Oracle Key Vault contacts the HSM every five minutes (or whatever you have set the monitoring interval to) to ensure that the Root of Trust key is available and the TDE wallet password can be decrypted.

What Cosmian provides is:

- **a HSM client**: this is a PKCS#11 provider library that make the Oracle Key Vault a HSM client itself. **It enables the Root-of-Trust** by protecting the Oracle Key Vault wallets passwords. That library also provides a KMS client to communicate with the KMS server.
- **a KMS server** that is interrogated by the KMS client. The KMS server can either front a HSM or act as a HSM but deployed in a secure environment.

<div align="center">

```mermaid
graph TD
    subgraph okv_client[Oracle Database]
        okvclient[okvclient.jar]
        dek[**Encryption Keys**
        encrypted by
        TDE Master Key]
    end
    okvclient -- OKV endpoint --> OKV[Oracle Key Vault]
    subgraph OKV[Oracle Key Vault]
        subgraph hsm_client[Cosmian **HSM** client]
            kms_client[Cosmian **KMS** client]
        end
        subgraph wallet[Wallet protected by HSM]
            tde[**TDE Master Key**]
        end
        tde --> hsm_client
    end
    kms_client -- REST API --> KMS[Cosmian **KMS** Server]
    KMS --> HSM[HSM]
    subgraph HSM[HSM]
        kek[**Wallet Encryption Key**]
    end
```

</div>

### Oracle Key Vault Configuration

Before configuring a HSM such as described in [Oracle Key Vault](https://docs.oracle.com/en/database/oracle/key-vault/21.10/okvhm/index.html), some steps are needed:

For Oracle Database OS, the PKCS#11 library is available here: [cosmian-pkcs11](https://package.cosmian.com/kms/5.17.0/deb/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.17.0_amd64.deb).

- Extract the package:

    ```bash
    dpkg-deb -x cosmian-kms-cli-non-fips-static-openssl_5.17.0_amd64.deb extracted/
    ```

- Copy the PKCS#11 provider library from the `extracted/` directory to the Oracle Key Vault server to `/usr/local/okv/hsm/generic/libcosmian_pkcs11.so`
- Copy the configuration of the PKCS#11 provider library to `/usr/local/okv/hsm/generic/ckms.toml`
- Override the OKV generic HSM configuration files:

    - `/usr/local/okv/hsm/generic/okv_hsm_env`

    ```bash
    COSMIAN_PKCS11_LOGGING_LEVEL="trace"
    CKMS_CONF="/usr/local/okv/hsm/generic/ckms.toml"
    COSMIAN_PKCS11_LOGGING_FOLDER="/var/okv/log/hsm"
    ```

    - `/usr/local/okv/hsm/generic/okv_hsm_conf`

    ```bash
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
    ```

- At this point, the symmetric key labeled `OKV 18.1 HSM Root Key` has been created in KMS server by Oracle Key Vault.
- Then you can follow the official [HSM-Enabling in a Standalone Oracle Key Vault Deployment](https://docs.oracle.com/en/database/oracle/key-vault/21.10/okvhm/configuring-hsm-oracle-key-vault1.html#GUID-5645696A-3F19-4CF9-AE79-105569529182).

## Mode 2: Direct HSM Integration

For simplified deployments or environments where Oracle Key Vault is not available, Oracle Database can communicate directly with HSM via PKCS#11. In this mode, the Cosmian PKCS#11 library (`libcosmian_pkcs11.so`) provides direct access to the Cosmian KMS server, which manages the TDE master keys in the HSM.

This approach eliminates Oracle Key Vault from the architecture, reducing complexity while maintaining the security benefits of HSM-protected keys.

<div align="center">

```mermaid
graph TD
    subgraph oracle_db[Oracle Database]
        tde_engine[TDE Engine]
        dek[**Data Encryption Keys**
        encrypted by
        TDE Master Key]
    end
    tde_engine -- PKCS#11 --> pkcs11[Cosmian PKCS#11 Library
    libcosmian_pkcs11.so]
    pkcs11 -- REST API --> KMS[Cosmian **KMS** Server]
    KMS --> HSM[HSM]
    subgraph HSM[HSM]
        master_key[**TDE Master Key**]
    end
```

</div>

### Direct HSM Configuration

#### Linux

1. **Install Cosmian PKCS#11 Library**

    For Oracle Database OS, the PKCS#11 library is available here: [cosmian-pkcs11](https://package.cosmian.com/kms/5.17.0/deb/amd64/non-fips/static/cosmian-kms-cli-non-fips-static-openssl_5.17.0_amd64.deb).

    ```bash
    # Extract library from Linux package.
    dpkg-deb -x cosmian-kms-cli-non-fips-static-openssl_5.17.0_amd64.deb extracted/

    # Copy to Oracle's HSM directory
    mkdir -p /opt/oracle/extapi/64/hsm/Cosmian/
    cp libcosmian_pkcs11.so /opt/oracle/extapi/64/hsm/Cosmian/
    chown oracle:oinstall /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so
    ```

2. **Configure Cosmian PKCS#11 Library**

    Create the configuration file `/home/oracle/.cosmian/ckms.toml`:

    ```toml
    [http_config]
    server_url = "http://kms:9998"
    ```

    Set proper ownership:

    ```bash
    mkdir -p /home/oracle/.cosmian/
    chown oracle:oinstall /home/oracle/.cosmian/ckms.toml
    ```

3. **Prepare Oracle Directory Structure**

    ```bash
    # Create keystore directories
    mkdir -p /etc/ORACLE/KEYSTORES/FREE
    chown -R oracle:oinstall /etc/ORACLE/KEYSTORES/FREE

    # Setup logging
    chown -R oracle:oinstall /var/log
    ```

4. **Configure Oracle Database for PKCS#11**

    Set up TDE to use the HSM via PKCS#11:

    ```sql
    -- Set WALLET_ROOT to point to the PKCS#11 library
    ALTER SYSTEM SET WALLET_ROOT='/opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so' SCOPE=SPFILE;
    SHUTDOWN IMMEDIATE;
    STARTUP;

    -- Configure TDE to use HSM keystore
    ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH SID='*';
    SHUTDOWN IMMEDIATE;
    STARTUP;
    ```

5. **Create and Configure HSM Keystore**

    ```sql
    -- Open the HSM keystore
    ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;

    -- Create TDE master key in HSM with backup
    ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass WITH BACKUP;
    ```

6. **Verify Configuration**

    ```sql
    -- Check keystore status
    COLUMN WRL_PARAMETER FORMAT A50;
    SET LINES 200;
    SELECT WRL_TYPE, WRL_PARAMETER, WALLET_TYPE, STATUS FROM V$ENCRYPTION_WALLET;

    -- Verify keys are stored in HSM
    COLUMN NAME FORMAT A40;
    SET LINES 400;
    SELECT KEY_ID, KEYSTORE_TYPE, CREATOR_DBNAME, ACTIVATION_TIME, KEY_USE, ORIGIN
    FROM V$ENCRYPTION_KEYS;
    ```

7. **Optional: Create Test Encrypted Table**

    ```sql
    -- Create a table with encrypted columns to verify TDE is working
    CREATE TABLE test_tde (something CHAR(32) ENCRYPT);
    ```

#### Windows

Oracle 26ai Free for Windows has two unfixed HSM/PKCS#11 issues that require workarounds
when configuring TDE directly (without Oracle Key Vault):

1. **`skgdllDiscover` finds nothing on Windows.** The auto-discovery function only scans the
   hard-coded Linux path `/opt/oracle/extapi/64/pkcs11/`. No equivalent Windows path is
   scanned, so Oracle cannot locate any PKCS#11 DLL automatically.

2. **`pkcs11_library_location` rejects Windows paths.** The `ALTER SYSTEM SET` validator checks
   that the supplied path starts with `/opt/oracle/extapi/64/pkcs11/`. Any Windows path
   (`C:\...`) is rejected with `ORA-46707` / `ORA-32017`.

The steps below apply the required workarounds.

1. **Install Cosmian PKCS#11 Library**

    Download `cosmian_pkcs11.dll` from the [release packages](https://package.cosmian.com/kms/5.16.2/).

    The DLL **must** be placed at the drive-relative Linux path so that Oracle's
    `LoadLibrary` call resolves it. On Windows a path starting with `/` is treated as
    drive-relative (`/opt/...` → `C:\opt\...` on a system where `C:` is the current drive).

    ```powershell
    # Create the required directory structure
    New-Item -ItemType Directory -Force -Path 'C:\opt\oracle\extapi\64\pkcs11'

    # Install the DLL (both locations are used by Oracle)
    Copy-Item cosmian_pkcs11.dll 'C:\opt\oracle\extapi\64\pkcs11\cosmian_pkcs11.dll'

    New-Item -ItemType Directory -Force -Path "$env:ORACLE_HOME\extapi\64\hsm\Cosmian"
    Copy-Item cosmian_pkcs11.dll "$env:ORACLE_HOME\extapi\64\hsm\Cosmian\cosmian_pkcs11.dll"
    ```

2. **Configure Cosmian PKCS#11 Library**

    Place `ckms.toml` alongside the DLL so it is found regardless of which Windows user
    account Oracle's service runs under:

    ```powershell
    @'
    [http_config]
    server_url = "http://kms:9998"
    '@ | Set-Content -Path 'C:\opt\oracle\extapi\64\pkcs11\ckms.toml' -Encoding UTF8
    ```

    > **Note:** The PKCS#11 library searches for `ckms.toml` in the following order:
    > `CKMS_CONF` environment variable → directory containing the DLL →
    > `%USERPROFILE%\.cosmian\ckms.toml`.

3. **Prepare Oracle Wallet Directory**

    ```powershell
    # Create the wallet directory (adjust path to match your ORACLE_BASE)
    New-Item -ItemType Directory -Force -Path 'C:\app\oracle\admin\FREE\wallet'
    ```

4. **Configure Oracle Database for PKCS#11**

    Because `ALTER SYSTEM SET pkcs11_library_location` rejects Windows paths, set all three
    TDE parameters via a plain PFILE and restart with `STARTUP PFILE=`:

    ```sql
    -- Step 1: capture current in-memory parameters to a text PFILE
    CREATE PFILE='C:\app\oracle\dbhomeFree\database\initFREE_pkcs11.ora' FROM MEMORY;
    SHUTDOWN IMMEDIATE;
    ```

    Edit the generated `initFREE_pkcs11.ora` with a text editor and add (or update) the
    following three lines — using forward slashes throughout:

    ```ini
    *.wallet_root='C:/app/oracle/admin/FREE/wallet'
    *.tde_configuration='KEYSTORE_CONFIGURATION=HSM'
    *.pkcs11_library_location='/opt/oracle/extapi/64/pkcs11/cosmian_pkcs11.dll'
    ```

    Then restart and persist:

    ```sql
    -- Step 2: start the instance using the edited PFILE
    STARTUP PFILE='C:\app\oracle\dbhomeFree\database\initFREE_pkcs11.ora';

    -- Step 3: write the active configuration back to SPFILE
    CREATE SPFILE FROM MEMORY;
    ```

5. **Create and Configure HSM Keystore**

    ```sql
    -- Open the HSM keystore (loads cosmian_pkcs11.dll)
    ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;

    -- Create TDE master key in HSM
    ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass;
    ```

6. **Verify Configuration**

    ```sql
    -- Check keystore status
    COLUMN WRL_PARAMETER FORMAT A50;
    SET LINES 200;
    SELECT WRL_TYPE, WRL_PARAMETER, WALLET_TYPE, STATUS FROM V$ENCRYPTION_WALLET;

    -- Verify keys are stored in HSM
    SET LINES 400;
    SELECT KEY_ID, KEYSTORE_TYPE, CREATOR_DBNAME, ACTIVATION_TIME, KEY_USE, ORIGIN
    FROM V$ENCRYPTION_KEYS;
    ```

7. **Optional: Create Test Encrypted Table**

    ```sql
    CREATE TABLE test_tde (something CHAR(32) ENCRYPT);
    ```

**Troubleshooting:**

- PKCS#11 log (service user): `C:\WINDOWS\ServiceProfiles\OracleService<SID>\.cosmian\cosmian-pkcs11.log`
- PKCS#11 log (current user): `%USERPROFILE%\.cosmian\cosmian-pkcs11.log`
- Oracle alert log: `%ORACLE_BASE%\diag\rdbms\free\<SID>\trace\alert_<SID>.log`
- Oracle trace dir: `%ORACLE_BASE%\diag\rdbms\free\<SID>\trace\`

### HSM Identity and Authentication

The `hsm_identity_pass` used in the SQL commands represents the PKCS#11 PIN that authenticates
access to the HSM. This should be configured in your Cosmian KMS setup and corresponds to the
authentication mechanism for accessing keys stored in the HSM.

## Automated Testing

Automated integration tests verify that `cosmian_pkcs11.dll` correctly provides TDE support for
an Oracle Database installed directly on Windows (no Docker required for Oracle itself).

### Windows (PowerShell)

**Prerequisites:**

- **Oracle Database 23ai/26ai Free** installed on Windows — [download here](https://www.oracle.com/database/free/get-started/)
- `ORACLE_HOME` and `ORACLE_SID` environment variables set
- `cosmian_pkcs11.dll` built: `cargo build --release -p cosmian_pkcs11 --features non-fips`
- `cosmian_kms.exe` built: `cargo build --release -p cosmian_kms_server --features non-fips`
  (or a KMS server already running at `http://localhost:9998`)
- No administrator privileges required

```powershell
# Set Oracle environment (adjust paths for your installation)
$env:ORACLE_HOME = 'C:\app\rndde\product\26ai\dbhomeFree'
$env:ORACLE_SID  = 'FREE'

# Optionally point to a pre-built KMS binary (defaults to target\release\cosmian_kms.exe)
# $env:KMS_BINARY = 'C:\path\to\cosmian_kms.exe'

# Run the full test
& .\.github\scripts\oracle\test_oracle_tde.ps1
```

The orchestration script `test_oracle_tde.ps1`:

1. Validates prerequisites (Oracle installation, services, DLL, sqlplus)
2. Starts a KMS server process (`target\release\cosmian_kms.exe`) on port 9998 (or reuses an already-running KMS)
3. Calls `set_hsm.ps1` which:
     - Copies `cosmian_pkcs11.dll` to `C:\opt\oracle\extapi\64\pkcs11\` (see porting notes above)
     - Writes `ckms.toml` to the Oracle service user's profile via Oracle's `UTL_FILE` package
     - Configures `WALLET_ROOT`, `TDE_CONFIGURATION=KEYSTORE_CONFIGURATION=HSM`, and
       `pkcs11_library_location` via a plain PFILE and `STARTUP PFILE=`
     - Executes the TDE SQL configuration (HSM keystore open, master key creation)
     - Verifies the keystore and encryption key status
4. Stops the KMS server process
