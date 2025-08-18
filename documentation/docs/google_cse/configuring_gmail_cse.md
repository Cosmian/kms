Follow the [Google documentation](https://support.google.com/a/answer/13069736?hl=en&ref_topic=10742486) to enable S/MIME for client-side encryption in your organization and create a service account to interact with the Gmail API.

## Configure cosmian client (CLI)

The `cosmian` command line interface (CLI) simplifies the setup of S/MIME keys and certificates for users.

After completing the setup, update your [Cosmian CLI](../../cosmian_cli/configuration.md#example-with-smime-gmail-service-account-configuration-for-kms-server) with the necessary information for the service account you created for the Gmail API.

## Import certificates chain to Cosmian KMS

According to [Google's requirements](https://support.google.com/a/answer/7300887#zippy=%2Croot-ca%2Cintermediate-ca-certificates-other-than-from-issuing-intermediate-ca%2Cintermediate-ca-certificate-that-issues-the-end-entity%2Cend-entity-certificate)
and [configuration guidelines](https://support.google.com/a/answer/13297070?hl=en#guidelines),
upload the certificate chain to Cosmian KMS. This certificate chain will be used to generate user certificates.

More details about S/MIME workflow can be found [here](../pki/smime.md).

```sh
cosmian kms certificates import -f pkcs12 issuer_ca_certificate.p12 -p \
    PASSWORD issuer_ca_certificate
```

If multiple administrators will be generating key-pairs for users, ensure that each administrator has the appropriate access rights to the imported certificate chain elements:

- the issuer certificate ID (given when importing the Certificate Authority)
- the issuer private key ID
- the issuer public key ID

In order to get the issuer private ID and issuer public key ID, run the following command:

```sh
cosmian kms attributes get -i issuer_ca_certificate
```

You'll use the ID of the issuer's private key (imported from the certificate chain) to later sign users' public keys and create their certificates.

## Create user key-pair

Gmail uses `key-pairs` (an RSA private key wrapped with its associated certificate) and `identities` (the ID of an uploaded key-pair, associated with a user) to sign and encrypt emails using S/MIME.
These objects are uploaded to Google via the Gmail API.

You can create a key-pair (RSA private key and user certificate chain) and upload it to the Gmail API using the following command:

```sh
cosmian kms google key-pairs create --cse-key-id CSE_KEY_ID \
    --subject-name "C=FR, ST=IdF, L=Paris, O=ORGANIZATION, OU=DEPARTMENT, CN=user@organization.com, emailAddress=user@organization.com" \
    -i ISSUER_PRIVATE_KEY_ID --leaf-certificate-extensions user.ext user@your_organization.com
```

If you already have an existing RSA key-pair for the user, you can specify it in the command.

### Using an existing leaf certificate

Instead of generating a new leaf certificate, you can use an existing one by specifying either:

- `--leaf-certificate-id CERT_ID`: Use a certificate already stored in KMS
- `--leaf-certificate-pkcs12-file /path/to/cert.p12`: Use a local certificate file

When using an existing leaf certificate, the `--leaf-certificate-extensions` parameter is not required.

!!! warning "X509 flags extensions"
    Remember that existing X509 certificate must comply the Google CSE requirements. X509 flags are expected by Google Gmail CSE for [S/MIME](https://support.google.com/a/answer/7300887?fl=1&sjid=2093401421194266294-NA).

Example with existing certificate:

```sh
cosmian kms google key-pairs create --cse-key-id CSE_KEY_ID \
    --subject-name "C=FR, ST=IdF, L=Paris, O=ORGANIZATION, OU=DEPARTMENT, CN=user@organization.com, emailAddress=user@organization.com" \
    -i ISSUER_PRIVATE_KEY_ID --leaf-certificate-pkcs12-file /path/to/cert.p12 --leaf-certificate-pkcs12-password user@your_organization.com
```

Once created, the ID of the key-pair will be displayed.

Note: It may take up to 24 hours for Google to propagate the Client-Side Encryption (CSE) activation for a user within the Gmail API, allowing you to upload the S/MIME elements.

## Insert user identity

After creating the key-pair, you must associate it with the user’s identity. To do so, run the following command:

```sh
cosmian kms google identities insert \
    --user-id user@your_organization.com CREATED_KEYPAIR_ID
```

You can manage key-pairs (get, list, enable, disable, obliterate) and identities (get, list, delete, patch) using the other available commands in the `cosmian` [commands documentation](../../cosmian_cli/cli/main_commands.md).

Note: It may take a few hours for Google to propagate the uploaded elements, after which users can begin using S/MIME for secure email exchanges.

## User experience

To send a client-side encrypted email within your organization, a user needs to turn on the additional encryption option in the message window (lock -> Turn on additional encryption).
Only users with CSE activated can encrypt and decrypt encrypted emails.

To send a client-side encrypted email outside your organization, a user needs to send a message to the recipient with their digital signature, without CSE turned on.
The recipient then needs to reply to the message with their digital signature.
Then the sender can choose to add CSE to email sent to the external recipient.

Encrypted emails will be automatically decrypted from Gmail interface.

Learn more about [CSE user experience](https://support.google.com/a/answer/14311764?hl=en&ref_topic=10742486)
