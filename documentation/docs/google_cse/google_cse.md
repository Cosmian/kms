
The Cosmian Key Management Server is compatible with Google Workspace client-side encryption. Using this feature, your users can encrypt files and documents, in their browsers, before sending them to Google servers. The ephemeral encryption keys are protected by "key wrapping keys", stored in the KMS and unavailable to Google. Only users that have the right to unwrap the ephemeral encryption keys inside the KMS, can decrypt the files. An overview is provided in Google's [About client-side encryption page](https://support.google.com/a/answer/10741897?hl=en).

To enable client-side encryption (CSE) in Google Workspace, connect as an admin to the admin console and go to the [Google Workspace client-side encryption page](https://admin.google.com/ac/cse?hl=en).

Google has extensive documentation on how to enable CSE in Google Workspace. The [Use client-side encryption for users' data page](https://support.google.com/a/topic/10742486?hl=en) is a good starting point. It may be slightly overwhelming, and this documentation adds some details to help you get started.


### 1. Choosing and configuring the Identity Provider

The first thing that will need to be done is to configure the Identity Provider. This is the service that the Cosmian Key Management Server will use to authenticate users before they can encrypt files or access encrypted files.

The identity provider (IdP) is either a third party IdP or Google identity. Using Google Identity is not recommended since Google as the authority could issue tokens to impersonate users and recover their keys. However, since configuring an Identity Provider is hard and Google Identity is the easiest to configure, we will use it in this tutorial.

![Enable CSE](./images/url-of-well-known-file.png)

The initial page should look like this. What matters here is the link shown at the tip of the red-arrow. This is the URL at which Google client-side encryption expects the well-known file to be served.

To configure a well-known file, you need to:

1. Set up a server that serves the file at the URL shown in the image above: [instructions](./configuring-the-well-known-server.md)

2. Create the well-known file with the proper content: instructions are provided in the [Configuring the well-known file](./configuring-the-well-known-file.md) section.

Once this is complete, the screen on refresh should turn to this:

![IdP configuration is successful](./images/idp-configuration-is-successful.png)

### 2. Configuring the Key Management Server

The KMS must be behind a valid TLS certificate when started.
Assuming it is running at `https://cse.example.com`, you should add the External Key Service with KACLS URL `https://cse.example.com/google_cse` in the Client-Side Encryption page of the Google Workspace admin console.

To enable Client Side Encryption on the Cosmian KMS server, it must be started with the `--google-cse-kacls-url` option. This option is the URL at which the KMS will serve the Key Access Control Lists (KACLs) for the Google CSE service. The KACLs are used by the Google CSE service to determine which users have access to which keys. The KACLs are served by the KMS at the URL `https://cse.example.com/google_cse` in the example above.

The Key Management Server must be configured to use the same Identity Provider as the one configured in the previous step. When using Google Identity, the server should be configured with the following options set in the [corresponding Google documentation](https://developers.google.com/workspace/cse/guides/configure-service?hl=en)


Assuming Google is the Identity Provider, the KMS should be started with the following options:

```sh
--jwt-issuer-uri=https://accounts.google.com
--jwks-uri=https://www.googleapis.com/oauth2/v3/certs
--google-cse-kacls-url=https://cse.example.com/google_cse
```
For example, if you are using the docker image, you can run the following command:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.6.0 \
    --jwt-issuer-uri=https://accounts.google.com \
    --jwks-uri=https://www.googleapis.com/oauth2/v3/certs \
    --google-cse-kacls-url=https://cse.example.com/google_cse
```



![external keys service](./images/configure_external_key_service.png)

Then test the connection; it should show:

![external key service ok](./images/external_key_service_ok.png)

Finalize the configuration. The Client Side Encryption page should now show the service to be active and you will now have to decide whether to assign this service to all users or to a subset of users.

![Cosmian KMS active](./images/cosmian_kms_active.png)

