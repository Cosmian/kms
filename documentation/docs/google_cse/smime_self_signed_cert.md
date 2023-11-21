
### Root certificate authority

To generate a self-signed root CA with OpenSSL, you can use the following steps:

1. Create a new private key for the CA:

```
openssl genrsa -out ca.key 4096
```

This will generate a 4096-bit RSA private key, which is a good size for most applications.

2. Generate a self-signed certificate for the CA:

```
openssl req -x509 -new -days 3650 -key ca.key -out ca.crt
```

This will generate a self-signed certificate for the CA, which will be valid for 3650 days (10 years).


### Intermediate certificate


1. Generate a private key for the intermediate certificate:

```
openssl genrsa -out int.key 4096
```

2. Generate a CSR for the intermediate certificate:

```
openssl req -new -key int.key -out int.csr
```

3. Sign the intermediate certificate with the root CA certificate:

```
openssl x509 -req -in int.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out int.crt -days 3650
```

4. Verify the intermediate certificate:

```
openssl verify -CAfile ca.crt int.crt
```

### S/MIME user certificate

To sign a user certificate for the blue user with the intermediate certificate, you can use the following steps:

1. Generate a private key for the user certificate:

```
openssl genrsa -out blue.key 4096
```

2. Generate a CSR for the user certificate:

```
openssl req -new -key blue.key -out blue.csr
```

3. Sign the user certificate with the intermediate certificate:

```
openssl x509 -req -in blue.csr -CA int.crt -CAkey int.key -CAcreateserial -out blue.crt -days 3650
```




