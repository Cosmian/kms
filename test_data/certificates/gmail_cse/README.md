# test_private_key and test_public_key

`cosmian` is used to generate a RSA key pair where the private key is wrapped by the symmetric key `google_cse`. All the chain is saved in a PKCS7 file.

- `test_private_key` is a RSA wrapped private key.
- `test_public_key` is extracted from the PKCS7 file:
  - openssl pkcs7 -in test_public_key.pkcs7 -print_certs
  - openssl x509 -pubkey -noout -in test_public_key.crt > test_public_key.pub
  - openssl rsa -in test_public_key -pubin -RSAPublicKey_out -out test_public_key

# int.p12

Was obtained with:

```bash
openssl pkcs12 -export -out int.p12 -inkey intermediate.key -in intermediate.pem -certfile ca.pem
```
