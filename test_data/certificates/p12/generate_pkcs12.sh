#! /bin/bash

rm output.p12

openssl pkcs12 -export -inkey cert.key -CAfile subca.pem -passout pass:secret -out output.p12 -in cert.pem -certfile subca.pem
