#!/bin/bash

# Create a self-signed cert
openssl req -x509 -nodes -new -sha256 -days 365 -keyout /tmp/test.key -out /tmp/test.crt

# Generate a PKCS12 file 
openssl pkcs12 -export -out /tmp/test.p12 -inkey /tmp/test.key -in /tmp/test.crt -password pass:
