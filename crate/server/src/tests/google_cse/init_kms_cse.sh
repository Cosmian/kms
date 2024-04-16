#!/bin/sh

PWD=$(pwd)

cp ~/.cosmian/kms.json.cse.blue ~/.cosmian/kms.json

./ckms login
./ckms sym keys import -t google_cse "$PWD/documentation/docs/google_cse/17fd53a2-a753-4ec4-800b-ccc68bc70480.demo.key.json" google_cse

./ckms access-rights grant blue@cosmian.com google_cse create destroy get encrypt decrypt
./ckms access-rights grant green@cosmian.com google_cse create destroy get encrypt decrypt
./ckms access-rights grant celia@cosmian.com google_cse create destroy get encrypt decrypt
./ckms access-rights grant celia.corsin@cosmian.com google_cse create destroy get encrypt decrypt
./ckms access-rights grant bruno@cosmian.com google_cse create destroy get encrypt decrypt
./ckms access-rights grant bruno.grieder@cosmian.com google_cse create destroy get encrypt decrypt

rm -f sym_key_cse.json
./ckms sym keys export -t google_cse -f json-ttlv sym_key_cse.json
cat sym_key_cse.json
rm -f sym_key_cse.json
