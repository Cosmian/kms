#! /bin/bash

# Tested on CentOS 7 and CentOS 8
# Check the latest version at https://curl.se/download/
VERSION=8.4.0

yum update -y
yum install wget gcc openssl-devel make -y
wget https://curl.haxx.se/download/curl-${VERSION}.tar.gz
tar -xzvf curl-${VERSION}.tar.gz
rm -f curl-${VERSION}.tar.gz
pushd curl-${VERSION}
./configure --prefix=/usr/local --with-ssl
make
make install
ldconfig
popd
rm -rf curl-${VERSION}
