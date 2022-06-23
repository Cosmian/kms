#!/bin/sh

mkdir -p scripts
# MR enclave directory
mkdir -p private_data/
# Plain text directory
mkdir -p public_data/
# MR signer directory
mkdir -p shared_data/

rm -rf private_data/*
