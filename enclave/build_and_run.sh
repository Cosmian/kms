#!/bin/bash

make SGX=1 DEBUG=1 && gramine-sgx ./kms
