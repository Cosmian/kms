## creating keys on amazon kms

https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html

"importing keys link"

https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html


requirements for key material :
https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html#importing-keys-material-requirements


        // TODO: export a file path, if specified
        // test key : e8518bca-e1d0-4519-a915-d80da8e8f38a

        // aws kms get-parameters-for-import \
        //     --key-id e8518bca-e1d0-4519-a915-d80da8e8f38a \
        //     --wrapping-algorithm RSA_AES_KEY_WRAP_SHA_256 \
        //     --wrapping-key-spec RSA_3072

        // results :
        //         {
        //     "KeyId": "arn:aws:kms:eu-west-3:447182645454:key/e8518bca-e1d0-4519-a915-d80da8e8f38a",
        //     "ImportToken": "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",
        //     "PublicKey": "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA020eGsIGUYdaNMP2Ty6b/YmpL+8eMopdaXg5I+x3TMzTT7QV7d3mfe5E/wgNRGDjYRdA74S8WwdwcSpfFpppVnDKX1dKIXS5woYa7hx/YAdY/3kv0VJKGKxt8Tf1Ajpekot0uVLbHOwR9DF8aBiDCtrZR7x94H1GPSXZ3VLZimBldcJ+Tszt4wITmwBjJxkPXJzkVa8zg2tnTKm/M5TwMDe5Q3DUOYKVgMKdcsJPX43q72radD1VdMazxzps+7wDT64AD5FZoXHcJH4ZytIMySbhlwsQntT5lNeyulg7kbFAFuSzGM7SipDwvVPzgxrDY1aw/VpJ9vuMqtO/V7TWwL8NSuoh/5bsVXCUFdSXHmz9oh/hj8zIPDLjHc/Z1guGanl+4/ZQbs4M4SgqN1KT/aayX+oDsvj6Q+GVzhCIpq7XQJekcOcRjCyYocCLfYOTv2N/vFMGxcKZZLM4LmCGMFsDEO1GaISPsv6mVUgewWMeBmzTBbyB6atA07Li9JMjAgMBAAE=",
        //     "ParametersValidTo": "2026-01-15T16:58:27.315000+01:00"
        // }

        // aws kms import-key-material --key-id e8518bca-e1d0-4519-a915-d80da8e8f38a \
        //     --encrypted-key-material fileb://EncryptedKeyMaterial.bin \
        //     --import-token fileb://ImportToken.bin
