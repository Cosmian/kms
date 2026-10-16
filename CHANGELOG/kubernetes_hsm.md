# Kubernetes HSM documentation

## Features

- Helm chart: new `command` value replaces the image entrypoint, so the FIPS image can start the
  KMS with `OPENSSL_CONF` unset for HSM libraries that embed their own OpenSSL (Trustway
  Proteccio).

## Documentation

- Helm chart guide: the HSM section is now generic (Thales Luna, Trustway Proteccio, Trustway
  Crypt2pay) and lists, per model, the `--hsm-model` value, the library-path environment variable
  and the vendor configuration.
- Add "Kubernetes (Helm chart)" guides to the Proteccio and Crypt2pay pages: official KMS image,
  vendor PKCS#11 library copied by an init container, configuration and credentials from
  Kubernetes Secrets. Crypt2pay runs as a single replica with a PersistentVolumeClaim for its
  configuration directory. With the FIPS image, Proteccio needs
  `command: [env, -u, OPENSSL_CONF, cosmian_kms]`: `libnethsm.so` embeds OpenSSL and fails
  `C_Initialize` under the image's FIPS `OPENSSL_CONF`. Validated on minikube against live
  Proteccio and Crypt2pay HSMs, FIPS and non-FIPS images (key creation, AES-GCM round trip;
  Crypt2pay key reuse after a pod restart).

## Testing

- New `test:k8s:hsm --model proteccio|crypt2pay --variant fips|non-fips`: builds the client image
  and installs the chart with the Dockerfile, Helm values and PVC extracted from the HSM guides,
  then runs an HSM key AES-GCM round trip through the KMS pod (Crypt2pay: also after a pod
  restart). Runs in the `hsm-upstream` CI job after the HSM loader tests, in the same per-HSM
  concurrency group.
- `test:helm`: renders the new `command` value and checks it is absent by default.
