# Kubernetes HSM documentation

## Documentation

- Helm chart guide: the HSM section is now generic (Thales Luna, Trustway Proteccio, Trustway
  Crypt2pay) and lists, per model, the `--hsm-model` value, the library-path environment variable
  and the vendor configuration.
- Add "Kubernetes (Helm chart)" guides to the Proteccio and Crypt2pay pages: official KMS image,
  vendor PKCS#11 library copied by an init container, configuration and credentials from
  Kubernetes Secrets. Crypt2pay runs as a single replica with a PersistentVolumeClaim for its
  configuration directory. Tested on minikube up to library load and `C_Initialize` (Crypt2pay);
  not tested against a live HSM.
