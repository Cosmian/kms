## Features

### Deployment

- Add Helm chart (`charts/cosmian-kms/`) for deploying Cosmian KMS on Kubernetes: `Deployment`, `Service`, optional `Ingress`, `PersistentVolumeClaim` (sqlite backend), `Secret` (or `existingSecret` reference) for database credentials, `HorizontalPodAutoscaler`, `PodDisruptionBudget`, and `NetworkPolicy` templates, configurable via `values.yaml` ([#886](https://github.com/Cosmian/kms/issues/886))
