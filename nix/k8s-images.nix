# Docker image derivations for the Cosmian KMS Kubernetes in-cluster components.
#
# These produce minimal, distroless-like images containing only:
#   - the binary
#   - CA certificates (for TLS connections to the KMS server)
#   - timezone data
#   - minimal /etc/passwd and /etc/group
#
# Unlike the KMS server image, no FIPS variant is needed: neither the operator
# nor the CSI provider performs cryptographic operations; they are thin HTTP/gRPC
# clients that delegate crypto to the KMS server.
{
  pkgs ? import <nixpkgs> { },
  # Binary derivations produced by k8s-binaries.nix
  operatorDrv,
  csiProviderDrv,
  version,
}:

let
  etcPasswd = pkgs.writeTextFile {
    name = "passwd";
    text = ''
      root:x:0:0:root:/root:/bin/sh
      nobody:x:65534:65534:nobody:/nonexistent:/bin/false
    '';
    destination = "/etc/passwd";
  };

  etcGroup = pkgs.writeTextFile {
    name = "group";
    text = ''
      root:x:0:
      nobody:x:65534:
    '';
    destination = "/etc/group";
  };

  # ── Operator image ─────────────────────────────────────────────────────────

  operatorImage = pkgs.dockerTools.buildLayeredImage {
    name = "cosmian-kms-operator";
    tag = version;
    created = "1970-01-01T00:00:01Z";

    contents = [
      operatorDrv
      pkgs.cacert
      pkgs.tzdata
      etcPasswd
      etcGroup
    ];

    config = {
      Entrypoint = [ "/bin/cosmian-kms-operator" ];
      User = "65534:65534"; # nobody
      Env = [
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "RUST_LOG=info"
      ];
      Labels = {
        "org.opencontainers.image.title" = "Cosmian KMS Operator";
        "org.opencontainers.image.description" = "Kubernetes Operator for KMSSecret CRDs";
        "org.opencontainers.image.version" = version;
        "org.opencontainers.image.vendor" = "Cosmian";
        "org.opencontainers.image.url" = "https://docs.cosmian.com/integrations/kubernetes/operator/";
        "org.opencontainers.image.source" = "https://github.com/Cosmian/kms";
      };
    };
  };

  # ── CSI provider image ─────────────────────────────────────────────────────

  csiProviderImage = pkgs.dockerTools.buildLayeredImage {
    name = "cosmian-kms-csi-provider";
    tag = version;
    created = "1970-01-01T00:00:01Z";

    contents = [
      csiProviderDrv
      pkgs.cacert
      pkgs.tzdata
      etcPasswd
      etcGroup
    ];

    config = {
      Entrypoint = [ "/bin/cosmian-kms-csi-provider" ];
      User = "65534:65534"; # nobody
      Env = [
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "RUST_LOG=info"
      ];
      Labels = {
        "org.opencontainers.image.title" = "Cosmian KMS CSI Provider";
        "org.opencontainers.image.description" = "Kubernetes Secrets Store CSI Driver Provider";
        "org.opencontainers.image.version" = version;
        "org.opencontainers.image.vendor" = "Cosmian";
        "org.opencontainers.image.url" = "https://docs.cosmian.com/integrations/kubernetes/csi-provider/";
        "org.opencontainers.image.source" = "https://github.com/Cosmian/kms";
      };
    };
  };

in
{
  inherit operatorImage csiProviderImage;
}
