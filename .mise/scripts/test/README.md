# Test scripts

Helper scripts, fixtures and tools called by the MISE test tasks under `.mise/tasks/test/`.
Each subfolder mirrors one task group, so a task `.mise/tasks/test/<group>/<leaf>` calls scripts in `.mise/scripts/test/<group>/`.
The task documentation (scenarios, diagrams) lives in [`.mise/tasks/test/README.md`](../../tasks/test/README.md).

## Layout

|Folder|Task group|Contents|
|---|---|---|
|`obs/`|`test:obs`|Audit log, CEF, SIEM (syslog, Filebeat, Fluent Bit) and monitoring scenarios; audit schema fixtures (`fixtures/`); `requirements-audit-compat.*`, `requirements-cef.*`|
|`cloud/`|`test:cloud`|Azure EKM, AWS XKS (local and remote) and secret-backend (AWS, Azure, Vault, Cosmian KMS) scenarios|
|`hsm/`|`test:hsm`|PKCS#11 IV shim, GCM IV probe, Crypt2pay inotify shim, Nix helper re-entry test|
|`pkcs11/`|`test:pkcs11`|PKCS#11 conformance and check tools, GnuPG, LUKS, OpenSSH, VeraCrypt scenarios; `requirements-pkcs11-check.*`|
|`interop/`|`test:interop`|Database TDE (ASE, Db2, EDB, IRIS), JOSE, KMIP Go, PyKMIP, SSH certificate, secret-rotation scenarios; `openbao/` scripts; `requirements-jose.*`|
|`pki/`|`test:pki`|EST and SCEP interoperability scenarios, SCEP capture proxy, `certificatePolicies/` OpenSSL configs|
|`spire/`|`test:spire`|SPIRE PKI grant helper|
|`ui/`|`test:ui`|Web UI Playwright harnesses (standard, Auth Verifier, OIDC, SAML) and the `saml_sso/` Keycloak stack|
|`pkg/`|`test:pkg`|Docker image smoke, scan and Oracle tests, Alpine musl test, load-balancer shutdown test, CBOM and SBOM tests|
|`k8s/`|`test:k8s`|Kubernetes HSM image checks|
|`db/`|`test:db`, `test:upgrade-db`|Database upgrade gate, seed/verify tool and its KMIP JSON client, migration fixture generator|
|`vectors/`|`dev:vectors-*`|Test vector maintenance tools (rekey vector generator, unused JSON finder)|

## Rules

1. A script lives in the folder of the `.mise/tasks/test/<group>/` task that calls it (`vectors/` for the `dev:vectors-*` tools).
2. Helpers, fixtures, configs and a `requirements-*.in`/`.txt` pair sit next to the scripts that use them.
3. A shell helper used by two or more groups goes in `.mise/lib/`; any other shared file goes in `.mise/scripts/test/common/` (created when first needed).
4. A new `requirements-*.txt` outside `interop/`, `obs/` and `pkcs11/` needs its folder added to the `pip` directories of `.github/dependabot.yml` and its path added to the `python-dependency-audit` list of `.github/workflows/supply-chain.yml`.
5. Moving or adding a script means updating `.github/ci-paths.toml`; check with `mise run dev:ci-changes --self-test`.
6. Scripts locate sibling files with `${SCRIPT_DIR}/...`; a script one level deeper than its folder (`openbao/`, `saml_sso/`) needs one more `../`.
