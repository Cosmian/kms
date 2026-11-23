# KMIP Operations & Test Configurations Reference

## Contents

- [KMIP operation dispatch](#kmip-operation-dispatch)
- [Test server configurations](#test-server-configurations)

---

## KMIP operation dispatch

Follow [dispatch.rs](../../../../crate/server/src/core/operations/dispatch.rs) to the handler and check [message.rs](../../../../crate/server/src/core/operations/message.rs) for batch handling. An unknown operation can surface as HTTP 404 for a standalone request or as `Operation_Not_Supported` in a KMIP batch result; check the response at the right layer.

---

## Test server configurations

Read the complete fixtures in `test_data/configs/server/` at the repo's pinned `test_data` revision (initialize with `git submodule update --init test_data` if needed). Choose one that matches the authentication, TLS, and backend needed by the test. Use [the fixture rules](../../../instructions/test-configs.instructions.md) rather than creating a partial config.
