# feat/implement_fpe

## Security

- Fix `/tokenize` scope `EnsureAuth::new` to check all auth methods (`use_jwt_auth || use_cert_auth || use_api_token_auth`) — previously only checked `use_cert_auth` ([#907](https://github.com/Cosmian/kms/pull/907)).

## Bug Fixes

- Replace Python-based dynamic port allocation in UI E2E test script with Node.js to avoid `python3: command not found` on CI runners ([#907](https://github.com/Cosmian/kms/pull/907)).

## Documentation

- Add tokenize REST endpoints to OpenAPI specification (`crate/server/documentation/openapi.yaml`) ([#907](https://github.com/Cosmian/kms/pull/907)).
- Strip internal duplication from `.github/copilot-instructions.md` and update UI actions structure ([#907](https://github.com/Cosmian/kms/pull/907)).
- Add data anonymization/tokenization to README features list ([#907](https://github.com/Cosmian/kms/pull/907)).
