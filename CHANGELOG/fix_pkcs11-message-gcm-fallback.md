## Bug Fixes

### HSM
- Retry classic PKCS#11 AES-GCM when message-based encryption fails, before rejecting an HSM KEK at startup.
