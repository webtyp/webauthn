# Pseudo-Random Function (PRF) Extension in WebAuthn

The PRF (`hmac-secret`) extension is a WebAuthn extension built on CTAP2. It enables authenticators to output deterministic secret key material derived from a user's biometric or PIN verification and a caller-supplied salt.

## Encryption Use Case

Unlike standard WebAuthn assertion signatures (which change on every use due to random challenges and incrementing sign counters), the PRF extension returns **32 deterministic bytes** for a given constant salt.

`webtyp/webauthn` exposes this via `GetOptions.PRFSalt`. Higher-level modules (such as `webtyp/keyring`) use these 32 bytes as a Key Encryption Key (KEK) to wrap locally encrypted secrets.

## Current Platform Support Matrix

| Platform / Authenticator | PRF Extension Support |
|---|---|
| **Apple Passwords** (macOS, iOS) | Supported |
| **Google Password Manager** (Android, Chrome) | Supported |
| **Windows Hello** (Windows 11 update Feb 2026+) | Supported |
| **YubiKey / Security Keys** (Chrome, Firefox, Edge) | Supported |
| **Safari on iOS with Roaming Authenticators** | **Unsupported** (Safari on iOS does not pass extension data to external YubiKeys) |

Because support is not universal, applications must check whether PRF evaluation succeeded:
- On registration, `Credential.PRFEnabled` indicates whether the authenticator supports PRF for subsequent assertions.
- On assertion, `Assertion.PRFOutput` will be `nil` and `Get` will return `ErrPRFUnsupported` if the authenticator or browser fails to evaluate the PRF extension.

## Critical Security & Loss Warnings

1. **Irreversible Loss:** PRF outputs are tied to the physical or cloud-synced authenticator. If the authenticator is lost, the PRF output bytes cannot be recovered.
2. **Salt Constancy:** Changing the input salt produces a completely different 32-byte output, rendering all data previously encrypted under the old salt permanently unrecoverable.
