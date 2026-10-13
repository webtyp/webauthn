# Architecture — `webtyp/webauthn`

`webtyp/webauthn` implements WebAuthn passkey ceremonies and relying-party verification for Go, targeting both native compilation and WebAssembly. The library is divided into two logical halves:

## 1. Browser Ceremonies (Root Package)

The root package (`webtyp.com/webauthn`) carries a `//go:build wasm` constraint and interfaces with the browser's `navigator.credentials` API via `syscall/js`.

### Responsibilities
1. **Browser Integration:** Interfacing with `navigator.credentials.create` and `navigator.credentials.get`.
2. **Blocking Async Calls:** Utilizing `webtyp.com/await` to block Go goroutines on JavaScript promises safely.
3. **Extension Management:** Requesting and parsing CTAP2 PRF (`hmac-secret`) extension inputs and outputs.
4. **Serialization:** Converting standard `PublicKeyCredential` JS response objects into standard base64url JSON strings (`RawResponse`).

### WebAuthn Level 2 Support
During registration, the browser half checks for the presence of `getPublicKey()`, `getPublicKeyAlgorithm()`, and `getAuthenticatorData()` methods (introduced in WebAuthn Level 2). If present, it extracts the SPKI public key directly, bypassing the need for a verifier to parse the CBOR-encoded `attestationObject`.

## 2. Relying-Party Verification (`webauthn/server`)

The `webauthn/server` package has no build tags and compiles natively as well as under `GOOS=js GOARCH=wasm` (e.g., for Cloudflare Workers). It verifies the `RawResponse` JSON emitted by the browser half.

### Design Choices
- **ES256 Only:** The verifier supports only the ES256 (-7) algorithm. This covers the vast majority of modern passkeys and simplifies the codebase.
- **No CBOR Parsing:** The verifier expects the browser half to provide the `publicKey` (SPKI DER) explicitly in the response JSON. It avoids adding a dependency on a CBOR parser just to read the `attestationObject`.
- **Constant-Time Verification:** All comparisons of challenges, origins, and credential IDs are performed in constant time using `webtyp.com/crypto/subtle`.
- **Fail Closed:** Every verification step that cannot be completed results in a rejection with a typed error constant. No steps are skipped.
