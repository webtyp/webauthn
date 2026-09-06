# Architecture — `webtyp/webauthn`

## Scope: Client-Side WASM Only (v0.1.0)

`webtyp/webauthn` is strictly a client-side WebAssembly module (`//go:build wasm`) designed to execute WebAuthn passkey ceremonies in the browser.

### Responsibilities of `webtyp/webauthn`

1. **Browser Integration:** Interfacing with `navigator.credentials.create` and `navigator.credentials.get`.
2. **Blocking Async Calls:** Utilizing `webtyp.com/await` to block Go goroutines on JavaScript promises safely.
3. **Extension Management:** Requesting and parsing CTAP2 PRF (`hmac-secret`) extension inputs and outputs.
4. **Serialization:** Converting standard `PublicKeyCredential` JS response objects into standard base64url JSON strings (`RawResponse`).

## Excluded Responsibilities (Server / Edge Verification)

Server-side and edge verification are deliberately out of scope for `v0.1.0`:
- CBOR parsing of attestation objects and authenticator data.
- COSE key decoding (ECDSA p256 / RSA).
- Assertion signature validation against stored public keys.

These server/edge verification tasks belong to authentication verification modules (such as `webtyp/user`) on the edge or backend server.
