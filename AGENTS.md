# Agent Guide — `webtyp/webauthn`

Constraints for agents working on this library. Read this before any change.

## What this library is

WebAuthn (passkeys) for the webtyp ecosystem, in two halves:

- **Root package `webauthn`** (`//go:build wasm`): the **browser** ceremonies
  (`navigator.credentials.create/get`) through `syscall/js`. It produces
  `Credential.RawResponse` / `Assertion.RawResponse`: base64url of the JSON a
  verifier needs.
- **`webauthn/server`**: the **relying-party verification** of those
  responses. It has no build tag and no `syscall/js`. It must compile and pass
  its tests natively **and** under `GOOS=js GOARCH=wasm`, because Cloudflare
  Workers (TinyGo) verify passkeys too.

## Rules

- **No standard library for text, numbers or errors**: use `webtyp.com/fmt`
  (no `strings`, `strconv`, `errors`, `fmt`). `crypto/sha256` is allowed
  (ECDSA work goes through `webtyp.com/crypto/asym`).
- **No `map`** in any package (both halves compile to WASM). Slices only.
- **No CBOR parser.** Registration reads the SPKI public key the browser
  exposes through `getPublicKey()` (WebAuthn Level 2); assertions need no
  CBOR. Do not add a CBOR dependency.
- **ES256 only** (COSE alg -7, P-256). It is what every platform
  authenticator supports and what `webtyp/crypto/asym` verifies.
- **Fail closed.** Every verification step that cannot be completed is a
  rejection with a typed error constant, never a skipped check.
- Comparisons of challenges and other secrets are **constant-time**
  (`webtyp.com/crypto/subtle`).
- Every repeated string is a named constant.

## Testing

- Tests live in `tests/` (external package). Browser tests carry
  `//go:build wasm` and mock `navigator.credentials` (see `tests/setup_test.go`).
  Server tests carry **no** build tag, so they run in both suites.
- Never export a symbol only so a test can reach it.
- Run `gotest`, never `go test`.
