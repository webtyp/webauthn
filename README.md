# webauthn
<img src="docs/img/badges.svg">

`webauthn` provides WebAuthn passkey ceremonies for Go compiling to WebAssembly (`//go:build wasm`), with support for the PRF extension (deterministic secret derivation).

## Passkeys & PRF Mechanics

A passkey's private key never leaves the authenticator. During standard authentication ceremonies, JavaScript asks the authenticator to sign a challenge.

> **CRITICAL WARNING — Signatures are NOT deterministic:**
> Every ceremony produces a different signature because the signature covers `authenticatorData` (whose counter increments) and `clientDataHash` (a random challenge). **Deriving encryption keys from assertion signatures will fail.**
>
> To derive deterministic key material (e.g. for unlocking encrypted local storage), you **must** use the **PRF extension** (`hmac-secret`). Given a fixed salt, the authenticator yields 32 deterministic output bytes released only after user verification.
>
> **Salt Warning:** Changing the salt changes the derived key and renders previously encrypted data permanently unrecoverable.

## Verifying on the server

The `webauthn/server` package provides verification of WebAuthn responses, ensuring that the relying party checks user presence, user verification, signature validity, and sign count. It supports ES256 only.

```go
package main

import (
	"fmt"
	"webtyp.com/webauthn/server"
)

var rp = server.RelyingParty{
	ID:     "example.com",
	Origin: "https://example.com",
}

func verifyRegistration(rawResponse string, issuedChallenge []byte) {
	registration, err := rp.VerifyRegistration(rawResponse, issuedChallenge)
	if err != nil {
		fmt.Println("Registration failed:", err)
		return
	}
	fmt.Printf("Stored Credential ID: %x\n", registration.CredentialID)
	// Store registration.PublicKey and registration.SignCount for this user
}

func verifyAssertion(rawResponse string, issuedChallenge []byte, stored server.StoredCredential) {
	newCount, err := rp.VerifyAssertion(rawResponse, issuedChallenge, stored)
	if err != nil {
		fmt.Println("Assertion failed:", err)
		return
	}
	fmt.Printf("New Sign Count: %d\n", newCount)
	// Update stored.SignCount with newCount
}
```

## Caller Requirements — Gesture & Goroutine Rules

> **IMPORTANT:**
> 1. **Do not call `Create` or `Get` from the main WASM goroutine.** Blocking the main goroutine deadlocks the JavaScript event loop. Always invoke `Create` or `Get` from a separate goroutine (e.g., `go func() { ... }()`).
> 2. **Must be triggered by a direct user gesture.** Modern browsers reject WebAuthn requests unless initiated directly within a user gesture event handler (such as a button click).

## Quickstart Example

```go
package main

import (
	"syscall/js"

	"webtyp.com/webauthn"
)

func onRegisterButtonClick(this js.Value, args []js.Value) any {
	go func() {
		cred, err := webauthn.Create(webauthn.CreateOptions{
			RPID:             "example.com",
			RPName:           "Example App",
			UserID:           []byte("user_12345"),
			UserName:         "alice@example.com",
			UserDisplayName: "Alice Smith",
			Challenge:        challenge32Bytes,
			ResidentKey:      true,
			UserVerification: "preferred",
			EnablePRF:        true,
		})
		if err != nil {
			// handle error (e.g. webauthn.ErrAborted)
			return
		}
		_ = cred.RawResponse // POST to verifier
	}()
	return nil
}

func onLoginButtonClick(this js.Value, args []js.Value) any {
	go func() {
		assertion, err := webauthn.Get(webauthn.GetOptions{
			RPID:             "example.com",
			Challenge:        challenge32Bytes,
			UserVerification: "preferred",
			PRFSalt:          fixed32ByteSalt,
		})
		if err != nil {
			// handle error
			return
		}
		_ = assertion.PRFOutput // 32 deterministic key bytes (if PRF supported)
	}()
	return nil
}
```
