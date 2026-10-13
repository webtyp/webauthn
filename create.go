//go:build wasm

package webauthn

import (
	"syscall/js"

	"webtyp.com/await"
	"webtyp.com/base64"
)

// CreateOptions describes a registration ceremony.
type CreateOptions struct {
	RPID             string // relying party id — the origin's domain, e.g. "app.example.com"
	RPName           string
	UserID           []byte // opaque, stable, never the email
	UserName         string // shown in the account picker
	UserDisplayName  string
	Challenge        []byte // 32 random bytes; server-issued for auth, local for encryption
	ResidentKey      bool   // true for a discoverable passkey
	UserVerification string // "required" | "preferred" | "discouraged"
	EnablePRF        bool   // request the prf extension
}

// Credential is the result of a registration ceremony.
type Credential struct {
	ID          []byte
	RawResponse string // base64url JSON, ready to POST to a verifier
	PRFEnabled  bool   // the authenticator will honour prf on later assertions
}

// Create runs navigator.credentials.create. It blocks the calling goroutine
// until the user completes or cancels the ceremony, and MUST be called from a
// goroutine started by a user-gesture event handler.
func Create(opts CreateOptions) (*Credential, error) {
	if len(opts.Challenge) < 16 {
		return nil, ErrBadChallenge
	}
	if !Available() {
		return nil, ErrUnavailable
	}

	pkOpts := js.Global().Get("Object").New()

	rpObj := js.Global().Get("Object").New()
	rpObj.Set("id", opts.RPID)
	rpObj.Set("name", opts.RPName)
	pkOpts.Set("rp", rpObj)

	userObj := js.Global().Get("Object").New()
	userObj.Set("id", bytesToArrayBuffer(opts.UserID))
	userObj.Set("name", opts.UserName)
	userObj.Set("displayName", opts.UserDisplayName)
	pkOpts.Set("user", userObj)

	pkOpts.Set("challenge", bytesToArrayBuffer(opts.Challenge))

	params := js.Global().Get("Array").New()
	p1 := js.Global().Get("Object").New()
	p1.Set("type", "public-key")
	p1.Set("alg", -7) // ES256
	params.Call("push", p1)
	pkOpts.Set("pubKeyCredParams", params)

	authSelection := js.Global().Get("Object").New()
	if opts.ResidentKey {
		authSelection.Set("residentKey", "required")
		authSelection.Set("requireResidentKey", true)
	} else {
		authSelection.Set("residentKey", "preferred")
	}
	if opts.UserVerification != "" {
		authSelection.Set("userVerification", opts.UserVerification)
	}
	pkOpts.Set("authenticatorSelection", authSelection)

	if opts.EnablePRF {
		pkOpts.Set("extensions", buildCreatePRFExtension())
	}

	pkOpts.Set("attestation", "none")

	options := js.Global().Get("Object").New()
	options.Set("publicKey", pkOpts)

	nav := js.Global().Get("navigator")
	creds := nav.Get("credentials")
	promise := creds.Call("create", options)

	res, err := await.Promise(promise)
	if err != nil {
		return nil, mapAwaitError(err)
	}
	if res.IsUndefined() || res.IsNull() {
		return nil, ErrNoCredential
	}

	credID := arrayBufferToBytes(res.Get("rawId"))
	if len(credID) == 0 {
		credID = []byte(res.Get("id").String())
	}

	prfEnabled := false
	if !res.Get("getClientExtensionResults").IsUndefined() && !res.Get("getClientExtensionResults").IsNull() {
		extResults := res.Call("getClientExtensionResults")
		prfEnabled = parseCreatePRFResult(extResults)
	}

	rawResp := serializeCredentialCreationResponse(res)

	return &Credential{
		ID:          credID,
		RawResponse: rawResp,
		PRFEnabled:  prfEnabled,
	}, nil
}

func mapAwaitError(err error) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	if containsSubstring(errStr, "NotAllowedError") || containsSubstring(errStr, "AbortError") {
		return ErrAborted
	}
	return Error("webauthn: " + errStr)
}

func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func serializeCredentialCreationResponse(res js.Value) string {
	jsonObj := js.Global().Get("Object").New()
	if !res.Get("id").IsUndefined() {
		jsonObj.Set("id", res.Get("id"))
	}
	if !res.Get("type").IsUndefined() {
		jsonObj.Set("type", res.Get("type"))
	}
	rawIDBytes := arrayBufferToBytes(res.Get("rawId"))
	if len(rawIDBytes) > 0 {
		jsonObj.Set("rawId", base64.URLEncode(rawIDBytes))
	}

	resp := res.Get("response")
	if !resp.IsUndefined() && !resp.IsNull() {
		respObj := js.Global().Get("Object").New()
		cdJSON := arrayBufferToBytes(resp.Get("clientDataJSON"))
		if len(cdJSON) > 0 {
			respObj.Set("clientDataJSON", base64.URLEncode(cdJSON))
		}

		attObj := arrayBufferToBytes(resp.Get("attestationObject"))
		if len(attObj) > 0 {
			respObj.Set("attestationObject", base64.URLEncode(attObj))
		}

		if !resp.Get("getPublicKey").IsUndefined() && !resp.Get("getPublicKey").IsNull() {
			pkBytes := arrayBufferToBytes(resp.Call("getPublicKey"))
			if len(pkBytes) > 0 {
				respObj.Set("publicKey", base64.URLEncode(pkBytes))
			}
		}

		if !resp.Get("getPublicKeyAlgorithm").IsUndefined() && !resp.Get("getPublicKeyAlgorithm").IsNull() {
			respObj.Set("publicKeyAlgorithm", resp.Call("getPublicKeyAlgorithm").Int())
		}

		if !resp.Get("getAuthenticatorData").IsUndefined() && !resp.Get("getAuthenticatorData").IsNull() {
			authDataBytes := arrayBufferToBytes(resp.Call("getAuthenticatorData"))
			if len(authDataBytes) > 0 {
				respObj.Set("authenticatorData", base64.URLEncode(authDataBytes))
			}
		}

		if !resp.Get("getTransports").IsUndefined() && !resp.Get("getTransports").IsNull() {
			respObj.Set("transports", resp.Call("getTransports"))
		}
		jsonObj.Set("response", respObj)
	}

	if !res.Get("getClientExtensionResults").IsUndefined() && !res.Get("getClientExtensionResults").IsNull() {
		extResults := res.Call("getClientExtensionResults")
		jsonObj.Set("clientExtensionResults", extResults)
	}

	jsonStr := js.Global().Get("JSON").Call("stringify", jsonObj).String()
	return base64.URLEncode([]byte(jsonStr))
}
