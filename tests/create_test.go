//go:build wasm

package webauthn_test

import (
	"strings"
	"syscall/js"
	"testing"

	. "webtyp.com/webauthn"
)

func TestCreateBadChallenge(t *testing.T) {
	_, err := Create(CreateOptions{Challenge: []byte("short")})
	if err != ErrBadChallenge {
		t.Fatalf("expected ErrBadChallenge, got %v", err)
	}
}

func TestCreateUnavailable(t *testing.T) {
	installBrowser(t, true, false)
	_, err := Create(CreateOptions{Challenge: make([]byte, 32)})
	if err != ErrUnavailable {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestCreateSuccess(t *testing.T) {
	br := installBrowser(t, true, true)
	credID := []byte("credential-id-1")
	clientData := []byte(`{"type":"webauthn.create","challenge":"AQID"}`)
	attObj := []byte("mock-attestation-object")
	transports := js.Global().Get("Array").New()
	transports.Call("push", "internal", "usb")
	extResults := js.Global().Get("Object").New()
	prfRes := js.Global().Get("Object").New()
	prfRes.Set("enabled", true)
	extResults.Set("prf", prfRes)

	br.stubCreate(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(credentialObject(credentialConfig{
			id:          credID,
			clientData:  clientData,
			attestation: attObj,
			transports:  transports,
			extResults:  extResults,
		}))
	})

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}

	cred, err := Create(CreateOptions{
		RPID:             "app.example.com",
		RPName:           "Example App",
		UserID:           []byte("user-42"),
		UserName:         "alice@example.com",
		UserDisplayName:  "Alice Smith",
		Challenge:        challenge,
		ResidentKey:      true,
		UserVerification: "required",
		EnablePRF:        true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(cred.ID) != string(credID) {
		t.Fatalf("got ID %q, want %q", cred.ID, credID)
	}
	if !cred.PRFEnabled {
		t.Fatal("expected PRFEnabled to be true")
	}

	json := decodeRawResponse(t, cred.RawResponse)
	for _, want := range []string{
		`"id"`, `"type"`, `"rawId"`, `"response"`,
		`"clientDataJSON"`, `"attestationObject"`, `"transports"`,
		`"clientExtensionResults"`, `"prf"`, `"enabled"`,
	} {
		if !strings.Contains(json, want) {
			t.Fatalf("raw response JSON missing %s: %s", want, json)
		}
	}

	pk := br.createOptions
	if pk.IsUndefined() {
		t.Fatal("credentials.create was not called with publicKey options")
	}
	rp := pk.Get("rp")
	if rp.Get("id").String() != "app.example.com" {
		t.Fatalf("got rp.id %q", rp.Get("id").String())
	}
	if rp.Get("name").String() != "Example App" {
		t.Fatalf("got rp.name %q", rp.Get("name").String())
	}

	user := pk.Get("user")
	if user.Get("name").String() != "alice@example.com" {
		t.Fatalf("got user.name %q", user.Get("name").String())
	}
	if user.Get("displayName").String() != "Alice Smith" {
		t.Fatalf("got user.displayName %q", user.Get("displayName").String())
	}
	if got := bytesOf(t, user.Get("id")); string(got) != "user-42" {
		t.Fatalf("got user.id %q", got)
	}
	if got := bytesOf(t, pk.Get("challenge")); string(got) != string(challenge) {
		t.Fatalf("challenge mismatch: got %q, want %q", got, challenge)
	}

	params := pk.Get("pubKeyCredParams")
	if params.Length() != 1 {
		t.Fatalf("expected 1 pubKeyCredParams, got %d", params.Length())
	}
	if params.Index(0).Get("alg").Int() != -7 {
		t.Fatalf("expected alg -7 (ES256), got %v", params.Index(0).Get("alg").Int())
	}

	authSelection := pk.Get("authenticatorSelection")
	if authSelection.Get("residentKey").String() != "required" {
		t.Fatalf("got residentKey %q, want %q", authSelection.Get("residentKey").String(), "required")
	}
	if !authSelection.Get("requireResidentKey").Bool() {
		t.Fatal("expected requireResidentKey to be true")
	}
	if authSelection.Get("userVerification").String() != "required" {
		t.Fatalf("got userVerification %q", authSelection.Get("userVerification").String())
	}

	ext := pk.Get("extensions")
	if ext.IsUndefined() {
		t.Fatal("expected extensions.prf to be requested")
	}
	prf := ext.Get("prf")
	if prf.IsUndefined() {
		t.Fatal("expected extensions.prf object")
	}
	if !prf.Get("eval").IsUndefined() {
		t.Fatal("create PRF extension must not carry an eval salt")
	}
}

func TestCreateNonResidentAndDefaultUV(t *testing.T) {
	br := installBrowser(t, true, true)
	br.stubCreate(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(credentialObject(credentialConfig{id: []byte("id")}))
	})

	_, err := Create(CreateOptions{Challenge: make([]byte, 32)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	authSelection := br.createOptions.Get("authenticatorSelection")
	if authSelection.Get("residentKey").String() != "preferred" {
		t.Fatalf("got residentKey %q, want %q", authSelection.Get("residentKey").String(), "preferred")
	}
	if !authSelection.Get("requireResidentKey").IsUndefined() {
		t.Fatal("requireResidentKey must be omitted for non-resident keys")
	}
	if !authSelection.Get("userVerification").IsUndefined() {
		t.Fatal("userVerification must be omitted when empty")
	}
	if !br.createOptions.Get("extensions").IsUndefined() {
		t.Fatal("extensions must be omitted when PRF is not requested")
	}
}

func TestCreateNoCredential(t *testing.T) {
	installBrowser(t, true, true).stubCreate(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(js.Undefined())
	})
	_, err := Create(CreateOptions{Challenge: make([]byte, 32)})
	if err != ErrNoCredential {
		t.Fatalf("expected ErrNoCredential, got %v", err)
	}
}

func TestCreateUserCancelled(t *testing.T) {
	installBrowser(t, true, true).stubCreate(t, func(this js.Value, args []js.Value) js.Value {
		return rejectedPromise(jsErr("NotAllowedError: User denied approval"))
	})
	_, err := Create(CreateOptions{Challenge: make([]byte, 32)})
	if err != ErrAborted {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
}

func TestCreateGenericDOMError(t *testing.T) {
	installBrowser(t, true, true).stubCreate(t, func(this js.Value, args []js.Value) js.Value {
		return rejectedPromise(jsErr("SecurityError: Relying party ID is invalid"))
	})
	_, err := Create(CreateOptions{Challenge: make([]byte, 32)})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "SecurityError") {
		t.Fatalf("expected cause preserved in %q", err)
	}
}

func TestCreatePRFDisabledFlag(t *testing.T) {
	t.Run("prf extension result reports disabled", func(t *testing.T) {
		br := installBrowser(t, true, true)
		extResults := js.Global().Get("Object").New()
		prfRes := js.Global().Get("Object").New()
		prfRes.Set("enabled", false)
		extResults.Set("prf", prfRes)
		br.stubCreate(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{
				id:         []byte("id"),
				extResults: extResults,
			}))
		})
		cred, err := Create(CreateOptions{Challenge: make([]byte, 32), EnablePRF: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.PRFEnabled {
			t.Fatal("expected PRFEnabled to be false when the authenticator reports disabled")
		}
	})

	t.Run("prf extension result absent", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubCreate(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{id: []byte("id")}))
		})
		cred, err := Create(CreateOptions{Challenge: make([]byte, 32), EnablePRF: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.PRFEnabled {
			t.Fatal("expected PRFEnabled to be false without extension results")
		}
	})
}
