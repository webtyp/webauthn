//go:build wasm

package webauthn_test

import (
	"strings"
	"syscall/js"
	"testing"

	. "webtyp.com/webauthn"
)

func TestGetBadChallenge(t *testing.T) {
	_, err := Get(GetOptions{Challenge: []byte("short")})
	if err != ErrBadChallenge {
		t.Fatalf("expected ErrBadChallenge, got %v", err)
	}
}

func TestGetUnavailable(t *testing.T) {
	installBrowser(t, true, false)
	_, err := Get(GetOptions{Challenge: make([]byte, 32)})
	if err != ErrUnavailable {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestGetSuccess(t *testing.T) {
	br := installBrowser(t, true, true)
	credID := []byte("credential-id-2")
	clientData := []byte(`{"type":"webauthn.get","challenge":"BAUG"}`)
	authData := []byte("mock-authenticator-data")
	signature := []byte("mock-signature")
	userHandle := []byte("user-42")

	br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(credentialObject(credentialConfig{
			id:         credID,
			clientData: clientData,
			authData:   authData,
			signature:  signature,
			userHandle: userHandle,
		}))
	})

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i + 2)
	}
	allowA := []byte("cred-a")
	allowB := []byte("cred-b")

	assertion, err := Get(GetOptions{
		RPID:             "app.example.com",
		Challenge:        challenge,
		AllowCredentials: [][]byte{allowA, allowB},
		UserVerification: "preferred",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(assertion.CredentialID) != string(credID) {
		t.Fatalf("got CredentialID %q, want %q", assertion.CredentialID, credID)
	}
	if assertion.PRFOutput != nil {
		t.Fatalf("expected PRFOutput to be nil without PRFSalt, got %x", assertion.PRFOutput)
	}

	json := decodeRawResponse(t, assertion.RawResponse)
	for _, want := range []string{
		`"id"`, `"type"`, `"rawId"`, `"response"`,
		`"clientDataJSON"`, `"authenticatorData"`, `"signature"`, `"userHandle"`,
	} {
		if !strings.Contains(json, want) {
			t.Fatalf("raw response JSON missing %s: %s", want, json)
		}
	}
	if strings.Contains(json, `"transports"`) {
		t.Fatal("assertion serialization must not include transports")
	}

	pk := br.getOptions
	if pk.IsUndefined() {
		t.Fatal("credentials.get was not called with publicKey options")
	}
	if pk.Get("rpId").String() != "app.example.com" {
		t.Fatalf("got rpId %q", pk.Get("rpId").String())
	}
	if got := bytesOf(t, pk.Get("challenge")); string(got) != string(challenge) {
		t.Fatalf("challenge mismatch: got %q, want %q", got, challenge)
	}
	if pk.Get("userVerification").String() != "preferred" {
		t.Fatalf("got userVerification %q", pk.Get("userVerification").String())
	}

	allow := pk.Get("allowCredentials")
	if allow.Length() != 2 {
		t.Fatalf("expected 2 allowCredentials, got %d", allow.Length())
	}
	if got := bytesOf(t, allow.Index(0).Get("id")); string(got) != string(allowA) {
		t.Fatalf("got allowCredentials[0].id %q", got)
	}
	if got := bytesOf(t, allow.Index(1).Get("id")); string(got) != string(allowB) {
		t.Fatalf("got allowCredentials[1].id %q", got)
	}
	if allow.Index(0).Get("type").String() != "public-key" {
		t.Fatalf("got allowCredentials[0].type %q", allow.Index(0).Get("type").String())
	}
	if !pk.Get("extensions").IsUndefined() {
		t.Fatal("extensions must be omitted without PRFSalt")
	}
}

func TestGetMinimalOptions(t *testing.T) {
	br := installBrowser(t, true, true)
	br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(credentialObject(credentialConfig{id: []byte("id")}))
	})
	if _, err := Get(GetOptions{Challenge: make([]byte, 32)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pk := br.getOptions
	if !pk.Get("rpId").IsUndefined() {
		t.Fatal("rpId must be omitted when empty")
	}
	if !pk.Get("userVerification").IsUndefined() {
		t.Fatal("userVerification must be omitted when empty")
	}
	if !pk.Get("allowCredentials").IsUndefined() {
		t.Fatal("allowCredentials must be omitted when empty")
	}
}

func TestGetNoCredential(t *testing.T) {
	installBrowser(t, true, true).stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(js.Undefined())
	})
	_, err := Get(GetOptions{Challenge: make([]byte, 32)})
	if err != ErrNoCredential {
		t.Fatalf("expected ErrNoCredential, got %v", err)
	}
}

func TestGetUserCancelled(t *testing.T) {
	installBrowser(t, true, true).stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return rejectedPromise(jsErr("AbortError: The operation either timed out or was not allowed"))
	})
	_, err := Get(GetOptions{Challenge: make([]byte, 32)})
	if err != ErrAborted {
		t.Fatalf("expected ErrAborted, got %v", err)
	}
}

func TestGetGenericDOMError(t *testing.T) {
	installBrowser(t, true, true).stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return rejectedPromise(jsErr("UnknownError: credential store is unavailable"))
	})
	_, err := Get(GetOptions{Challenge: make([]byte, 32)})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "credential store is unavailable") {
		t.Fatalf("expected cause preserved in %q", err)
	}
}

func TestGetFallbackIDFromString(t *testing.T) {
	installBrowser(t, true, true).stubGet(t, func(this js.Value, args []js.Value) js.Value {
		res := credentialObject(credentialConfig{})
		res.Set("id", "base64url-string-id")
		return resolvedPromise(res)
	})
	assertion, err := Get(GetOptions{Challenge: make([]byte, 32)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(assertion.CredentialID) != "base64url-string-id" {
		t.Fatalf("expected fallback to the string id, got %q", assertion.CredentialID)
	}
}
