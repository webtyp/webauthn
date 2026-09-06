//go:build wasm

package webauthn_test

import (
	"strings"
	"syscall/js"
	"testing"

	. "webtyp.com/webauthn"
)

func TestGetPRFOutput(t *testing.T) {
	br := installBrowser(t, true, true)
	salt := []byte("fixed-salt-for-tests-0123456789012") // 32 bytes
	prfOut := []byte("32bytes-long-prf-output-material1")

	extResults := js.Global().Get("Object").New()
	prfRes := js.Global().Get("Object").New()
	results := js.Global().Get("Object").New()
	results.Set("first", bufferOf(prfOut))
	prfRes.Set("results", results)
	extResults.Set("prf", prfRes)

	br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
		return resolvedPromise(credentialObject(credentialConfig{
			id:         []byte("id"),
			extResults: extResults,
		}))
	})

	assertion, err := Get(GetOptions{
		Challenge: make([]byte, 32),
		PRFSalt:   salt,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(assertion.PRFOutput) != string(prfOut) {
		t.Fatalf("got PRFOutput %x, want %x", assertion.PRFOutput, prfOut)
	}

	ext := br.getOptions.Get("extensions")
	prf := ext.Get("prf")
	if prf.IsUndefined() {
		t.Fatal("expected extensions.prf to be requested")
	}
	if got := bytesOf(t, prf.Get("eval").Get("first")); string(got) != string(salt) {
		t.Fatalf("got eval.first %q, want the PRF salt %q", got, salt)
	}
	if !prf.Get("eval").Get("second").IsUndefined() {
		t.Fatal("get PRF extension must only carry the first salt")
	}
}

func TestGetPRFUnsupported(t *testing.T) {
	t.Run("no extension results at all", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{id: []byte("id")}))
		})
		_, err := Get(GetOptions{Challenge: make([]byte, 32), PRFSalt: make([]byte, 32)})
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})

	t.Run("extension results without prf key", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{
				id:         []byte("id"),
				extResults: js.Global().Get("Object").New(),
			}))
		})
		_, err := Get(GetOptions{Challenge: make([]byte, 32), PRFSalt: make([]byte, 32)})
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})

	t.Run("prf present but results missing", func(t *testing.T) {
		br := installBrowser(t, true, true)
		extResults := js.Global().Get("Object").New()
		extResults.Set("prf", js.Global().Get("Object").New())
		br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{
				id:         []byte("id"),
				extResults: extResults,
			}))
		})
		_, err := Get(GetOptions{Challenge: make([]byte, 32), PRFSalt: make([]byte, 32)})
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})

	t.Run("results present but first missing", func(t *testing.T) {
		br := installBrowser(t, true, true)
		extResults := js.Global().Get("Object").New()
		prfRes := js.Global().Get("Object").New()
		prfRes.Set("results", js.Global().Get("Object").New())
		extResults.Set("prf", prfRes)
		br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{
				id:         []byte("id"),
				extResults: extResults,
			}))
		})
		_, err := Get(GetOptions{Challenge: make([]byte, 32), PRFSalt: make([]byte, 32)})
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})

	t.Run("first present but empty", func(t *testing.T) {
		br := installBrowser(t, true, true)
		extResults := js.Global().Get("Object").New()
		prfRes := js.Global().Get("Object").New()
		results := js.Global().Get("Object").New()
		results.Set("first", bufferOf(nil))
		prfRes.Set("results", results)
		extResults.Set("prf", prfRes)
		br.stubGet(t, func(this js.Value, args []js.Value) js.Value {
			return resolvedPromise(credentialObject(credentialConfig{
				id:         []byte("id"),
				extResults: extResults,
			}))
		})
		_, err := Get(GetOptions{Challenge: make([]byte, 32), PRFSalt: make([]byte, 32)})
		if err != ErrPRFUnsupported {
			t.Fatalf("expected ErrPRFUnsupported, got %v", err)
		}
	})
}

func TestCreatePRFSerializationInRawResponse(t *testing.T) {
	br := installBrowser(t, true, true)
	extResults := js.Global().Get("Object").New()
	prfRes := js.Global().Get("Object").New()
	prfRes.Set("enabled", true)
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
	json := decodeRawResponse(t, cred.RawResponse)
	if !strings.Contains(json, `"clientExtensionResults":{"prf":{"enabled":true}}`) {
		t.Fatalf("expected prf extension results in serialized JSON, got %s", json)
	}
}
