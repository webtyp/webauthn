//go:build wasm

// Package webauthn_test exercises the public API of webtyp.com/webauthn
// against a mocked browser environment (navigator.credentials, PublicKeyCredential).
// Shared setup lives here; every ceremony test installs its own fresh mock.
package webauthn_test

import (
	"syscall/js"
	"testing"

	"webtyp.com/base64"
)

// browser replaces the browser globals the library reads with mock objects.
// The previous values are restored when the test finishes, so tests never
// leak state into each other or into the host page.
type browser struct {
	creds js.Value // navigator.credentials mock
	pkc   js.Value // window.PublicKeyCredential mock

	createOptions js.Value // last publicKey options object passed to credentials.create
	getOptions    js.Value // last publicKey options object passed to credentials.get
}

// defineGlobal shadows a browser global (e.g. navigator, PublicKeyCredential)
// with a mock value. Plain js.Value.Set is silently ignored for prototype
// accessor properties, so Object.defineProperty is required. The previous
// value is restored when the test finishes.
func defineGlobal(t *testing.T, name string, v js.Value) {
	t.Helper()
	orig := js.Global().Get(name)

	desc := js.Global().Get("Object").New()
	desc.Set("value", v)
	desc.Set("configurable", true)
	js.Global().Get("Object").Call("defineProperty", js.Global(), name, desc)

	t.Cleanup(func() {
		if orig.IsUndefined() {
			js.Global().Get("Reflect").Call("deleteProperty", js.Global(), name)
			return
		}
		restore := js.Global().Get("Object").New()
		restore.Set("value", orig)
		restore.Set("configurable", true)
		js.Global().Get("Object").Call("defineProperty", js.Global(), name, restore)
	})
}

// installBrowser sets up navigator and PublicKeyCredential. Pass false to
// omit either surface to exercise the "not available" paths.
func installBrowser(t *testing.T, withCredentials, withPkc bool) *browser {
	t.Helper()

	br := &browser{
		creds: js.Global().Get("Object").New(),
		pkc:   js.Global().Get("Object").New(),
	}

	nav := js.Global().Get("Object").New()
	if withCredentials {
		nav.Set("credentials", br.creds)
	}
	defineGlobal(t, "navigator", nav)

	if withPkc {
		defineGlobal(t, "PublicKeyCredential", br.pkc)
	} else {
		defineGlobal(t, "PublicKeyCredential", js.Undefined())
	}
	return br
}

// stubCreate installs a credentials.create handler. The handler returns the
// js.Value that Create should await; return resolvedPromise/rejectedPromise.
func (b *browser) stubCreate(t *testing.T, handler func(this js.Value, args []js.Value) js.Value) {
	t.Helper()
	b.creds.Set("create", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			b.createOptions = args[0].Get("publicKey")
		}
		return handler(this, args)
	}))
}

// stubGet installs a credentials.get handler, mirroring stubCreate.
func (b *browser) stubGet(t *testing.T, handler func(this js.Value, args []js.Value) js.Value) {
	t.Helper()
	b.creds.Set("get", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			b.getOptions = args[0].Get("publicKey")
		}
		return handler(this, args)
	}))
}

// stubPlatformAuthenticatorAvailable installs
// PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable.
func (b *browser) stubPlatformAuthenticatorAvailable(handler func() js.Value) {
	b.pkc.Set("isUserVerifyingPlatformAuthenticatorAvailable", js.FuncOf(func(this js.Value, args []js.Value) any {
		return handler()
	}))
}

// resolvedPromise returns a then-able that settles immediately with v. It
// implements the then/catch surface that webtyp/await relies on.
func resolvedPromise(v js.Value) js.Value {
	p := js.Global().Get("Object").New()
	p.Set("then", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) > 0 {
			args[0].Invoke(v)
		}
		return p
	}))
	p.Set("catch", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return p
	}))
	return p
}

// rejectedPromise settles immediately with err, mirroring resolvedPromise.
func rejectedPromise(err js.Value) js.Value {
	p := js.Global().Get("Object").New()
	p.Set("then", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return p
	}))
	p.Set("catch", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) > 0 {
			args[0].Invoke(err)
		}
		return p
	}))
	return p
}

// jsErr builds a real JS Error whose toString() contains the given message,
// matching how the browser flattens DOMException errors through the await lib.
func jsErr(msg string) js.Value {
	return js.Global().Get("Error").New(msg)
}

// bufferOf converts []byte into a real JS ArrayBuffer, like the authenticator
// responses expose.
func bufferOf(b []byte) js.Value {
	if len(b) == 0 {
		return js.Global().Get("ArrayBuffer").New(0)
	}
	ua := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(ua, b)
	return ua.Get("buffer")
}

// bytesOf reads a JS ArrayBuffer back into []byte.
func bytesOf(t *testing.T, v js.Value) []byte {
	t.Helper()
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	ua := js.Global().Get("Uint8Array").New(v)
	length := ua.Get("length").Int()
	out := make([]byte, length)
	js.CopyBytesToGo(out, ua)
	return out
}

// credentialConfig describes the shape of a mock PublicKeyCredential object
// returned by credentials.create/credentials.get.
type credentialConfig struct {
	id          []byte
	clientData  []byte
	attestation []byte   // create only
	authData    []byte   // get only
	signature   []byte   // get only
	userHandle  []byte   // get only
	transports  js.Value // create only; nil skips the getTransports method
	extResults  js.Value // clientExtensionResults; undefined skips the method
}

// credentialObject builds the PublicKeyCredential JS object for a ceremony.
func credentialObject(cfg credentialConfig) js.Value {
	obj := js.Global().Get("Object").New()
	obj.Set("id", base64.URLEncode(cfg.id))
	obj.Set("type", "public-key")
	obj.Set("rawId", bufferOf(cfg.id))

	resp := js.Global().Get("Object").New()
	if cfg.clientData != nil {
		resp.Set("clientDataJSON", bufferOf(cfg.clientData))
	}
	if cfg.attestation != nil {
		resp.Set("attestationObject", bufferOf(cfg.attestation))

		// Add mock level 2 methods for create responses
		resp.Set("getPublicKey", js.FuncOf(func(_ js.Value, args []js.Value) any {
			return bufferOf([]byte("mock-public-key"))
		}))
		resp.Set("getPublicKeyAlgorithm", js.FuncOf(func(_ js.Value, args []js.Value) any {
			return -7
		}))
		resp.Set("getAuthenticatorData", js.FuncOf(func(_ js.Value, args []js.Value) any {
			return bufferOf([]byte("mock-authenticator-data"))
		}))
	}
	if cfg.authData != nil {
		resp.Set("authenticatorData", bufferOf(cfg.authData))
	}
	if cfg.signature != nil {
		resp.Set("signature", bufferOf(cfg.signature))
	}
	if cfg.userHandle != nil {
		resp.Set("userHandle", bufferOf(cfg.userHandle))
	}
	obj.Set("response", resp)

	if cfg.transports.Type() != js.TypeUndefined {
		transports := cfg.transports
		resp.Set("getTransports", js.FuncOf(func(_ js.Value, args []js.Value) any {
			return transports
		}))
	}
	if cfg.extResults.Type() != js.TypeUndefined {
		extResults := cfg.extResults
		obj.Set("getClientExtensionResults", js.FuncOf(func(_ js.Value, args []js.Value) any {
			return extResults
		}))
	}
	return obj
}

// decodeRawResponse decodes the base64url JSON emitted as Credential.RawResponse
// and Assertion.RawResponse back into readable JSON for assertion.
func decodeRawResponse(t *testing.T, raw string) string {
	t.Helper()
	if raw == "" {
		t.Fatal("raw response is empty")
	}
	decoded, err := base64.URLDecode(raw)
	if err != nil {
		t.Fatalf("raw response is not valid base64url: %v", err)
	}
	return string(decoded)
}
