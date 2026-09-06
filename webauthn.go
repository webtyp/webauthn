//go:build wasm

package webauthn

import (
	"syscall/js"

	"webtyp.com/await"
)

// Available reports whether the browser exposes the WebAuthn API at all.
func Available() bool {
	nav := js.Global().Get("navigator")
	if nav.IsUndefined() || nav.IsNull() {
		return false
	}
	creds := nav.Get("credentials")
	if creds.IsUndefined() || creds.IsNull() {
		return false
	}
	pkc := js.Global().Get("PublicKeyCredential")
	return !pkc.IsUndefined() && !pkc.IsNull()
}

// PlatformAuthenticatorAvailable blocks until the browser answers whether a
// built-in authenticator (Touch ID, Windows Hello, Android biometrics) exists.
func PlatformAuthenticatorAvailable() bool {
	if !Available() {
		return false
	}
	pkc := js.Global().Get("PublicKeyCredential")
	fn := pkc.Get("isUserVerifyingPlatformAuthenticatorAvailable")
	if fn.IsUndefined() || fn.IsNull() {
		return false
	}
	promise := pkc.Call("isUserVerifyingPlatformAuthenticatorAvailable")
	res, err := await.Promise(promise)
	if err != nil {
		return false
	}
	if res.Type() == js.TypeBoolean {
		return res.Bool()
	}
	return false
}

// JS conversion helpers

func bytesToArrayBuffer(b []byte) js.Value {
	if len(b) == 0 {
		return js.Global().Get("ArrayBuffer").New(0)
	}
	ua := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(ua, b)
	return ua.Get("buffer")
}

func arrayBufferToBytes(v js.Value) []byte {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	ua := js.Global().Get("Uint8Array").New(v)
	length := ua.Get("length").Int()
	if length == 0 {
		return nil
	}
	b := make([]byte, length)
	js.CopyBytesToGo(b, ua)
	return b
}
