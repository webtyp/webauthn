//go:build wasm

package webauthn_test

import (
	"syscall/js"
	"testing"

	. "webtyp.com/webauthn"
)

func TestAvailable(t *testing.T) {
	t.Run("browser exposes the WebAuthn API", func(t *testing.T) {
		installBrowser(t, true, true)
		if !Available() {
			t.Fatal("expected Available() to be true with mocked navigator + PublicKeyCredential")
		}
	})

	t.Run("no credentials surface", func(t *testing.T) {
		installBrowser(t, false, true)
		if Available() {
			t.Fatal("expected Available() to be false without navigator.credentials")
		}
	})

	t.Run("no PublicKeyCredential", func(t *testing.T) {
		installBrowser(t, true, false)
		if Available() {
			t.Fatal("expected Available() to be false without PublicKeyCredential")
		}
	})

	t.Run("no navigator at all", func(t *testing.T) {
		installBrowser(t, false, false)
		if Available() {
			t.Fatal("expected Available() to be false without navigator")
		}
	})
}

func TestPlatformAuthenticatorAvailable(t *testing.T) {
	t.Run("authenticator reports true", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubPlatformAuthenticatorAvailable(func() js.Value {
			return resolvedPromise(js.ValueOf(true))
		})
		if !PlatformAuthenticatorAvailable() {
			t.Fatal("expected platform authenticator to be available")
		}
	})

	t.Run("authenticator reports false", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubPlatformAuthenticatorAvailable(func() js.Value {
			return resolvedPromise(js.ValueOf(false))
		})
		if PlatformAuthenticatorAvailable() {
			t.Fatal("expected platform authenticator to be unavailable")
		}
	})

	t.Run("query rejects", func(t *testing.T) {
		br := installBrowser(t, true, true)
		br.stubPlatformAuthenticatorAvailable(func() js.Value {
			return rejectedPromise(jsErr("NotSupportedError: cannot probe"))
		})
		if PlatformAuthenticatorAvailable() {
			t.Fatal("expected false when the availability probe rejects")
		}
	})

	t.Run("method missing", func(t *testing.T) {
		installBrowser(t, true, true)
		if PlatformAuthenticatorAvailable() {
			t.Fatal("expected false when isUserVerifyingPlatformAuthenticatorAvailable is missing")
		}
	})

	t.Run("WebAuthn API missing entirely", func(t *testing.T) {
		installBrowser(t, false, false)
		if PlatformAuthenticatorAvailable() {
			t.Fatal("expected false when the WebAuthn API is unavailable")
		}
	})
}
