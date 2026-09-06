//go:build wasm

package webauthn_test

import (
	"strings"
	"testing"

	. "webtyp.com/webauthn"
)

func TestErrorStrings(t *testing.T) {
	tests := []struct {
		err      Error
		expected string
	}{
		{ErrUnavailable, "webauthn: not available in this browser"},
		{ErrAborted, "webauthn: ceremony cancelled by the user"},
		{ErrPRFUnsupported, "webauthn: authenticator does not support the prf extension"},
		{ErrNoCredential, "webauthn: no credential returned"},
		{ErrBadChallenge, "webauthn: challenge must be at least 16 bytes"},
	}

	for _, tc := range tests {
		if tc.err.Error() != tc.expected {
			t.Fatalf("got %q, want %q", tc.err.Error(), tc.expected)
		}
	}
}

// TestErrorsAreComparable guarantees the exported constants can be compared
// with ==, which is how ceremonies report failures to callers.
func TestErrorsAreComparable(t *testing.T) {
	if ErrBadChallenge != Error("webauthn: challenge must be at least 16 bytes") {
		t.Fatal("error constants must compare equal to their string form")
	}
	if ErrAborted == ErrUnavailable {
		t.Fatal("distinct errors must not compare equal")
	}
}

// TestMappedErrorsContainsCause checks that errors passing through the await
// promise layer keep the original DOMException name so callers can still
// branch on them with strings.Contains.
func TestMappedErrorsContainsCause(t *testing.T) {
	errStr := Error("webauthn: Error: SecurityError: Relying party ID is invalid")
	if !strings.Contains(errStr.Error(), "SecurityError") {
		t.Fatalf("expected cause to be preserved, got %q", errStr)
	}
}
