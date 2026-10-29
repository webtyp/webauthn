package webauthn_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/webauthn/server"
)

// buildCreateResponse simulates a browser returning a registration response.
func buildCreateResponse(rpID string, challenge, origin, spki []byte, signCount uint32, credID []byte, flags byte) string {
	cdJSON := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`

	rpIDHash := sha256.Sum256([]byte(rpID))

	authData := make([]byte, 0, 37+16+2+len(credID))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))

	// AAGUID (16 bytes)
	authData = append(authData, make([]byte, 16)...)

	// Credential ID length
	authData = append(authData, byte(len(credID)>>8), byte(len(credID)))

	// Credential ID
	authData = append(authData, credID...)

	respJSON := `{"clientDataJSON":"` + base64.URLEncode([]byte(cdJSON)) + `",` +
		`"authenticatorData":"` + base64.URLEncode(authData) + `",` +
		`"publicKey":"` + base64.URLEncode(spki) + `",` +
		`"publicKeyAlgorithm":-7}`

	credJSON := `{"id":"` + base64.URLEncode(credID) + `",` +
		`"rawId":"` + base64.URLEncode(credID) + `",` +
		`"type":"public-key",` +
		`"response":` + respJSON + `}`

	return base64.URLEncode([]byte(credJSON))
}

// buildGetResponse simulates a browser returning an assertion response.
func buildGetResponse(rpID string, challenge, origin, privKey []byte, signCount uint32, credID []byte, flags byte) string {
	cdJSON := `{"type":"webauthn.get","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`

	rpIDHash := sha256.Sum256([]byte(rpID))

	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))

	clientDataHash := sha256.Sum256([]byte(cdJSON))
	msg := make([]byte, 0, len(authData)+len(clientDataHash))
	msg = append(msg, authData...)
	msg = append(msg, clientDataHash[:]...)

	sig, err := asym.Sign(msg, privKey)
	if err != nil {
		panic(err) // in tests we just panic on key errors
	}

	respJSON := `{"clientDataJSON":"` + base64.URLEncode([]byte(cdJSON)) + `",` +
		`"authenticatorData":"` + base64.URLEncode(authData) + `",` +
		`"signature":"` + base64.URLEncode(sig) + `"}`

	credJSON := `{"id":"` + base64.URLEncode(credID) + `",` +
		`"rawId":"` + base64.URLEncode(credID) + `",` +
		`"type":"public-key",` +
		`"response":` + respJSON + `}`

	return base64.URLEncode([]byte(credJSON))
}

// Helper to replace raw parts of the JSON
func replaceBase64Field(rawResponse string, field string, newB64 string) string {
	jsonStr := decodeRawResponseForTest(rawResponse)

	// simple find and replace
	// this is slightly fragile but works for controlled test inputs
	parts := strings.Split(jsonStr, `"`+field+`":"`)
	if len(parts) < 2 {
		return rawResponse
	}
	endIdx := strings.Index(parts[1], `"`)

	newJSON := parts[0] + `"` + field + `":"` + newB64 + `"` + parts[1][endIdx+1:]
	return base64.URLEncode([]byte(newJSON))
}

func decodeRawResponseForTest(raw string) string {
	decoded, _ := base64.URLDecode(raw)
	return string(decoded)
}

func TestVerifyRegistration(t *testing.T) {
	rp := server.RelyingParty{
		ID:     "iam.velty.cl",
		Origin: "https://iam.velty.cl",
	}
	challenge := []byte("challenge-123")
	origin := []byte("https://iam.velty.cl")
	credID := []byte("credential-id")
	flags := byte(0x45) // UP (0x01) | UV (0x04) | AT (0x40)

	spki, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	validRaw := buildCreateResponse(rp.ID, challenge, origin, spki, 0, credID, flags)

	t.Run("W1 - malformed response", func(t *testing.T) {
		_, err := rp.VerifyRegistration("invalid-base64", challenge)
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse for garbage base64, got %v", err)
		}

		_, err = rp.VerifyRegistration(base64.URLEncode([]byte("{}")), challenge)
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse for empty JSON, got %v", err)
		}
	})

	t.Run("W2 - wrong type", func(t *testing.T) {
		cdJSON := `{"type":"webauthn.get","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))

		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrWrongType {
			t.Errorf("expected ErrWrongType, got %v", err)
		}
	})

	t.Run("W3 - challenge mismatch", func(t *testing.T) {
		badChallenge := []byte("challenge-124")
		cdJSON := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(badChallenge) + `","origin":"` + string(origin) + `"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))

		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrChallengeMismatch {
			t.Errorf("expected ErrChallengeMismatch, got %v", err)
		}
	})

	t.Run("W4 - origin mismatch", func(t *testing.T) {
		cdJSON := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(challenge) + `","origin":"https://evil.velty.cl"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))

		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrOriginMismatch {
			t.Errorf("expected ErrOriginMismatch, got %v", err)
		}
	})

	t.Run("W5 - rpIdHash mismatch", func(t *testing.T) {
		raw := buildCreateResponse("evil.com", challenge, origin, spki, 0, credID, flags)
		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrRPIDMismatch {
			t.Errorf("expected ErrRPIDMismatch, got %v", err)
		}
	})

	t.Run("W6 - user not present", func(t *testing.T) {
		raw := buildCreateResponse(rp.ID, challenge, origin, spki, 0, credID, 0x44) // no UP
		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrUserNotPresent {
			t.Errorf("expected ErrUserNotPresent, got %v", err)
		}
	})

	t.Run("W7 - user not verified", func(t *testing.T) {
		raw := buildCreateResponse(rp.ID, challenge, origin, spki, 0, credID, 0x41) // no UV
		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrUserNotVerified {
			t.Errorf("expected ErrUserNotVerified, got %v", err)
		}
	})

	t.Run("W8 - unsupported alg", func(t *testing.T) {
		jsonStr := decodeRawResponseForTest(validRaw)
		jsonStr = strings.Replace(jsonStr, `"publicKeyAlgorithm":-7`, `"publicKeyAlgorithm":-257`, 1)
		raw := base64.URLEncode([]byte(jsonStr))

		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrUnsupportedAlg {
			t.Errorf("expected ErrUnsupportedAlg, got %v", err)
		}
	})

	t.Run("W9 - credential mismatch and malformed authData", func(t *testing.T) {
		// Create a response where rawId doesn't match the one in authData
		badRawIDJSON := `{"id":"` + base64.URLEncode([]byte("different-id")) + `",` +
			`"rawId":"` + base64.URLEncode([]byte("different-id")) + `",` +
			strings.Split(decodeRawResponseForTest(validRaw), `"rawId":"`+base64.URLEncode(credID)+`",`)[1]

		_, err := rp.VerifyRegistration(base64.URLEncode([]byte(badRawIDJSON)), challenge)
		if err != server.ErrCredentialMismatch {
			t.Errorf("expected ErrCredentialMismatch, got %v", err)
		}

		// Create authData too short (no credential data)
		rpIDHash := sha256.Sum256([]byte(rp.ID))
		shortAuthData := append(rpIDHash[:], flags, 0, 0, 0, 0)
		rawShort := replaceBase64Field(validRaw, "authenticatorData", base64.URLEncode(shortAuthData))
		_, err = rp.VerifyRegistration(rawShort, challenge)
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse for short authData, got %v", err)
		}
	})

	t.Run("W10 - bad public key", func(t *testing.T) {
		badKey := make([]byte, 91)
		raw := buildCreateResponse(rp.ID, challenge, origin, badKey, 0, credID, flags)
		_, err := rp.VerifyRegistration(raw, challenge)
		if err != server.ErrBadPublicKey {
			t.Errorf("expected ErrBadPublicKey, got %v", err)
		}
	})

	t.Run("W11 - happy path", func(t *testing.T) {
		reg, err := rp.VerifyRegistration(validRaw, challenge)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(reg.CredentialID) != string(credID) {
			t.Errorf("expected credential ID %q, got %q", credID, reg.CredentialID)
		}
		if string(reg.PublicKey) != string(spki) {
			t.Errorf("expected public key %x, got %x", spki, reg.PublicKey)
		}
		if reg.SignCount != 0 {
			t.Errorf("expected sign count 0, got %d", reg.SignCount)
		}
	})
}

func TestUnverifiedChallenge_ReturnsClientDataChallenge(t *testing.T) {
	_, privKey, _ := asym.GenerateKeyPair()
	challenge := []byte("expected-challenge")
	validRaw := buildGetResponse("iam.velty.cl", challenge, []byte("org"), privKey, 1, []byte("cred"), 0x05)

	t.Run("returns challenge of a built assertion", func(t *testing.T) {
		chal, err := server.UnverifiedChallenge(validRaw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(chal) != string(challenge) {
			t.Errorf("expected %q, got %q", challenge, chal)
		}
	})
}

func TestUnverifiedChallenge_Malformed(t *testing.T) {
	t.Run("garbage base64", func(t *testing.T) {
		_, err := server.UnverifiedChallenge("%%%")
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse, got %v", err)
		}
	})

	t.Run("empty json", func(t *testing.T) {
		_, err := server.UnverifiedChallenge(base64.URLEncode([]byte("{}")))
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse, got %v", err)
		}
	})

	t.Run("empty clientDataJSON", func(t *testing.T) {
		credJSON := `{"id":"cred","rawId":"cred","type":"public-key","response":{"clientDataJSON":"","authenticatorData":"","signature":""}}`
		raw := base64.URLEncode([]byte(credJSON))
		_, err := server.UnverifiedChallenge(raw)
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse, got %v", err)
		}
	})
}

func TestVerifyAssertion(t *testing.T) {
	rp := server.RelyingParty{
		ID:     "iam.velty.cl",
		Origin: "https://iam.velty.cl",
	}
	challenge := []byte("challenge-123")
	origin := []byte("https://iam.velty.cl")
	credID := []byte("credential-id")
	flags := byte(0x05) // UP (0x01) | UV (0x04)

	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	stored := server.StoredCredential{
		ID:        credID,
		PublicKey: spki,
		SignCount: 5,
	}

	validRaw := buildGetResponse(rp.ID, challenge, origin, privKey, 6, credID, flags)

	t.Run("W12 - assertion with different rawId", func(t *testing.T) {
		badRaw := buildGetResponse(rp.ID, challenge, origin, privKey, 6, []byte("different-id"), flags)
		_, err := rp.VerifyAssertion(badRaw, challenge, stored)
		if err != server.ErrCredentialMismatch {
			t.Errorf("expected ErrCredentialMismatch, got %v", err)
		}
	})

	t.Run("W13 - type mismatch", func(t *testing.T) {
		cdJSON := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrWrongType {
			t.Errorf("expected ErrWrongType, got %v", err)
		}
	})

	t.Run("W13 - challenge mismatch", func(t *testing.T) {
		badChallenge := []byte("challenge-124")
		cdJSON := `{"type":"webauthn.get","challenge":"` + base64.URLEncode(badChallenge) + `","origin":"` + string(origin) + `"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrChallengeMismatch {
			t.Errorf("expected ErrChallengeMismatch, got %v", err)
		}
	})

	t.Run("W13 - origin mismatch", func(t *testing.T) {
		cdJSON := `{"type":"webauthn.get","challenge":"` + base64.URLEncode(challenge) + `","origin":"https://evil.velty.cl"}`
		raw := replaceBase64Field(validRaw, "clientDataJSON", base64.URLEncode([]byte(cdJSON)))
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrOriginMismatch {
			t.Errorf("expected ErrOriginMismatch, got %v", err)
		}
	})

	t.Run("W13 - rpIdHash mismatch", func(t *testing.T) {
		raw := buildGetResponse("evil.com", challenge, origin, privKey, 6, credID, flags)
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrRPIDMismatch {
			t.Errorf("expected ErrRPIDMismatch, got %v", err)
		}
	})

	t.Run("W13 - UP missing", func(t *testing.T) {
		raw := buildGetResponse(rp.ID, challenge, origin, privKey, 6, credID, 0x04) // no UP
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrUserNotPresent {
			t.Errorf("expected ErrUserNotPresent, got %v", err)
		}
	})

	t.Run("W13 - UV missing", func(t *testing.T) {
		raw := buildGetResponse(rp.ID, challenge, origin, privKey, 6, credID, 0x01) // no UV
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrUserNotVerified {
			t.Errorf("expected ErrUserNotVerified, got %v", err)
		}
	})

	t.Run("W14 - signed by another key", func(t *testing.T) {
		_, badPrivKey, _ := asym.GenerateKeyPair()
		raw := buildGetResponse(rp.ID, challenge, origin, badPrivKey, 6, credID, flags)
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrBadSignature {
			t.Errorf("expected ErrBadSignature, got %v", err)
		}
	})

	t.Run("W14 - tampered authData after signing", func(t *testing.T) {
		// Valid base64, correct length, but tampered
		badAuthData := make([]byte, 37)
		// Maintain rpIdHash and flags so it passes those checks and gets to signature verification
		rpIDHash := sha256.Sum256([]byte(rp.ID))
		copy(badAuthData[:32], rpIDHash[:])
		badAuthData[32] = flags
		badAuthData[33] = 0x99 // Tampered sign count

		raw := replaceBase64Field(validRaw, "authenticatorData", base64.URLEncode(badAuthData))
		_, err := rp.VerifyAssertion(raw, challenge, stored)
		if err != server.ErrBadSignature {
			t.Errorf("expected ErrBadSignature, got %v", err)
		}
	})

	t.Run("W15 - counter regression (cloned)", func(t *testing.T) {
		rawEqual := buildGetResponse(rp.ID, challenge, origin, privKey, 5, credID, flags)
		_, err := rp.VerifyAssertion(rawEqual, challenge, stored)
		if err != server.ErrCloneDetected {
			t.Errorf("expected ErrCloneDetected for equal count, got %v", err)
		}

		rawLower := buildGetResponse(rp.ID, challenge, origin, privKey, 3, credID, flags)
		_, err = rp.VerifyAssertion(rawLower, challenge, stored)
		if err != server.ErrCloneDetected {
			t.Errorf("expected ErrCloneDetected for lower count, got %v", err)
		}
	})

	t.Run("W16 - stored 0 / new 0", func(t *testing.T) {
		storedZero := server.StoredCredential{
			ID:        credID,
			PublicKey: spki,
			SignCount: 0,
		}
		rawZero := buildGetResponse(rp.ID, challenge, origin, privKey, 0, credID, flags)
		count, err := rp.VerifyAssertion(rawZero, challenge, storedZero)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 0 {
			t.Errorf("expected count 0, got %d", count)
		}
	})

	t.Run("W16 - stored 5 / new 6", func(t *testing.T) {
		count, err := rp.VerifyAssertion(validRaw, challenge, stored)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 6 {
			t.Errorf("expected count 6, got %d", count)
		}
	})
}

func TestUnverifiedCredentialID(t *testing.T) {
	_, privKey, _ := asym.GenerateKeyPair()
	credID := []byte("credential-id-42")
	validRaw := buildGetResponse("iam.velty.cl", []byte("ch"), []byte("org"), privKey, 1, credID, 0x05)

	t.Run("returns rawId of a built assertion", func(t *testing.T) {
		id, err := server.UnverifiedCredentialID(validRaw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(id) != string(credID) {
			t.Errorf("expected %q, got %q", credID, id)
		}
	})

	t.Run("garbage base64", func(t *testing.T) {
		_, err := server.UnverifiedCredentialID("invalid-base64")
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse, got %v", err)
		}
	})

	t.Run("empty json", func(t *testing.T) {
		_, err := server.UnverifiedCredentialID(base64.URLEncode([]byte("{}")))
		if err != server.ErrMalformedResponse {
			t.Errorf("expected ErrMalformedResponse, got %v", err)
		}
	})
}
