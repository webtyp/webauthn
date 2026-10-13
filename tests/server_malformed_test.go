package webauthn_test

import (
	"crypto/sha256"
	"testing"

	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/webauthn/server"
)

// badB64 is not valid base64url: every field set to it must fail decoding.
const badB64 = "!!"

// envelope wraps a credential JSON the way the browser half does.
func envelope(credJSON string) string { return base64.URLEncode([]byte(credJSON)) }

// authDataFor builds the 37-byte authenticator data header, optionally
// followed by attested credential data.
func authDataFor(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), h[:]...)
	out = append(out, flags, byte(count>>24), byte(count>>16), byte(count>>8), byte(count))
	return append(out, attested...)
}

// Every decoding step of VerifyRegistration fails closed with a typed error.
func TestVerifyRegistrationMalformedFields(t *testing.T) {
	rp := server.RelyingParty{ID: "iam.velty.cl", Origin: "https://iam.velty.cl"}
	challenge := []byte("challenge-123")
	credID := []byte("credential-id")
	spki, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	valid := buildCreateResponse(rp.ID, challenge, []byte(rp.Origin), spki, 0, credID, 0x45)

	cdBadChallenge := `{"type":"webauthn.create","challenge":"` + badB64 + `","origin":"` + rp.Origin + `"}`
	cdOK := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + rp.Origin + `"}`

	// authData whose attested part is cut before the credential id length.
	shortAttested := authDataFor(rp.ID, 0x45, 0, make([]byte, 10))
	// authData whose credential id length points past the end.
	overflow := authDataFor(rp.ID, 0x45, 0, append(make([]byte, 16), 0x00, 0xff))

	regEnvelope := func(cd string, authData []byte, pk, rawID string) string {
		return envelope(`{"id":"x","rawId":"` + rawID + `","type":"public-key","response":{` +
			`"clientDataJSON":"` + base64.URLEncode([]byte(cd)) + `",` +
			`"authenticatorData":"` + base64.URLEncode(authData) + `",` +
			`"publicKey":"` + pk + `","publicKeyAlgorithm":-7}}`)
	}
	goodAuthData := authDataFor(rp.ID, 0x45, 0, append(append(make([]byte, 16), 0, byte(len(credID))), credID...))
	pkB64 := base64.URLEncode(spki)
	idB64 := base64.URLEncode(credID)

	badPrefix := append([]byte(nil), spki...)
	badPrefix[0] ^= 0xff
	badPoint := append([]byte(nil), spki...)
	badPoint[26] = 0x02

	cases := []struct {
		name string
		raw  string
		want server.Error
	}{
		{"outer JSON is not an object", envelope("not json"), server.ErrMalformedResponse},
		{"clientDataJSON not base64", replaceBase64Field(valid, "clientDataJSON", badB64), server.ErrMalformedResponse},
		{"clientDataJSON not JSON", replaceBase64Field(valid, "clientDataJSON", base64.URLEncode([]byte("nope"))), server.ErrMalformedResponse},
		{"challenge in clientData not base64", replaceBase64Field(valid, "clientDataJSON", base64.URLEncode([]byte(cdBadChallenge))), server.ErrChallengeMismatch},
		{"authenticatorData not base64", replaceBase64Field(valid, "authenticatorData", badB64), server.ErrMalformedResponse},
		{"authenticatorData shorter than its header", replaceBase64Field(valid, "authenticatorData", base64.URLEncode(make([]byte, 20))), server.ErrMalformedResponse},
		{"AT flag missing", regEnvelope(cdOK, authDataFor(rp.ID, 0x05, 0, nil), pkB64, idB64), server.ErrMalformedResponse},
		{"attested data cut before the id length", regEnvelope(cdOK, shortAttested, pkB64, idB64), server.ErrMalformedResponse},
		{"credential id length past the end", regEnvelope(cdOK, overflow, pkB64, idB64), server.ErrMalformedResponse},
		{"rawId not base64", regEnvelope(cdOK, goodAuthData, pkB64, badB64), server.ErrMalformedResponse},
		{"publicKey not base64", regEnvelope(cdOK, goodAuthData, badB64, idB64), server.ErrMalformedResponse},
		{"publicKey of the wrong length", regEnvelope(cdOK, goodAuthData, base64.URLEncode(spki[:90]), idB64), server.ErrBadPublicKey},
		{"publicKey with a foreign SPKI prefix", regEnvelope(cdOK, goodAuthData, base64.URLEncode(badPrefix), idB64), server.ErrBadPublicKey},
		{"publicKey with a compressed point marker", regEnvelope(cdOK, goodAuthData, base64.URLEncode(badPoint), idB64), server.ErrBadPublicKey},
	}
	for _, c := range cases {
		if _, err := rp.VerifyRegistration(c.raw, challenge); err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}

	// The happy path still holds with the same builders.
	if _, err := rp.VerifyRegistration(regEnvelope(cdOK, goodAuthData, pkB64, idB64), challenge); err != nil {
		t.Errorf("valid registration rejected: %v", err)
	}
}

// Every decoding step of VerifyAssertion fails closed with a typed error.
func TestVerifyAssertionMalformedFields(t *testing.T) {
	rp := server.RelyingParty{ID: "iam.velty.cl", Origin: "https://iam.velty.cl"}
	challenge := []byte("challenge-123")
	credID := []byte("credential-id")
	spki, priv, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stored := server.StoredCredential{ID: credID, PublicKey: spki}
	valid := buildGetResponse(rp.ID, challenge, []byte(rp.Origin), priv, 1, credID, 0x05)

	cdBadChallenge := `{"type":"webauthn.get","challenge":"` + badB64 + `","origin":"` + rp.Origin + `"}`

	// An assertion without UP, correctly signed so only the flag fails.
	noUP := buildGetResponse(rp.ID, challenge, []byte(rp.Origin), priv, 1, credID, 0x04)

	cases := []struct {
		name string
		raw  string
		want server.Error
	}{
		{"outer not base64", badB64, server.ErrMalformedResponse},
		{"outer JSON is not an object", envelope("not json"), server.ErrMalformedResponse},
		{"empty object", envelope("{}"), server.ErrMalformedResponse},
		{"rawId not base64", replaceBase64Field(valid, "rawId", badB64), server.ErrMalformedResponse},
		{"clientDataJSON not base64", replaceBase64Field(valid, "clientDataJSON", badB64), server.ErrMalformedResponse},
		{"clientDataJSON not JSON", replaceBase64Field(valid, "clientDataJSON", base64.URLEncode([]byte("nope"))), server.ErrMalformedResponse},
		{"challenge in clientData not base64", replaceBase64Field(valid, "clientDataJSON", base64.URLEncode([]byte(cdBadChallenge))), server.ErrChallengeMismatch},
		{"authenticatorData not base64", replaceBase64Field(valid, "authenticatorData", badB64), server.ErrMalformedResponse},
		{"authenticatorData shorter than its header", replaceBase64Field(valid, "authenticatorData", base64.URLEncode(make([]byte, 20))), server.ErrMalformedResponse},
		{"user presence missing", noUP, server.ErrUserNotPresent},
		{"signature not base64", replaceBase64Field(valid, "signature", badB64), server.ErrMalformedResponse},
	}
	for _, c := range cases {
		if _, err := rp.VerifyAssertion(c.raw, challenge, stored); err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestUnverifiedCredentialIDMalformed(t *testing.T) {
	for _, raw := range []string{
		envelope("not json"),
		envelope(`{"rawId":""}`),
		envelope(`{"rawId":"` + badB64 + `"}`),
	} {
		if _, err := server.UnverifiedCredentialID(raw); err != server.ErrMalformedResponse {
			t.Errorf("UnverifiedCredentialID(%q): got %v, want ErrMalformedResponse", decodeRawResponseForTest(raw), err)
		}
	}
}

// The typed error reads as its own text, so callers can log it as-is.
func TestErrorText(t *testing.T) {
	if got := server.ErrCloneDetected.Error(); got != string(server.ErrCloneDetected) {
		t.Errorf("Error() = %q", got)
	}
}
