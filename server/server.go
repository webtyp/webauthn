// Package server verifies WebAuthn responses on the relying party (ES256 only).
package server

import (
	"crypto/sha256"

	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/crypto/subtle"
	"webtyp.com/json"
)

// RelyingParty is who the passkeys are for.
type RelyingParty struct {
	ID     string // RP id: a registrable domain, e.g. "iam.velty.cl"
	Origin string // exact expected origin, e.g. "https://iam.velty.cl"
}

// Registration is what to store after a successful registration.
type Registration struct {
	CredentialID []byte
	PublicKey    []byte // SPKI DER, P-256
	SignCount    uint32
}

// StoredCredential is what the caller loaded for the credential being asserted.
type StoredCredential struct {
	ID        []byte
	PublicKey []byte // SPKI DER
	SignCount uint32
}

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrMalformedResponse  Error = "webauthn: malformed response"
	ErrWrongType          Error = "webauthn: clientData.type mismatch"
	ErrChallengeMismatch  Error = "webauthn: challenge mismatch"
	ErrOriginMismatch     Error = "webauthn: origin mismatch"
	ErrRPIDMismatch       Error = "webauthn: rpIdHash mismatch"
	ErrUserNotPresent     Error = "webauthn: user presence flag not set"
	ErrUserNotVerified    Error = "webauthn: user verification flag not set"
	ErrUnsupportedAlg     Error = "webauthn: only ES256 (-7) is supported"
	ErrBadPublicKey       Error = "webauthn: public key is not a P-256 SPKI key"
	ErrCredentialMismatch Error = "webauthn: credential id mismatch"
	ErrBadSignature       Error = "webauthn: signature does not verify"
	ErrCloneDetected      Error = "webauthn: sign count did not increase (possible cloned authenticator)"
)

// isP256SPKI checks if the DER is exactly an uncompressed P-256 SPKI public key.
// Browsers always emit exactly this shape for ES256 (-7).
func isP256SPKI(der []byte) bool {
	if len(der) != 91 {
		return false
	}
	// Fixed SPKI prefix of an uncompressed P-256 key
	prefix := []byte{
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
	}
	if subtle.ConstantTimeCompare(der[:26], prefix) != 1 {
		return false
	}
	return der[26] == 0x04
}

// VerifyRegistration checks a Credential.RawResponse against the challenge the
// server issued. It requires user presence AND user verification.
func (rp RelyingParty) VerifyRegistration(rawResponse string, challenge []byte) (Registration, error) {
	jsonBytes, err := base64.URLDecode(rawResponse)
	if err != nil {
		return Registration{}, ErrMalformedResponse
	}

	var cred credentialJSON
	if err := json.Decode(jsonBytes, &cred); err != nil {
		return Registration{}, ErrMalformedResponse
	}

	if cred.RawID == "" || cred.Response.ClientDataJSON == "" || cred.Response.AuthenticatorData == "" || cred.Response.PublicKey == "" {
		return Registration{}, ErrMalformedResponse
	}

	clientDataJSONBytes, err := base64.URLDecode(cred.Response.ClientDataJSON)
	if err != nil {
		return Registration{}, ErrMalformedResponse
	}

	var cdata clientData
	if err := json.Decode(clientDataJSONBytes, &cdata); err != nil {
		return Registration{}, ErrMalformedResponse
	}

	if cdata.Type != typeCreate {
		return Registration{}, ErrWrongType
	}

	chalBytes, err := base64.URLDecode(cdata.Challenge)
	if err != nil {
		return Registration{}, ErrChallengeMismatch
	}
	if subtle.ConstantTimeCompare(chalBytes, challenge) != 1 {
		return Registration{}, ErrChallengeMismatch
	}

	if cdata.Origin != rp.Origin {
		return Registration{}, ErrOriginMismatch
	}

	authData, err := base64.URLDecode(cred.Response.AuthenticatorData)
	if err != nil {
		return Registration{}, ErrMalformedResponse
	}

	if len(authData) < authDataMinLen {
		return Registration{}, ErrMalformedResponse
	}

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(authData[:32], rpIDHash[:]) != 1 {
		return Registration{}, ErrRPIDMismatch
	}

	flags := authData[32]
	if flags&flagUP == 0 {
		return Registration{}, ErrUserNotPresent
	}
	if flags&flagUV == 0 {
		return Registration{}, ErrUserNotVerified
	}
	if flags&flagAT == 0 {
		return Registration{}, ErrMalformedResponse
	}

	if cred.Response.PublicKeyAlgorithm != algES256 {
		return Registration{}, ErrUnsupportedAlg
	}

	// Attested credential data starts at byte 37
	// AAGUID (16 bytes) -> starts at 37
	// Credential ID length (2 bytes, big-endian) -> starts at 53
	// Credential ID -> starts at 55
	if len(authData) < 55 {
		return Registration{}, ErrMalformedResponse
	}

	credIDLen := int(authData[53])<<8 | int(authData[54])
	if len(authData) < 55+credIDLen {
		return Registration{}, ErrMalformedResponse
	}

	attestedCredID := authData[55 : 55+credIDLen]
	rawIDBytes, err := base64.URLDecode(cred.RawID)
	if err != nil {
		return Registration{}, ErrMalformedResponse
	}

	if len(attestedCredID) != len(rawIDBytes) || subtle.ConstantTimeCompare(attestedCredID, rawIDBytes) != 1 {
		return Registration{}, ErrCredentialMismatch
	}

	spki, err := base64.URLDecode(cred.Response.PublicKey)
	if err != nil {
		return Registration{}, ErrMalformedResponse
	}

	if !isP256SPKI(spki) {
		return Registration{}, ErrBadPublicKey
	}

	signCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])

	return Registration{
		CredentialID: rawIDBytes,
		PublicKey:    spki,
		SignCount:    signCount,
	}, nil
}

// VerifyAssertion checks an Assertion.RawResponse against the issued challenge
// and the stored credential, and returns the new sign count to store.
func (rp RelyingParty) VerifyAssertion(rawResponse string, challenge []byte, stored StoredCredential) (uint32, error) {
	jsonBytes, err := base64.URLDecode(rawResponse)
	if err != nil {
		return 0, ErrMalformedResponse
	}

	var cred credentialJSON
	if err := json.Decode(jsonBytes, &cred); err != nil {
		return 0, ErrMalformedResponse
	}

	if cred.RawID == "" || cred.Response.ClientDataJSON == "" || cred.Response.AuthenticatorData == "" || cred.Response.Signature == "" {
		return 0, ErrMalformedResponse
	}

	rawIDBytes, err := base64.URLDecode(cred.RawID)
	if err != nil {
		return 0, ErrMalformedResponse
	}

	if len(rawIDBytes) != len(stored.ID) || subtle.ConstantTimeCompare(rawIDBytes, stored.ID) != 1 {
		return 0, ErrCredentialMismatch
	}

	clientDataJSONBytes, err := base64.URLDecode(cred.Response.ClientDataJSON)
	if err != nil {
		return 0, ErrMalformedResponse
	}

	var cdata clientData
	if err := json.Decode(clientDataJSONBytes, &cdata); err != nil {
		return 0, ErrMalformedResponse
	}

	if cdata.Type != typeGet {
		return 0, ErrWrongType
	}

	chalBytes, err := base64.URLDecode(cdata.Challenge)
	if err != nil {
		return 0, ErrChallengeMismatch
	}
	if subtle.ConstantTimeCompare(chalBytes, challenge) != 1 {
		return 0, ErrChallengeMismatch
	}

	if cdata.Origin != rp.Origin {
		return 0, ErrOriginMismatch
	}

	authData, err := base64.URLDecode(cred.Response.AuthenticatorData)
	if err != nil {
		return 0, ErrMalformedResponse
	}

	if len(authData) < authDataMinLen {
		return 0, ErrMalformedResponse
	}

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(authData[:32], rpIDHash[:]) != 1 {
		return 0, ErrRPIDMismatch
	}

	flags := authData[32]
	if flags&flagUP == 0 {
		return 0, ErrUserNotPresent
	}
	if flags&flagUV == 0 {
		return 0, ErrUserNotVerified
	}

	sigBytes, err := base64.URLDecode(cred.Response.Signature)
	if err != nil {
		return 0, ErrMalformedResponse
	}

	clientDataHash := sha256.Sum256(clientDataJSONBytes)
	msg := make([]byte, 0, len(authData)+len(clientDataHash))
	msg = append(msg, authData...)
	msg = append(msg, clientDataHash[:]...)

	ok, err := asym.Verify(msg, sigBytes, stored.PublicKey)
	if !ok || err != nil {
		return 0, ErrBadSignature
	}

	newCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])

	if stored.SignCount != 0 || newCount != 0 {
		if newCount <= stored.SignCount {
			return 0, ErrCloneDetected
		}
	}

	return newCount, nil
}

// UnverifiedCredentialID returns the rawId of an Assertion.RawResponse WITHOUT
// verifying anything. Its only legitimate use is loading the StoredCredential
// to pass to VerifyAssertion; never trust it for anything else.
func UnverifiedCredentialID(rawResponse string) ([]byte, error) {
	jsonBytes, err := base64.URLDecode(rawResponse)
	if err != nil {
		return nil, ErrMalformedResponse
	}

	var cred credentialJSON
	if err := json.Decode(jsonBytes, &cred); err != nil {
		return nil, ErrMalformedResponse
	}
	if cred.RawID == "" {
		return nil, ErrMalformedResponse
	}
	rawIDBytes, err := base64.URLDecode(cred.RawID)
	if err != nil {
		return nil, ErrMalformedResponse
	}

	return rawIDBytes, nil
}
